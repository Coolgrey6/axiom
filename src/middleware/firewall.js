import fs from 'node:fs'
import path from 'node:path'
import { writeAudit } from '../audit.js'

const GEO_FILES = [
  path.resolve('data', 'GeoLite2-City.mmdb'),
  path.resolve('data', 'GeoLite2-Country.mmdb')
]

let geoReader
let geoState = 'unchecked'
let geoWarned = false

function ipv4ToBig (ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let value = 0n
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = (value << 8n) + BigInt(octet)
  }
  return value
}

function ipv6ToBig (ip) {
  let zone = ip
  const percent = zone.indexOf('%')
  if (percent !== -1) zone = zone.slice(0, percent)
  if (zone.includes('.')) {
    const last = zone.lastIndexOf(':')
    const v4 = ipv4ToBig(zone.slice(last + 1))
    if (v4 == null) return null
    const hi = ((v4 >> 16n) & 0xffffn).toString(16)
    const lo = (v4 & 0xffffn).toString(16)
    zone = `${zone.slice(0, last)}:${hi}:${lo}`
  }
  const halves = zone.split('::')
  if (halves.length > 2) return null
  let groups
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : []
    const right = halves[1] ? halves[1].split(':') : []
    if (left.length + right.length > 8) return null
    groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
  } else {
    groups = zone.split(':')
  }
  if (groups.length !== 8) return null
  let value = 0n
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null
    value = (value << 16n) + BigInt(parseInt(group, 16))
  }
  return value
}

function parseIp (ip) {
  if (typeof ip !== 'string' || ip.length === 0) return null
  if (ip.includes(':')) {
    const value = ipv6ToBig(ip)
    return value == null ? null : { version: 6, value }
  }
  const value = ipv4ToBig(ip)
  return value == null ? null : { version: 4, value }
}

export function normalizeIp (ip) {
  const value = ip ?? ''
  return value.startsWith('::ffff:') ? value.slice(7) : value
}

export function clientIp (request) {
  return normalizeIp(request.ip)
}

export function isValidCidr (cidr) {
  if (typeof cidr !== 'string' || cidr.length === 0 || cidr.length > 64) return false
  if (!cidr.includes('/')) return parseIp(cidr) != null
  const slash = cidr.indexOf('/')
  const host = cidr.slice(0, slash)
  const bitsText = cidr.slice(slash + 1)
  if (!/^\d{1,3}$/.test(bitsText)) return false
  const parsed = parseIp(host)
  if (!parsed) return false
  const bits = Number(bitsText)
  const max = parsed.version === 4 ? 32 : 128
  return bits >= 0 && bits <= max
}

export function cidrMatches (ip, cidr) {
  if (!cidr.includes('/')) return ip === cidr
  const slash = cidr.indexOf('/')
  const address = parseIp(ip)
  const network = parseIp(cidr.slice(0, slash))
  if (!address || !network || address.version !== network.version) return false
  const bits = BigInt(cidr.slice(slash + 1))
  const width = address.version === 4 ? 32n : 128n
  if (bits === 0n) return true
  const shift = width - bits
  return (address.value >> shift) === (network.value >> shift)
}

async function geoAvailable () {
  if (geoState === 'ready') return true
  if (geoState === 'missing') return false
  const file = GEO_FILES.find((candidate) => fs.existsSync(candidate))
  if (!file) {
    geoState = 'missing'
    if (!geoWarned) {
      geoWarned = true
      console.warn('GeoLite2 database not found. Geo rules are skipped until data/GeoLite2-City.mmdb is added.')
    }
    return false
  }
  try {
    const mod = await import('maxmind')
    const open = mod.open ?? mod.default?.open
    if (typeof open !== 'function') throw new Error('maxmind open() is unavailable')
    geoReader = await open(file)
    geoState = 'ready'
    return true
  } catch (error) {
    geoState = 'missing'
    console.warn(`GeoLite2 database could not be opened (${error.message}). Geo rules are skipped.`)
    return false
  }
}

function countryFor (ip) {
  const record = geoReader.get(ip)
  return record?.country?.iso_code ?? record?.registered_country?.iso_code ?? null
}

function isLoopback (ip) {
  return ip === '127.0.0.1' || ip === '::1'
}

function decision (ipRules, geoRules, ip, country) {
  for (const rule of ipRules) {
    if (rule.action === 'deny' && cidrMatches(ip, rule.cidr)) {
      return { block: true, reason: 'ip-deny', ruleId: rule.id }
    }
  }
  for (const rule of geoRules) {
    if (country && rule.action === 'deny' && rule.country_code === country) {
      return { block: true, reason: 'geo-deny', ruleId: rule.id }
    }
  }
  const ipAllows = ipRules.filter((rule) => rule.action === 'allow')
  if (ipAllows.length > 0 && !ipAllows.some((rule) => cidrMatches(ip, rule.cidr))) {
    return { block: true, reason: 'ip-allow' }
  }
  const geoAllows = geoRules.filter((rule) => rule.action === 'allow')
  if (geoAllows.length > 0 && !isLoopback(ip)) {
    if (!country || !geoAllows.some((rule) => rule.country_code === country)) {
      return { block: true, reason: 'geo-allow' }
    }
  }
  return { block: false }
}

export async function inspectRequest (db, ip, requestPath) {
  const path = requestPath.split('?')[0]
  if (path === '/health') return { block: false }
  const address = normalizeIp(ip)
  const ipRules = db.prepare('SELECT id, cidr, action FROM firewall_ip').all()
  const geoReady = await geoAvailable()
  const geoRules = geoReady
    ? db.prepare('SELECT id, country_code, action FROM firewall_geo').all()
    : []
  const country = geoRules.length > 0 ? countryFor(address) : null
  const result = decision(ipRules, geoRules, address, country)
  if (!result.block) return { block: false, ip: address, country }
  writeAudit(db, 'firewall.block', {
    ip: address,
    country,
    reason: result.reason,
    ruleId: result.ruleId ?? null,
    path
  })
  return { block: true, ip: address, country, reason: result.reason }
}

export async function lookupCountry (ip) {
  const ready = await geoAvailable()
  if (!ready) return null
  return countryFor(normalizeIp(ip))
}

export function createFirewallHook () {
  return async function firewall (request, reply) {
    const result = await inspectRequest(request.server.db, request.ip, request.url)
    if (!result.block) return
    return reply.code(403).send({ error: 'blocked' })
  }
}
