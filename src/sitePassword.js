import { createHmac, timingSafeEqual } from 'node:crypto'

const COOKIE = 'axiom_site'
const MAX_AGE_SEC = 60 * 60 * 24 * 14

function secret () {
  return process.env.AUTH_SECRET || process.env.APP_PASSWORD || ''
}

export function sitePasswordEnabled () {
  return Boolean(process.env.APP_PASSWORD)
}

export function passwordsMatch (input, expected) {
  const a = Buffer.from(String(input))
  const b = Buffer.from(String(expected))
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

function sign (payload) {
  return createHmac('sha256', secret()).update(payload).digest('base64url')
}

export function createSessionToken (now = Date.now()) {
  const exp = Math.floor(now / 1000) + MAX_AGE_SEC
  const payload = String(exp)
  return `${payload}.${sign(payload)}`
}

export function verifySessionToken (token, now = Date.now()) {
  if (!token || !secret()) return false
  const [payload, sig] = String(token).split('.')
  if (!payload || !sig) return false
  const expected = sign(payload)
  const a = Buffer.from(sig)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false
  const expiresAt = Number(payload)
  return Number.isFinite(expiresAt) && expiresAt * 1000 > now
}

export function readSiteCookie (request) {
  return request.cookies?.[COOKIE] || null
}

export function setSiteCookie (reply, token) {
  reply.setCookie(COOKIE, token, {
    httpOnly: true,
    secure: Boolean(process.env.VERCEL),
    sameSite: 'lax',
    path: '/',
    maxAge: MAX_AGE_SEC
  })
}

const OPEN = new Set(['/login.html', '/site-login', '/axiom.css', '/logo.jpg', '/robots.txt'])

export function sitePasswordAllows (request) {
  if (!sitePasswordEnabled()) return true
  const path = request.url.split('?')[0]
  if (OPEN.has(path)) return true
  return verifySessionToken(readSiteCookie(request))
}
