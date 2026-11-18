import fs from 'node:fs'
import path from 'node:path'
import { canonicalSignKey, generateSigningKeyPair } from './crypto.js'
import { dataDir } from './paths.js'

function ensureDataDir () {
  fs.mkdirSync(dataDir(), { recursive: true })
}

function dataFile (name) {
  return path.join(dataDir(), name)
}

export function loadMasterKey () {
  ensureDataDir()
  const file = dataFile('master.key')
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))))
  }
  const key = fs.readFileSync(file)
  if (key.length !== 32) throw new Error('data/master.key must be 32 bytes')
  return new Uint8Array(key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength))
}

export function loadCookieSecret () {
  ensureDataDir()
  const file = dataFile('cookie.secret')
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString('base64'))
  }
  return fs.readFileSync(file, 'utf8').trim()
}

export async function loadSigningKeys () {
  ensureDataDir()
  const file = dataFile('signing.json')
  if (fs.existsSync(file)) {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (canonicalSignKey(parsed.publicKey) && parsed.privateKey) return parsed
  }
  const pair = generateSigningKeyPair()
  fs.writeFileSync(file, JSON.stringify(pair))
  return pair
}
