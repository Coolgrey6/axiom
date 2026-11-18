import { createHmac, timingSafeEqual } from 'node:crypto'

function mac (value, secret) {
  return createHmac('sha256', secret).update(value).digest('base64').replace(/=+$/, '')
}

export function signCookie (value, secret) {
  return `${value}.${mac(value, secret)}`
}

export function unsignCookie (signedValue, secret) {
  if (typeof signedValue !== 'string') return { valid: false, value: null }
  const dot = signedValue.lastIndexOf('.')
  if (dot <= 0) return { valid: false, value: null }
  const value = signedValue.slice(0, dot)
  const actual = Buffer.from(signedValue.slice(dot + 1))
  const expected = Buffer.from(mac(value, secret))
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return { valid: false, value: null }
  }
  return { valid: true, value }
}
