import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

export function bytesToBase64 (bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i])
  return btoa(binary)
}

export function base64ToBytes (value) {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function generateKemKeyPair () {
  const { publicKey, secretKey } = ml_kem768.keygen()
  return { publicKey: bytesToBase64(publicKey), privateKey: bytesToBase64(secretKey) }
}

export function generateSigningKeyPair () {
  const { publicKey, secretKey } = ml_dsa65.keygen()
  return { publicKey: bytesToBase64(publicKey), privateKey: bytesToBase64(secretKey) }
}

export function signMessage (privateKey, message) {
  return bytesToBase64(ml_dsa65.sign(new TextEncoder().encode(message), base64ToBytes(privateKey)))
}

export async function openRelease (privateKey, release) {
  const valid = ml_dsa65.verify(
    base64ToBytes(release.signature),
    new TextEncoder().encode(release.signed),
    base64ToBytes(release.serverPublicKey)
  )
  if (!valid) throw new Error('bad signature')
  const payload = JSON.parse(release.signed)
  const shared = ml_kem768.decapsulate(
    base64ToBytes(payload.encapsulation.cipherText),
    base64ToBytes(privateKey)
  )
  const wrapKey = await crypto.subtle.importKey('raw', shared, 'AES-GCM', false, ['decrypt'])
  const contentKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(payload.encapsulation.iv) },
    wrapKey,
    base64ToBytes(payload.encapsulation.wrappedKey)
  )
  const aes = await crypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['decrypt'])
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(payload.ciphertext.iv) },
    aes,
    base64ToBytes(payload.ciphertext.data)
  )
  const bytes = new Uint8Array(plain)
  const mime = typeof payload.mime === 'string' && payload.mime ? payload.mime : 'text/plain'
  const filename = typeof payload.filename === 'string' ? payload.filename : ''
  const textual = mime.startsWith('text/') || mime === 'application/json' || mime === 'application/xml' || mime === 'image/svg+xml'
  return {
    id: payload.id,
    filename,
    mime,
    bytes,
    plaintext: textual ? new TextDecoder().decode(bytes) : null
  }
}
