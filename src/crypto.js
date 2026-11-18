import { createHash, randomBytes } from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

const subtle = globalThis.crypto.subtle

export const KEM_ID = 'ML-KEM-768'
export const SIGNATURE_ALG = 'ML-DSA-65'
export const KEM_PUBLIC_BYTES = ml_kem768.lengths.publicKey
export const SIGN_PUBLIC_BYTES = ml_dsa65.lengths.publicKey

function copyBytes (bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength)
}

export function toBase64 (bytes) {
  return Buffer.from(bytes).toString('base64')
}

export function fromBase64 (value) {
  return new Uint8Array(copyBytes(Buffer.from(value, 'base64')))
}

export function canonicalKey (value, length) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 8192) return null
  const raw = Buffer.from(value, 'base64')
  if (raw.length !== length) return null
  return raw.toString('base64')
}

export function canonicalKemKey (value) {
  return canonicalKey(value, KEM_PUBLIC_BYTES)
}

export function canonicalSignKey (value) {
  return canonicalKey(value, SIGN_PUBLIC_BYTES)
}

export function fingerprintOf (publicKey) {
  return createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex')
}

export function randomContentKey () {
  return globalThis.crypto.getRandomValues(new Uint8Array(32))
}

export async function encryptBytes (keyBytes, plaintext) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const key = await subtle.importKey('raw', copyBytes(keyBytes), 'AES-GCM', false, ['encrypt'])
  const data = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    copyBytes(typeof plaintext === 'string' ? Buffer.from(plaintext) : plaintext)
  )
  return { iv: toBase64(iv), data: toBase64(data) }
}

async function decryptRaw (keyBytes, payload) {
  const key = await subtle.importKey('raw', copyBytes(keyBytes), 'AES-GCM', false, ['decrypt'])
  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: copyBytes(fromBase64(payload.iv)) },
    key,
    copyBytes(fromBase64(payload.data))
  )
  return new Uint8Array(copyBytes(plain))
}

export async function decryptBytes (keyBytes, payload) {
  return Buffer.from(await decryptRaw(keyBytes, payload)).toString('utf8')
}

export async function wrapContentKey (masterKey, contentKey) {
  return JSON.stringify(await encryptBytes(masterKey, contentKey))
}

export async function unwrapContentKey (masterKey, wrapped) {
  const payload = typeof wrapped === 'string' ? JSON.parse(wrapped) : wrapped
  return decryptRaw(masterKey, payload)
}

export function generateKemKeyPair () {
  const { publicKey, secretKey } = ml_kem768.keygen()
  return { publicKey: toBase64(publicKey), privateKey: toBase64(secretKey) }
}

export function generateSigningKeyPair () {
  const { publicKey, secretKey } = ml_dsa65.keygen()
  return { publicKey: toBase64(publicKey), privateKey: toBase64(secretKey) }
}

export async function encapsulateContentKey (recipientPublicKey, contentKey) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(fromBase64(recipientPublicKey))
  const sealed = await encryptBytes(Uint8Array.from(sharedSecret), contentKey)
  return {
    kem: KEM_ID,
    cipherText: toBase64(cipherText),
    iv: sealed.iv,
    wrappedKey: sealed.data
  }
}

export async function decapsulateContentKey (recipientPrivateKey, encapsulation) {
  const shared = ml_kem768.decapsulate(fromBase64(encapsulation.cipherText), fromBase64(recipientPrivateKey))
  return decryptRaw(Uint8Array.from(shared), {
    iv: encapsulation.iv,
    data: encapsulation.wrappedKey
  })
}

export function sign (privateKey, message) {
  return toBase64(ml_dsa65.sign(Buffer.from(message), fromBase64(privateKey)))
}

export function verify (publicKey, message, signature) {
  return ml_dsa65.verify(fromBase64(signature), Buffer.from(message), fromBase64(publicKey))
}

export function adminMessage ({ timestamp, method, url, body }) {
  const hash = createHash('sha256').update(body ?? '').digest('base64')
  return `${timestamp}.${method.toUpperCase()}.${url}.${hash}`
}

export async function signPayload (privateKey, payload) {
  const message = JSON.stringify(payload)
  return {
    alg: SIGNATURE_ALG,
    signed: message,
    signature: sign(privateKey, message)
  }
}

export function randomId (bytes = 16) {
  return randomBytes(bytes).toString('hex')
}
