import { generateKemKeyPair, openRelease } from '/client.bundle.js'

export function loadReaderKey () {
  const savedPublic = sessionStorage.getItem('axiom.client.publicKey')
  const savedPrivate = sessionStorage.getItem('axiom.client.privateKey')
  const keys = savedPublic && savedPrivate
    ? { publicKey: savedPublic, privateKey: savedPrivate }
    : generateKemKeyPair()
  sessionStorage.setItem('axiom.client.publicKey', keys.publicKey)
  sessionStorage.setItem('axiom.client.privateKey', keys.privateKey)
  return keys
}

function base64UrlToBytes (value) {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4)
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0))
}

function bytesToBase64Url (bytes) {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes
  let binary = ''
  for (const byte of view) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function publicKeyCredentialToJSON (credential) {
  const response = credential.response
  const json = {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {}
  }
  if (response.attestationObject) json.response.attestationObject = bytesToBase64Url(response.attestationObject)
  if (response.clientDataJSON) json.response.clientDataJSON = bytesToBase64Url(response.clientDataJSON)
  if (response.authenticatorData) json.response.authenticatorData = bytesToBase64Url(response.authenticatorData)
  if (response.signature) json.response.signature = bytesToBase64Url(response.signature)
  if (response.userHandle) json.response.userHandle = bytesToBase64Url(response.userHandle)
  return json
}

export async function registerPasskey () {
  const options = await (await fetch('/webauthn/register/options', { method: 'POST' })).json()
  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: base64UrlToBytes(options.challenge),
      user: { ...options.user, id: base64UrlToBytes(options.user.id) }
    }
  })
  const response = await fetch('/webauthn/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(publicKeyCredentialToJSON(credential))
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.error || 'Passkey registration failed')
}

export async function unlockObject ({ contentId, keyPath, keys }) {
  const optionsResponse = await fetch('/webauthn/assert/options', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ contentId, publicKey: keys.publicKey })
  })
  const options = await optionsResponse.json()
  if (!optionsResponse.ok) throw new Error(options.error || 'Unlock failed')
  const credential = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: base64UrlToBytes(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((item) => ({
        ...item,
        id: base64UrlToBytes(item.id)
      }))
    }
  })
  const verified = await fetch('/verify-human', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ contentId, publicKey: keys.publicKey, response: publicKeyCredentialToJSON(credential) })
  })
  const verifiedBody = await verified.json()
  if (!verified.ok) throw new Error(verifiedBody.error || 'Unlock failed')
  const response = await fetch(keyPath, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ publicKey: keys.publicKey })
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.error || 'Unlock failed')
  return openRelease(keys.privateKey, body)
}

export function showOpened (output, opened, fallbackName) {
  output.replaceChildren()
  if (opened.mime === 'text/html' && opened.plaintext != null) {
    const frame = document.createElement('iframe')
    frame.className = 'page'
    frame.sandbox = 'allow-scripts allow-forms allow-popups'
    frame.srcdoc = opened.plaintext
    frame.title = opened.filename || 'Opened page'
    output.append(frame)
    return
  }
  const file = new Blob([opened.bytes], { type: opened.mime || 'application/octet-stream' })
  const url = URL.createObjectURL(file)
  if ((opened.mime || '').startsWith('image/')) {
    const image = document.createElement('img')
    image.className = 'opened'
    image.alt = opened.filename || 'Opened image'
    image.src = url
    output.append(image)
  } else if (opened.plaintext != null) {
    const text = document.createElement('pre')
    text.textContent = opened.plaintext
    output.append(text)
  }
  const link = document.createElement('a')
  link.href = url
  link.download = opened.filename || fallbackName
  link.textContent = `Download ${link.download}`
  output.append(link)
}
