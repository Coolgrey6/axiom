import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server'
import { prepareGrant } from './grants.js'

export const rpID = process.env.AXIOM_RP_ID || 'localhost'
export const origin = process.env.AXIOM_ORIGIN || 'https://localhost:8443'

const CHALLENGE_MS = 5 * 60 * 1000

function rememberChallenge (db, challenge, kind, contentId = null, publicKey = null) {
  db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(Date.now())
  db.prepare(`
    INSERT INTO challenges (challenge, kind, content_id, public_key, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(challenge, kind, contentId, publicKey, Date.now() + CHALLENGE_MS)
}

function takeChallenge (db, challenge, kind) {
  const row = db.prepare(
    'SELECT challenge, kind, content_id, public_key, expires_at FROM challenges WHERE challenge = ? AND kind = ?'
  ).get(challenge, kind)
  if (!row) return null
  db.prepare('DELETE FROM challenges WHERE challenge = ?').run(challenge)
  if (row.expires_at < Date.now()) return null
  return row
}

export async function registrationOptions (db) {
  const options = await generateRegistrationOptions({
    rpName: 'Axiom',
    rpID,
    userName: 'reader',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required'
    }
  })
  rememberChallenge(db, options.challenge, 'register')
  return options
}

export async function registerCredential (db, response) {
  let client
  try {
    client = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'))
  } catch {
    return { error: 'webauthn failed', status: 400 }
  }
  const saved = takeChallenge(db, client.challenge, 'register')
  if (!saved) return { error: 'challenge expired', status: 400 }
  let verification
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: saved.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true
    })
  } catch {
    return { error: 'webauthn failed', status: 400 }
  }
  if (!verification.verified) return { error: 'webauthn failed', status: 400 }
  const credential = verification.registrationInfo.credential
  db.prepare(`
    INSERT INTO credentials (credential_id, public_key, counter, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(credential_id) DO UPDATE SET public_key = excluded.public_key, counter = excluded.counter
  `).run(
    credential.id,
    Buffer.from(credential.publicKey).toString('base64'),
    credential.counter,
    Date.now()
  )
  return { credentialId: credential.id }
}

export async function authenticationOptions (db, { contentId, publicKey }) {
  const credentials = db.prepare('SELECT credential_id FROM credentials').all()
  if (credentials.length === 0) return { error: 'passkey required', status: 401 }
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    allowCredentials: credentials.map((row) => ({ id: row.credential_id, type: 'public-key' }))
  })
  rememberChallenge(db, options.challenge, 'assert', contentId, publicKey)
  return options
}

export async function verifyAssertion (db, { response, contentId, publicKey, capability, signingPublicKey }) {
  let client
  try {
    client = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'))
  } catch {
    return { error: 'webauthn failed', status: 400 }
  }
  const saved = takeChallenge(db, client.challenge, 'assert')
  if (!saved || saved.content_id !== contentId || saved.public_key !== publicKey) {
    return { error: 'challenge expired', status: 400 }
  }
  const stored = db.prepare(
    'SELECT credential_id, public_key, counter FROM credentials WHERE credential_id = ?'
  ).get(response.id)
  if (!stored) return { error: 'unknown passkey', status: 401 }
  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: saved.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
      credential: {
        id: stored.credential_id,
        publicKey: Buffer.from(stored.public_key, 'base64'),
        counter: stored.counter
      }
    })
  } catch {
    return { error: 'webauthn failed', status: 400 }
  }
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    return { error: 'webauthn failed', status: 400 }
  }
  db.prepare('UPDATE credentials SET counter = ? WHERE credential_id = ?').run(
    verification.authenticationInfo.newCounter,
    stored.credential_id
  )
  const grant = await prepareGrant(db, {
    contentId,
    publicKey,
    credentialId: stored.credential_id,
    capability,
    signingPublicKey
  })
  if (grant.error) return grant
  return { credentialId: stored.credential_id, grantId: grant.id, expiresAt: grant.expiresAt }
}
