import { readBlob } from '../blobs.js'
import { writeAudit } from '../audit.js'
import {
  canonicalKemKey,
  encapsulateContentKey,
  fingerprintOf,
  signPayload,
  unwrapContentKey
} from '../crypto.js'
import { consumeGrant } from '../grants.js'
import { readGrant, requireSession } from '../middleware/human.js'

function fail (reply, status, error) {
  return reply.code(status).send({ error })
}

async function releaseKey (request, reply, { id, wrappedKey, ciphertextPath, publicKey, auditEvent, filename = null, mime = 'text/plain' }) {
  const grant = readGrant(request)
  if (!grant.valid || !consumeGrant(request.server.db, { grantId: grant.value, contentId: id, publicKey })) {
    return fail(reply, 401, 'human verification required')
  }

  let contentKey
  let ciphertext
  try {
    contentKey = await unwrapContentKey(request.server.masterKey, wrappedKey)
    ciphertext = readBlob(ciphertextPath)
  } catch {
    return fail(reply, 500, 'ciphertext unavailable')
  }

  let encapsulation
  try {
    encapsulation = await encapsulateContentKey(publicKey, contentKey)
  } catch {
    return fail(reply, 400, 'invalid public key')
  }

  const signed = await signPayload(request.server.signingKeys.privateKey, {
    id,
    filename,
    mime,
    ciphertext,
    encapsulation
  })
  writeAudit(request.server.db, auditEvent, { id, fingerprint: fingerprintOf(publicKey) })
  return {
    ...signed,
    serverPublicKey: request.server.signingKeys.publicKey
  }
}

export default async function contentRoutes (app) {
  app.post('/content/:id/key', async (request, reply) => {
    const publicKey = canonicalKemKey(request.body?.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')

    const row = app.db.prepare(
      'SELECT id, filename, mime, ciphertext_path, wrapped_key FROM content WHERE id = ?'
    ).get(request.params.id)
    if (!row) return fail(reply, 404, 'content not found')

    return releaseKey(request, reply, {
      id: String(row.id),
      filename: row.filename,
      mime: row.mime || 'text/plain',
      wrappedKey: row.wrapped_key,
      ciphertextPath: row.ciphertext_path,
      publicKey,
      auditEvent: 'content.key_released'
    })
  })
}

export { requireSession }
