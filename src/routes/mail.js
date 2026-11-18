import { readBlob, writeBlob } from '../blobs.js'
import { writeAudit } from '../audit.js'
import {
  canonicalKemKey,
  encapsulateContentKey,
  encryptBytes,
  fingerprintOf,
  randomContentKey,
  signPayload,
  unwrapContentKey,
  wrapContentKey
} from '../crypto.js'
import { consumeGrant } from '../grants.js'
import { readGrant, requireSession } from '../middleware/human.js'

function fail (reply, status, error) {
  return reply.code(status).send({ error })
}

const ADDRESS_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/

export async function storeMessage (db, masterKey, { recipient, plaintext }) {
  const contentKey = randomContentKey()
  const ciphertext = await encryptBytes(contentKey, plaintext)
  const createdAt = Date.now()
  const result = db.prepare(`
    INSERT INTO mailbox (recipient_public_key, ciphertext_path, wrapped_key, created_at)
    VALUES (?, '', '', ?)
  `).run(recipient, createdAt)
  const id = Number(result.lastInsertRowid)
  const file = writeBlob(`mail-${id}.json`, ciphertext)
  const wrappedKey = await wrapContentKey(masterKey, contentKey)
  db.prepare('UPDATE mailbox SET ciphertext_path = ?, wrapped_key = ? WHERE id = ?').run(file, wrappedKey, id)
  writeAudit(db, 'mail.send', { id, fingerprint: fingerprintOf(recipient) })
  return { id, createdAt }
}

export default async function mailRoutes (app) {
  app.post('/mail/address', async (request, reply) => {
    if (requireSession(request, reply)) return
    const publicKey = canonicalKemKey(request.body?.publicKey)
    const address = typeof request.body?.address === 'string' ? request.body.address.toLowerCase() : ''
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    if (!ADDRESS_RE.test(address)) return fail(reply, 400, 'invalid address')
    app.db.prepare(`
      INSERT INTO addresses (address, public_key, created_at) VALUES (?, ?, ?)
      ON CONFLICT(address) DO UPDATE SET public_key = excluded.public_key
    `).run(address, publicKey, Date.now())
    writeAudit(app.db, 'mail.address', { address, fingerprint: fingerprintOf(publicKey) })
    return { address, publicKey }
  })

  app.get('/mail/inbox', async (request, reply) => {
    if (requireSession(request, reply)) return
    const publicKey = canonicalKemKey(request.query.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    return app.db.prepare(
      'SELECT id, created_at AS createdAt FROM mailbox WHERE recipient_public_key = ? ORDER BY id DESC'
    ).all(publicKey)
  })

  app.post('/mail/send', async (request, reply) => {
    if (requireSession(request, reply)) return
    const recipient = canonicalKemKey(request.body?.recipientPublicKey)
    if (!recipient) return fail(reply, 400, 'invalid public key')
    const plaintext = request.body?.plaintext
    if (typeof plaintext !== 'string' || plaintext.length === 0 || Buffer.byteLength(plaintext) > 1_000_000) {
      return fail(reply, 400, 'invalid plaintext')
    }
    const stored = await storeMessage(app.db, app.masterKey, { recipient, plaintext })
    return reply.code(201).send(stored)
  })

  app.get('/mail/:id/key', async (request, reply) => {
    const publicKey = canonicalKemKey(request.headers['x-axiom-public-key'] ?? request.query.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    const row = app.db.prepare(
      'SELECT id, recipient_public_key, ciphertext_path, wrapped_key FROM mailbox WHERE id = ?'
    ).get(Number(request.params.id))
    if (!row) return fail(reply, 404, 'message not found')
    if (row.recipient_public_key !== publicKey) {
      writeAudit(app.db, 'mail.key_denied', { id: row.id, fingerprint: fingerprintOf(publicKey) })
      return fail(reply, 403, 'not allowed')
    }
    const grant = readGrant(request)
    if (!grant.valid || !consumeGrant(app.db, { grantId: grant.value, contentId: `mail:${row.id}`, publicKey })) {
      return fail(reply, 401, 'human verification required')
    }
    let contentKey
    let ciphertext
    try {
      contentKey = await unwrapContentKey(app.masterKey, row.wrapped_key)
      ciphertext = readBlob(row.ciphertext_path)
    } catch {
      return fail(reply, 500, 'ciphertext unavailable')
    }
    const signed = await signPayload(app.signingKeys.privateKey, {
      id: row.id,
      ciphertext,
      encapsulation: await encapsulateContentKey(publicKey, contentKey)
    })
    writeAudit(app.db, 'mail.key_released', { id: row.id, fingerprint: fingerprintOf(publicKey) })
    return { ...signed, serverPublicKey: app.signingKeys.publicKey }
  })
}
