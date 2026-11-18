import { randomUUID } from 'node:crypto'
import { verify } from './crypto.js'
import { modulesByKind, runGates } from './modules.js'

const HOUR_MS = 60 * 60 * 1000
const GRANT_MS = 5 * 60 * 1000

function budgetLimit () {
  const limit = Number(process.env.AXIOM_HOURLY_BUDGET || 8)
  return Number.isFinite(limit) && limit > 0 ? limit : 8
}

export function issueGrant (db, { contentId, publicKey, credentialId }) {
  const since = Date.now() - HOUR_MS
  const used = db.prepare(
    'SELECT COUNT(*) AS n FROM grants WHERE credential_id = ? AND created_at > ?'
  ).get(credentialId, since).n
  if (used >= budgetLimit()) return { error: 'hourly budget reached', status: 429 }

  const id = randomUUID()
  const now = Date.now()
  db.prepare(`
    INSERT INTO grants (id, content_id, public_key, credential_id, expires_at, spent, created_at)
    VALUES (?, ?, ?, ?, ?, 0, ?)
  `).run(id, contentId, publicKey, credentialId, now + GRANT_MS, now)
  return { id, expiresAt: now + GRANT_MS }
}

function capabilityAllows (signingPublicKey, capability, contentId, publicKey) {
  if (!signingPublicKey || !capability || typeof capability.signed !== 'string' || typeof capability.signature !== 'string') return false
  if (!verify(signingPublicKey, capability.signed, capability.signature)) return false
  try {
    const payload = JSON.parse(capability.signed)
    return payload.contentId === contentId && payload.publicKey === publicKey && Number(payload.expiresAt) > Date.now()
  } catch {
    return false
  }
}

export async function prepareGrant (db, { contentId, publicKey, credentialId, capability, signingPublicKey }) {
  const gates = await runGates({ db, contentId, publicKey, credentialId })
  if (!gates.ok) return { error: gates.reason, status: 403 }

  if (contentId.startsWith('mail:')) {
    const row = db.prepare('SELECT recipient_public_key FROM mailbox WHERE id = ?').get(Number(contentId.slice(5)))
    if (!row || row.recipient_public_key !== publicKey) return { error: 'not allowed', status: 403 }
  } else if (contentId.startsWith('src:')) {
    const row = db.prepare('SELECT id FROM protected_urls WHERE id = ?').get(contentId.slice(4))
    if (!row) return { error: 'content not found', status: 404 }
  } else {
    const content = db.prepare(
      'SELECT id, is_public, payment_required FROM content WHERE id = ?'
    ).get(contentId)
    if (!content) return { error: 'content not found', status: 404 }
    if (content.is_public !== 1) {
      const allowed = db.prepare(`
        SELECT id FROM allowlist
        WHERE content_id = ? AND public_key = ? AND (expires_at IS NULL OR expires_at > ?)
      `).get(contentId, publicKey, Date.now())
      if (!allowed && !capabilityAllows(signingPublicKey, capability, contentId, publicKey)) {
        return { error: 'not allowed', status: 403 }
      }
    }
    if (content.payment_required === 1) {
      let paid = false
      for (const mod of modulesByKind('payment')) {
        if (await mod.isPaid({ db, contentId, publicKey })) paid = true
      }
      if (!paid) return { error: 'payment required', status: 402 }
    }
  }
  return issueGrant(db, { contentId, publicKey, credentialId })
}

export function consumeGrant (db, { grantId, contentId, publicKey }) {
  const result = db.prepare(`
    UPDATE grants
    SET spent = 1
    WHERE id = ? AND spent = 0 AND content_id = ? AND public_key = ? AND expires_at > ?
  `).run(grantId, contentId, publicKey, Date.now())
  return result.changes === 1
}
