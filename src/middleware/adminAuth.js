import { adminMessage, canonicalSignKey, verify } from '../crypto.js'

const SKEW_MS = 5 * 60 * 1000

export async function checkAdmin (db, { method, url, rawBody = '', headers }) {
  const timestamp = headers['x-axiom-admin-timestamp']
  const signature = headers['x-axiom-admin-signature']
  const presented = canonicalSignKey(headers['x-axiom-admin-key'])
  if (typeof timestamp !== 'string' || typeof signature !== 'string' || !presented) {
    return { ok: false, status: 401, error: 'admin signature required' }
  }
  const issuedAt = Number(timestamp)
  if (!Number.isFinite(issuedAt) || Math.abs(Date.now() - issuedAt) > SKEW_MS) {
    return { ok: false, status: 401, error: 'admin signature expired' }
  }
  const admin = db.prepare('SELECT id FROM admins WHERE public_key = ?').get(presented)
  if (!admin) return { ok: false, status: 403, error: 'admin not recognized' }
  const message = adminMessage({ timestamp, method, url, body: rawBody ?? '' })
  const ok = verify(presented, message, signature)
  if (!ok) return { ok: false, status: 401, error: 'bad admin signature' }
  return { ok: true, publicKey: presented }
}

export async function requireAdmin (request, reply) {
  const path = request.url.split('?')[0]
  if (request.method === 'POST' && path === '/admin/bootstrap') return
  const result = await checkAdmin(request.server.db, {
    method: request.method,
    url: request.url,
    rawBody: request.rawBody ?? '',
    headers: request.headers
  })
  if (!result.ok) return reply.code(result.status).send({ error: result.error })
  request.adminPublicKey = result.publicKey
}
