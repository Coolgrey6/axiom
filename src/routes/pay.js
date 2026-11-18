import { randomUUID } from 'node:crypto'
import { writeAudit } from '../audit.js'
import { canonicalKemKey } from '../crypto.js'
import { requireSession } from '../middleware/human.js'

function fail (reply, status, error) {
  return reply.code(status).send({ error })
}

export default async function payRoutes (app) {
  app.post('/pay', async (request, reply) => {
    if (requireSession(request, reply)) return
    const publicKey = canonicalKemKey(request.body?.publicKey)
    const contentId = request.body?.contentId
    if (!publicKey || typeof contentId !== 'string') return fail(reply, 400, 'invalid request')
    const content = app.db.prepare(
      'SELECT id, payment_required, price FROM content WHERE id = ?'
    ).get(contentId)
    if (!content) return fail(reply, 404, 'content not found')
    if (content.payment_required !== 1) return fail(reply, 409, 'payment not required')
    const id = randomUUID()
    const createdAt = Date.now()
    app.db.prepare(`
      INSERT INTO invoices (id, content_id, public_key, amount, currency, status, created_at)
      VALUES (?, ?, ?, ?, 'sats', 'pending', ?)
    `).run(id, content.id, publicKey, content.price || 0, createdAt)
    writeAudit(app.db, 'payment.invoice', { id, contentId: content.id })
    return reply.code(201).send({
      id,
      contentId: content.id,
      amount: content.price || 0,
      currency: 'sats',
      status: 'pending',
      provider: 'manual'
    })
  })
}
