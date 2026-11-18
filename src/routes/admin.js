import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { removeBlob, writeBlob } from '../blobs.js'
import { writeAudit } from '../audit.js'
import {
  canonicalKemKey,
  canonicalSignKey,
  encryptBytes,
  fingerprintOf,
  randomContentKey,
  signPayload,
  wrapContentKey
} from '../crypto.js'
import { isValidCidr } from '../middleware/firewall.js'
import { requireAdmin } from '../middleware/adminAuth.js'
import { createSource, findSource, listSources, presentSource, removeSource } from '../sources.js'

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const TEXT_LIMIT = 1_000_000
const FILE_LIMIT = 8 * 1024 * 1024
const CONTENT_COLUMNS = 'id, title, summary, filename, mime, is_public, payment_required, price, created_at'

function cleanFilename (name) {
  const base = path.basename(String(name || 'file')).replace(/[\u0000-\u001f]/g, '').slice(0, 200)
  return base || 'file'
}

function cleanMime (type) {
  if (typeof type !== 'string') return 'application/octet-stream'
  const trimmed = type.split(';')[0].trim().toLowerCase()
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(trimmed) || trimmed.length > 200) {
    return 'application/octet-stream'
  }
  return trimmed
}

function bytesFromRequest (body) {
  if (body?.file && typeof body.file === 'object') {
    const data = body.file.data
    if (typeof data !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(data)) {
      return { error: 'invalid file' }
    }
    const bytes = Buffer.from(data, 'base64')
    if (bytes.length === 0 || bytes.length > FILE_LIMIT) return { error: 'invalid file' }
    return {
      bytes,
      filename: cleanFilename(body.file.name),
      mime: cleanMime(body.file.type)
    }
  }
  const plaintext = body?.plaintext
  if (typeof plaintext !== 'string' || plaintext.length === 0 || Buffer.byteLength(plaintext) > TEXT_LIMIT) {
    return { error: 'invalid plaintext' }
  }
  return { bytes: Buffer.from(plaintext), filename: null, mime: 'text/plain' }
}

function fail (reply, status, error) {
  return reply.code(status).send({ error })
}

function presentContent (row) {
  return {
    id: row.id,
    title: row.title,
    summary: row.summary || '',
    isPublic: row.is_public === 1,
    paymentRequired: row.payment_required === 1,
    filename: row.filename || '',
    mime: row.mime || 'text/plain',
    price: row.price || 0,
    createdAt: row.created_at
  }
}

function presentAllow (row) {
  return {
    id: row.id,
    contentId: row.content_id,
    publicKey: row.public_key,
    fingerprint: row.fingerprint,
    expiresAt: row.expires_at
  }
}

async function storeBytes (app, id, bytes) {
  const contentKey = randomContentKey()
  const ciphertext = await encryptBytes(contentKey, bytes)
  const file = writeBlob(`${id}.json`, ciphertext)
  const wrappedKey = await wrapContentKey(app.masterKey, contentKey)
  return { file, wrappedKey }
}

export default async function adminRoutes (app) {
  app.addHook('preHandler', requireAdmin)

  app.post('/admin/bootstrap', async (request, reply) => {
    const publicKey = canonicalSignKey(request.body?.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    const created = app.db.transaction(() => {
      const count = app.db.prepare('SELECT COUNT(*) AS n FROM admins').get().n
      if (count > 0) return null
      const fingerprint = fingerprintOf(publicKey)
      const result = app.db.prepare(
        'INSERT INTO admins (public_key, fingerprint) VALUES (?, ?)'
      ).run(publicKey, fingerprint)
      return { id: Number(result.lastInsertRowid), publicKey, fingerprint }
    })()
    if (!created) return fail(reply, 409, 'admin already registered')
    writeAudit(app.db, 'admin.bootstrap', { id: created.id, fingerprint: created.fingerprint })
    return reply.code(201).send(created)
  })

  app.get('/admin/content', async () => {
    return app.db.prepare(
      `SELECT ${CONTENT_COLUMNS} FROM content ORDER BY created_at DESC`
    ).all().map(presentContent)
  })

  app.post('/admin/content', async (request, reply) => {
    const title = request.body?.title
    const summary = typeof request.body?.summary === 'string' ? request.body.summary.trim().slice(0, 600) : ''
    const isPublic = request.body?.isPublic !== false
    const paymentRequired = request.body?.paymentRequired === true
    const price = Number(request.body?.price || 0)
    if (typeof title !== 'string' || title.length === 0 || title.length > 500) {
      return fail(reply, 400, 'invalid title')
    }
    if (isPublic && !summary) return fail(reply, 400, 'Add a short description for the public page.')
    const incoming = bytesFromRequest(request.body)
    if (incoming.error) return fail(reply, 400, incoming.error)
    const id = request.body?.id ?? randomUUID()
    if (typeof id !== 'string' || !ID_RE.test(id)) return fail(reply, 400, 'invalid id')
    if (app.db.prepare('SELECT id FROM content WHERE id = ?').get(id)) {
      return fail(reply, 409, 'content already exists')
    }
    const stored = await storeBytes(app, id, incoming.bytes)
    const createdAt = Date.now()
    const storedPrice = Number.isFinite(price) ? price : 0
    app.db.prepare(`
      INSERT INTO content (id, title, summary, filename, mime, is_public, payment_required, price, ciphertext_path, wrapped_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, title, summary, incoming.filename, incoming.mime, isPublic ? 1 : 0, paymentRequired ? 1 : 0, storedPrice, stored.file, stored.wrappedKey, createdAt)
    writeAudit(app.db, 'content.create', { id, isPublic, paymentRequired, filename: incoming.filename, mime: incoming.mime, bytes: incoming.bytes.length })
    return reply.code(201).send({ id, title, summary, filename: incoming.filename || '', mime: incoming.mime, isPublic, paymentRequired, price: storedPrice, createdAt })
  })

  app.get('/admin/content/:id', async (request, reply) => {
    const row = app.db.prepare(
      `SELECT ${CONTENT_COLUMNS} FROM content WHERE id = ?`
    ).get(request.params.id)
    if (!row) return fail(reply, 404, 'content not found')
    const allowlist = app.db.prepare(
      'SELECT id, content_id, public_key, fingerprint, expires_at FROM allowlist WHERE content_id = ? ORDER BY id'
    ).all(row.id).map(presentAllow)
    return { ...presentContent(row), allowlist }
  })

  app.patch('/admin/content/:id', async (request, reply) => {
    const row = app.db.prepare('SELECT id, ciphertext_path FROM content WHERE id = ?').get(request.params.id)
    if (!row) return fail(reply, 404, 'content not found')
    const fields = []
    const values = []
    if (request.body?.title !== undefined) {
      if (typeof request.body.title !== 'string' || request.body.title.length === 0 || request.body.title.length > 500) {
        return fail(reply, 400, 'invalid title')
      }
      fields.push('title = ?')
      values.push(request.body.title)
    }
    if (request.body?.isPublic !== undefined) {
      fields.push('is_public = ?')
      values.push(request.body.isPublic === true ? 1 : 0)
    }
    if (request.body?.plaintext !== undefined || request.body?.file !== undefined) {
      const incoming = bytesFromRequest(request.body)
      if (incoming.error) return fail(reply, 400, incoming.error)
      const stored = await storeBytes(app, row.id, incoming.bytes)
      if (stored.file !== row.ciphertext_path) removeBlob(row.ciphertext_path)
      fields.push('ciphertext_path = ?', 'wrapped_key = ?', 'filename = ?', 'mime = ?')
      values.push(stored.file, stored.wrappedKey, incoming.filename, incoming.mime)
    }
    if (fields.length === 0) return fail(reply, 400, 'no changes')
    values.push(row.id)
    app.db.prepare(`UPDATE content SET ${fields.join(', ')} WHERE id = ?`).run(...values)
    writeAudit(app.db, 'content.update', { id: row.id })
    const updated = app.db.prepare(
      `SELECT ${CONTENT_COLUMNS} FROM content WHERE id = ?`
    ).get(row.id)
    return presentContent(updated)
  })

  app.delete('/admin/content/:id', async (request, reply) => {
    const row = app.db.prepare('SELECT id, ciphertext_path FROM content WHERE id = ?').get(request.params.id)
    if (!row) return fail(reply, 404, 'content not found')
    app.db.prepare('DELETE FROM allowlist WHERE content_id = ?').run(row.id)
    app.db.prepare('DELETE FROM content WHERE id = ?').run(row.id)
    removeBlob(row.ciphertext_path)
    writeAudit(app.db, 'content.delete', { id: row.id })
    return { status: 'deleted' }
  })

  app.get('/admin/content/:id/allowlist', async (request, reply) => {
    const content = app.db.prepare('SELECT id FROM content WHERE id = ?').get(request.params.id)
    if (!content) return fail(reply, 404, 'content not found')
    return app.db.prepare(
      'SELECT id, content_id, public_key, fingerprint, expires_at FROM allowlist WHERE content_id = ? ORDER BY id'
    ).all(content.id).map(presentAllow)
  })

  app.post('/admin/content/:id/allowlist', async (request, reply) => {
    const content = app.db.prepare('SELECT id FROM content WHERE id = ?').get(request.params.id)
    if (!content) return fail(reply, 404, 'content not found')
    const publicKey = canonicalKemKey(request.body?.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    let expiresAt = null
    if (request.body?.expiresAt != null) {
      expiresAt = Number(request.body.expiresAt)
      if (!Number.isFinite(expiresAt)) return fail(reply, 400, 'invalid expiresAt')
    }
    const fingerprint = fingerprintOf(publicKey)
    app.db.prepare('DELETE FROM allowlist WHERE content_id = ? AND public_key = ?').run(content.id, publicKey)
    const result = app.db.prepare(`
      INSERT INTO allowlist (content_id, public_key, fingerprint, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(content.id, publicKey, fingerprint, expiresAt)
    writeAudit(app.db, 'allowlist.add', { contentId: content.id, fingerprint })
    return reply.code(201).send({
      id: Number(result.lastInsertRowid),
      contentId: content.id,
      publicKey,
      fingerprint,
      expiresAt
    })
  })

  app.delete('/admin/allowlist/:id', async (request, reply) => {
    const id = Number(request.params.id)
    const row = app.db.prepare('SELECT id, content_id, fingerprint FROM allowlist WHERE id = ?').get(id)
    if (!row) return fail(reply, 404, 'allowlist entry not found')
    app.db.prepare('DELETE FROM allowlist WHERE id = ?').run(id)
    writeAudit(app.db, 'allowlist.remove', { id, contentId: row.content_id, fingerprint: row.fingerprint })
    return { status: 'deleted' }
  })

  app.post('/admin/capability', async (request, reply) => {
    const content = app.db.prepare('SELECT id FROM content WHERE id = ?').get(request.body?.contentId)
    if (!content) return fail(reply, 404, 'content not found')
    const publicKey = canonicalKemKey(request.body?.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    const expiresAt = Number(request.body?.expiresAt)
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      return fail(reply, 400, 'invalid expiresAt')
    }
    const token = await signPayload(app.signingKeys.privateKey, {
      contentId: content.id,
      publicKey,
      expiresAt
    })
    writeAudit(app.db, 'capability.issue', { contentId: content.id, fingerprint: fingerprintOf(publicKey), expiresAt })
    return token
  })

  app.get('/admin/firewall/ip', async () => {
    return app.db.prepare(
      'SELECT id, cidr, action, created_at FROM firewall_ip ORDER BY id'
    ).all().map((row) => ({
      id: row.id,
      cidr: row.cidr,
      action: row.action,
      createdAt: row.created_at
    }))
  })

  app.post('/admin/firewall/ip', async (request, reply) => {
    const cidr = request.body?.cidr
    const action = request.body?.action
    if (!isValidCidr(cidr)) return fail(reply, 400, 'invalid cidr')
    if (action !== 'allow' && action !== 'deny') return fail(reply, 400, 'invalid action')
    const createdAt = Date.now()
    const result = app.db.prepare(
      'INSERT INTO firewall_ip (cidr, action, created_at) VALUES (?, ?, ?)'
    ).run(cidr, action, createdAt)
    writeAudit(app.db, 'firewall.ip.add', { cidr, action })
    return reply.code(201).send({ id: Number(result.lastInsertRowid), cidr, action, createdAt })
  })

  app.delete('/admin/firewall/ip/:id', async (request, reply) => {
    const id = Number(request.params.id)
    const row = app.db.prepare('SELECT id, cidr FROM firewall_ip WHERE id = ?').get(id)
    if (!row) return fail(reply, 404, 'rule not found')
    app.db.prepare('DELETE FROM firewall_ip WHERE id = ?').run(id)
    writeAudit(app.db, 'firewall.ip.remove', { id, cidr: row.cidr })
    return { status: 'deleted' }
  })

  app.get('/admin/firewall/geo', async () => {
    return app.db.prepare(
      'SELECT id, country_code, action, created_at FROM firewall_geo ORDER BY id'
    ).all().map((row) => ({
      id: row.id,
      countryCode: row.country_code,
      action: row.action,
      createdAt: row.created_at
    }))
  })

  app.post('/admin/firewall/geo', async (request, reply) => {
    const countryCode = typeof request.body?.countryCode === 'string'
      ? request.body.countryCode.toUpperCase()
      : ''
    const action = request.body?.action
    if (!/^[A-Z]{2}$/.test(countryCode)) return fail(reply, 400, 'invalid countryCode')
    if (action !== 'allow' && action !== 'deny') return fail(reply, 400, 'invalid action')
    const createdAt = Date.now()
    const result = app.db.prepare(
      'INSERT INTO firewall_geo (country_code, action, created_at) VALUES (?, ?, ?)'
    ).run(countryCode, action, createdAt)
    writeAudit(app.db, 'firewall.geo.add', { countryCode, action })
    return reply.code(201).send({ id: Number(result.lastInsertRowid), countryCode, action, createdAt })
  })

  app.delete('/admin/firewall/geo/:id', async (request, reply) => {
    const id = Number(request.params.id)
    const row = app.db.prepare('SELECT id, country_code FROM firewall_geo WHERE id = ?').get(id)
    if (!row) return fail(reply, 404, 'rule not found')
    app.db.prepare('DELETE FROM firewall_geo WHERE id = ?').run(id)
    writeAudit(app.db, 'firewall.geo.remove', { id, countryCode: row.country_code })
    return { status: 'deleted' }
  })

  app.get('/admin/audit', async (request) => {
    const limit = Math.min(500, Math.max(1, Number(request.query.limit) || 100))
    return app.db.prepare(
      'SELECT id, event, details, created_at FROM audit_log ORDER BY id DESC LIMIT ?'
    ).all(limit).map((row) => {
      let details = row.details
      try { details = JSON.parse(row.details) } catch { /* keep the raw string */ }
      return { id: row.id, event: row.event, details, createdAt: row.created_at }
    })
  })

  app.get('/admin/admins', async () => {
    return app.db.prepare('SELECT id, public_key, fingerprint FROM admins ORDER BY id').all().map((row) => ({
      id: row.id,
      publicKey: row.public_key,
      fingerprint: row.fingerprint
    }))
  })

  app.post('/admin/admins', async (request, reply) => {
    const publicKey = canonicalSignKey(request.body?.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    if (app.db.prepare('SELECT id FROM admins WHERE public_key = ?').get(publicKey)) {
      return fail(reply, 409, 'admin already registered')
    }
    const fingerprint = fingerprintOf(publicKey)
    const result = app.db.prepare(
      'INSERT INTO admins (public_key, fingerprint) VALUES (?, ?)'
    ).run(publicKey, fingerprint)
    writeAudit(app.db, 'admin.add', { fingerprint })
    return reply.code(201).send({ id: Number(result.lastInsertRowid), publicKey, fingerprint })
  })

  app.delete('/admin/admins/:id', async (request, reply) => {
    const id = Number(request.params.id)
    const row = app.db.prepare('SELECT id, fingerprint FROM admins WHERE id = ?').get(id)
    if (!row) return fail(reply, 404, 'admin not found')
    const count = app.db.prepare('SELECT COUNT(*) AS n FROM admins').get().n
    if (count <= 1) return fail(reply, 409, 'last admin cannot be removed')
    app.db.prepare('DELETE FROM admins WHERE id = ?').run(id)
    writeAudit(app.db, 'admin.remove', { id, fingerprint: row.fingerprint })
    return { status: 'deleted' }
  })

  app.get('/admin/sources', async () => {
    return listSources(app.db).map((row) => presentSource(row, { includeOrigin: true }))
  })

  app.post('/admin/sources', async (request, reply) => {
    const created = createSource(app.db, request.body)
    if (created.error) return fail(reply, created.status, created.error)
    writeAudit(app.db, 'source.create', { id: created.source.id, mountPath: created.source.mountPath })
    return reply.code(201).send(created.source)
  })

  app.delete('/admin/sources/:id', async (request, reply) => {
    const existing = findSource(app.db, request.params.id)
    const removed = removeSource(app.db, request.params.id)
    if (removed.error) return fail(reply, removed.status, removed.error)
    writeAudit(app.db, 'source.remove', { id: existing.id })
    return removed.body
  })

  app.post('/admin/invoices/:id/confirm', async (request, reply) => {
    const row = app.db.prepare('SELECT id, status FROM invoices WHERE id = ?').get(request.params.id)
    if (!row) return fail(reply, 404, 'invoice not found')
    app.db.prepare(`UPDATE invoices SET status = 'paid' WHERE id = ?`).run(row.id)
    writeAudit(app.db, 'payment.confirm', { id: row.id })
    return { id: row.id, status: 'paid' }
  })
}
