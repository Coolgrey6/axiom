import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import { signCookie, unsignCookie } from './cookies.js'
import { canonicalKemKey } from './crypto.js'
import { consumeGrant } from './grants.js'
import { checkAdmin } from './middleware/adminAuth.js'
import { inspectRequest } from './middleware/firewall.js'
import { storeMessage } from './routes/mail.js'
import { authenticationOptions, registerCredential, registrationOptions, verifyAssertion } from './webauthn.js'
import { readBlob } from './blobs.js'
import { encapsulateContentKey, signPayload, unwrapContentKey } from './crypto.js'
import { createSource, fetchSource, findSource, listSources, matchMount, presentSource, publicCatalog, removeSource, sealSource, sourceContentId } from './sources.js'

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public')

function cookieHeader (req, name, secret) {
  const header = req.headers.cookie || ''
  const found = header.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))
  if (!found) return { valid: false, value: null }
  return unsignCookie(decodeURIComponent(found.slice(name.length + 1)), secret)
}

export function attachAxiom (app, { db, masterKey, signingKeys, cookieSecret }) {
  app.use(express.json({
    verify: (req, _res, buffer) => {
      req.rawBody = buffer.toString('utf8')
    }
  }))
  app.use(async (req, res, next) => {
    const result = await inspectRequest(db, req.ip, req.path)
    if (result.block) return res.status(403).json({ error: 'blocked' })
    if (req.method === 'GET' || req.method === 'HEAD') {
      const match = matchMount(db, req.path)
      if (match) return res.redirect(`/view.html?id=${encodeURIComponent(match.id)}`)
    }
    next()
  })

  for (const file of ['view.html', 'admin.html', 'axiom.css', 'logo.jpg', 'client.bundle.js']) {
    app.get(`/${file}`, (_req, res) => {
      res.sendFile(path.join(publicDir, file))
    })
  }

  app.get('/catalog', (_req, res) => {
    res.json(publicCatalog(db))
  })

  app.get('/sources', (_req, res) => {
    res.json(listSources(db).map((row) => presentSource(row)))
  })

  app.get('/sources/:id', (req, res) => {
    const row = findSource(db, req.params.id)
    if (!row) return res.status(404).json({ error: 'page not found' })
    res.json(presentSource(row))
  })

  app.post('/source/:id/key', async (req, res) => {
    const publicKey = canonicalKemKey(req.body?.publicKey)
    if (!publicKey) return res.status(400).json({ error: 'invalid public key' })
    const row = findSource(db, req.params.id)
    if (!row) return res.status(404).json({ error: 'page not found' })
    const grant = cookieHeader(req, 'axiom_grant', cookieSecret)
    if (!grant.valid || !consumeGrant(db, { grantId: grant.value, contentId: sourceContentId(row.id), publicKey })) {
      return res.status(401).json({ error: 'human verification required' })
    }
    try {
      const fetched = await fetchSource(row.source_url)
      res.json(await sealSource({ signingKeys, id: row.id, publicKey, fetched }))
    } catch (error) {
      res.status(error.status || 502).json({ error: error.message || 'origin unavailable' })
    }
  })

  async function adminOnly (req, res) {
    const result = await checkAdmin(db, {
      method: req.method,
      url: req.originalUrl.split('?')[0],
      rawBody: req.rawBody || '',
      headers: req.headers
    })
    if (!result.ok) {
      res.status(result.status).json({ error: result.error })
      return false
    }
    return true
  }

  app.get('/admin/sources', async (req, res) => {
    if (!await adminOnly(req, res)) return
    res.json(listSources(db).map((row) => presentSource(row, { includeOrigin: true })))
  })

  app.post('/admin/sources', async (req, res) => {
    if (!await adminOnly(req, res)) return
    const created = createSource(db, req.body)
    if (created.error) return res.status(created.status).json({ error: created.error })
    res.status(201).json(created.source)
  })

  app.delete('/admin/sources/:id', async (req, res) => {
    if (!await adminOnly(req, res)) return
    const removed = removeSource(db, req.params.id)
    if (removed.error) return res.status(removed.status).json({ error: removed.error })
    res.json(removed.body)
  })

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' })
  })

  app.post('/webauthn/register/options', async (_req, res) => {
    res.json(await registrationOptions(db))
  })

  app.post('/webauthn/register', async (req, res) => {
    const result = await registerCredential(db, req.body)
    if (result.error) return res.status(result.status).json({ error: result.error })
    res.setHeader('set-cookie', `axiom_session=${encodeURIComponent(signCookie(result.credentialId, cookieSecret))}; HttpOnly; Path=/; Max-Age=3600`)
    res.json({ status: 'ok' })
  })

  app.post('/webauthn/assert/options', async (req, res) => {
    const publicKey = canonicalKemKey(req.body?.publicKey)
    const options = await authenticationOptions(db, { contentId: req.body?.contentId, publicKey })
    if (options.error) return res.status(options.status).json({ error: options.error })
    res.json(options)
  })

  app.post('/verify-human', async (req, res) => {
    const publicKey = canonicalKemKey(req.body?.publicKey)
    const result = await verifyAssertion(db, { response: req.body?.response, contentId: req.body?.contentId, publicKey })
    if (result.error) return res.status(result.status).json({ error: result.error })
    const session = signCookie(result.credentialId, cookieSecret)
    const grant = signCookie(result.grantId, cookieSecret)
    res.setHeader('set-cookie', [
      `axiom_session=${encodeURIComponent(session)}; HttpOnly; Path=/; Max-Age=3600`,
      `axiom_grant=${encodeURIComponent(grant)}; HttpOnly; Path=/; Max-Age=300`
    ])
    res.json({ status: 'ok', grantId: result.grantId, expiresAt: result.expiresAt })
  })

  app.post('/content/:id/key', async (req, res) => {
    const publicKey = canonicalKemKey(req.body?.publicKey)
    if (!publicKey) return res.status(400).json({ error: 'invalid public key' })
    const row = db.prepare('SELECT id, filename, mime, ciphertext_path, wrapped_key FROM content WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'content not found' })
    const grant = cookieHeader(req, 'axiom_grant', cookieSecret)
    if (!grant.valid || !consumeGrant(db, { grantId: grant.value, contentId: String(row.id), publicKey })) {
      return res.status(401).json({ error: 'human verification required' })
    }
    const contentKey = await unwrapContentKey(masterKey, row.wrapped_key)
    const signed = await signPayload(signingKeys.privateKey, {
      id: row.id,
      filename: row.filename,
      mime: row.mime || 'text/plain',
      ciphertext: readBlob(row.ciphertext_path),
      encapsulation: await encapsulateContentKey(publicKey, contentKey)
    })
    res.json({ ...signed, serverPublicKey: signingKeys.publicKey })
  })

  app.post('/mail/send', async (req, res) => {
    const session = cookieHeader(req, 'axiom_session', cookieSecret)
    if (!session.valid) return res.status(401).json({ error: 'human verification required' })
    const recipient = canonicalKemKey(req.body?.recipientPublicKey)
    if (!recipient || typeof req.body?.plaintext !== 'string') return res.status(400).json({ error: 'invalid request' })
    res.status(201).json(await storeMessage(db, masterKey, { recipient, plaintext: req.body.plaintext }))
  })
}
