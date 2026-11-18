import { randomBytes } from 'node:crypto'
import path from 'node:path'
import {
  encapsulateContentKey,
  encryptBytes,
  randomContentKey,
  signPayload
} from './crypto.js'

const FILE_LIMIT = 8 * 1024 * 1024
const RESERVED = new Set([
  '/',
  '/admin.html',
  '/view.html',
  '/index.html',
  '/health',
  '/robots.txt',
  '/logo.jpg',
  '/axiom.css',
  '/client.bundle.js',
  '/client.js'
])

export function sourceContentId (id) {
  return `src:${id}`
}

export function presentSource (row, { includeOrigin = false } = {}) {
  const page = {
    id: row.id,
    label: row.label,
    summary: row.summary || '',
    mountPath: row.mount_path || '',
    visitorPath: `/view.html?id=${encodeURIComponent(row.id)}`,
    createdAt: row.created_at
  }
  if (includeOrigin) page.sourceUrl = row.source_url
  return page
}

export function listSources (db) {
  return db.prepare(
    'SELECT id, label, summary, source_url, mount_path, created_at FROM protected_urls ORDER BY created_at DESC'
  ).all()
}

export function findSource (db, id) {
  if (typeof id !== 'string' || !/^[a-f0-9]{12}$/.test(id)) return null
  return db.prepare(
    'SELECT id, label, summary, source_url, mount_path, created_at FROM protected_urls WHERE id = ?'
  ).get(id) || null
}

export function matchMount (db, requestPath) {
  const pathname = requestPath.split('?')[0]
  if (!pathname || pathname === '/') return null
  return db.prepare(
    'SELECT id, label, summary, source_url, mount_path, created_at FROM protected_urls WHERE mount_path = ?'
  ).get(pathname) || null
}

function cleanSummary (value) {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/[\u0000-\u001f]/g, '').slice(0, 600)
}

function cleanLabel (label) {
  if (typeof label !== 'string') return ''
  const trimmed = label.trim().replace(/[\u0000-\u001f]/g, '')
  return trimmed.slice(0, 120)
}

function cleanSourceUrl (value) {
  if (typeof value !== 'string' || value.length > 2000) return null
  let url
  try { url = new URL(value.trim()) } catch { return null }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  if (url.username || url.password) return null
  return url.toString()
}

function cleanMount (value) {
  if (value == null || value === '') return ''
  if (typeof value !== 'string' || value.length > 200) return null
  const pathname = value.trim()
  if (!pathname.startsWith('/') || pathname.includes('?') || pathname.includes('#') || pathname.includes('..')) return null
  if (RESERVED.has(pathname) || pathname.startsWith('/admin') || pathname.startsWith('/webauthn') || pathname.startsWith('/content') || pathname.startsWith('/source') || pathname.startsWith('/mail') || pathname.startsWith('/pay')) {
    return null
  }
  return pathname
}

export function createSource (db, body) {
  const label = cleanLabel(body?.label)
  const summary = cleanSummary(body?.summary)
  const sourceUrl = cleanSourceUrl(body?.sourceUrl)
  const mountPath = cleanMount(body?.mountPath)
  if (!label) return { error: 'Add a name for this page.', status: 400 }
  if (!summary) return { error: 'Add a short description. Visitors can read it. Programs cannot open the page.', status: 400 }
  if (!sourceUrl) return { error: 'Enter the full http or https URL from your existing server.', status: 400 }
  if (mountPath == null) return { error: 'A local path starts with / and cannot replace the home page, admin, or unlock routes.', status: 400 }
  if (mountPath && db.prepare('SELECT id FROM protected_urls WHERE mount_path = ?').get(mountPath)) {
    return { error: 'That local path is already protected.', status: 409 }
  }
  let id = ''
  for (let attempt = 0; attempt < 5; attempt += 1) {
    id = randomBytes(6).toString('hex')
    if (!findSource(db, id)) break
  }
  const createdAt = Date.now()
  db.prepare(`
    INSERT INTO protected_urls (id, label, summary, source_url, mount_path, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, label, summary, sourceUrl, mountPath, createdAt)
  return { status: 201, source: presentSource({ id, label, summary, source_url: sourceUrl, mount_path: mountPath, created_at: createdAt }, { includeOrigin: true }) }
}

export function publicCatalog (db) {
  const pages = listSources(db).map((row) => ({
    kind: 'page',
    id: row.id,
    title: row.label,
    summary: row.summary || '',
    href: row.mount_path || `/view.html?id=${encodeURIComponent(row.id)}`
  }))
  const notes = db.prepare(`
    SELECT id, title, summary, filename FROM content
    WHERE is_public = 1
    ORDER BY created_at DESC
  `).all().map((row) => ({
    kind: row.filename ? 'file' : 'note',
    id: row.id,
    title: row.title,
    summary: row.summary || '',
    href: `/view.html?content=${encodeURIComponent(row.id)}`
  }))
  return [...pages, ...notes]
}

export function removeSource (db, id) {
  const row = findSource(db, id)
  if (!row) return { error: 'page not found', status: 404 }
  db.prepare('DELETE FROM protected_urls WHERE id = ?').run(id)
  return { status: 200, body: { status: 'deleted' } }
}

export async function fetchSource (sourceUrl) {
  const target = new URL(sourceUrl)
  const response = await fetch(target, {
    redirect: 'follow',
    signal: AbortSignal.timeout(15000),
    headers: { 'user-agent': 'Axiom' }
  })
  if (!response.ok) {
    const error = new Error('origin unavailable')
    error.status = 502
    throw error
  }
  const bytes = Buffer.from(await response.arrayBuffer())
  if (bytes.length === 0 || bytes.length > FILE_LIMIT) {
    const error = new Error('that page is empty or larger than 8 MB')
    error.status = 400
    throw error
  }
  const mime = (response.headers.get('content-type') || 'application/octet-stream').split(';')[0].trim().toLowerCase() || 'application/octet-stream'
  const filename = path.basename(target.pathname) || 'page'
  return { bytes, mime, filename }
}

export async function sealSource ({ signingKeys, id, publicKey, fetched }) {
  const contentKey = randomContentKey()
  const ciphertext = await encryptBytes(contentKey, fetched.bytes)
  const signed = await signPayload(signingKeys.privateKey, {
    id: sourceContentId(id),
    filename: fetched.filename,
    mime: fetched.mime,
    ciphertext,
    encapsulation: await encapsulateContentKey(publicKey, contentKey)
  })
  return { ...signed, serverPublicKey: signingKeys.publicKey }
}
