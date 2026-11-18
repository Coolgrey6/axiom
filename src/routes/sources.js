import { writeAudit } from '../audit.js'
import { canonicalKemKey, fingerprintOf } from '../crypto.js'
import { consumeGrant } from '../grants.js'
import { readGrant } from '../middleware/human.js'
import { fetchSource, findSource, listSources, presentSource, publicCatalog, sealSource, sourceContentId } from '../sources.js'

function fail (reply, status, error) {
  return reply.code(status).send({ error })
}

export default async function sourceRoutes (app) {
  app.get('/catalog', async () => {
    return publicCatalog(app.db)
  })

  app.get('/sources', async () => {
    return listSources(app.db).map((row) => presentSource(row))
  })

  app.get('/sources/:id', async (request, reply) => {
    const row = findSource(app.db, request.params.id)
    if (!row) return fail(reply, 404, 'page not found')
    return presentSource(row)
  })

  app.post('/source/:id/key', async (request, reply) => {
    const publicKey = canonicalKemKey(request.body?.publicKey)
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    const row = findSource(app.db, request.params.id)
    if (!row) return fail(reply, 404, 'page not found')
    const grant = readGrant(request)
    if (!grant.valid || !consumeGrant(app.db, { grantId: grant.value, contentId: sourceContentId(row.id), publicKey })) {
      return fail(reply, 401, 'human verification required')
    }
    try {
      const fetched = await fetchSource(row.source_url)
      const sealed = await sealSource({
        signingKeys: app.signingKeys,
        id: row.id,
        publicKey,
        fetched
      })
      writeAudit(app.db, 'source.key_released', { id: row.id, fingerprint: fingerprintOf(publicKey) })
      return sealed
    } catch (error) {
      return fail(reply, error.status || 502, error.message || 'origin unavailable')
    }
  })
}
