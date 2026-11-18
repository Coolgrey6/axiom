import { writeAudit } from '../audit.js'
import { canonicalKemKey } from '../crypto.js'
import { readGrant, setGrantCookie, setSessionCookie } from '../middleware/human.js'
import { authenticationOptions, registerCredential, registrationOptions, verifyAssertion } from '../webauthn.js'

function fail (reply, status, error) {
  return reply.code(status).send({ error })
}

export default async function webauthnRoutes (app) {
  app.post('/webauthn/register/options', async () => {
    return registrationOptions(app.db)
  })

  app.post('/webauthn/register', async (request, reply) => {
    const result = await registerCredential(app.db, request.body)
    if (result.error) return fail(reply, result.status, result.error)
    setSessionCookie(reply, request, result.credentialId)
    writeAudit(app.db, 'webauthn.register', { credentialId: result.credentialId })
    return { status: 'ok' }
  })

  app.post('/webauthn/assert/options', async (request, reply) => {
    const contentId = request.body?.contentId
    const publicKey = canonicalKemKey(request.body?.publicKey)
    if (typeof contentId !== 'string' || contentId.length === 0 || contentId.length > 160) {
      return fail(reply, 400, 'invalid content')
    }
    if (!publicKey) return fail(reply, 400, 'invalid public key')
    const options = await authenticationOptions(app.db, { contentId, publicKey })
    if (options.error) return fail(reply, options.status, options.error)
    return options
  })

  app.post('/verify-human', async (request, reply) => {
    const contentId = request.body?.contentId
    const publicKey = canonicalKemKey(request.body?.publicKey)
    if (typeof contentId !== 'string' || !publicKey || !request.body?.response) {
      return fail(reply, 400, 'invalid request')
    }
    const result = await verifyAssertion(app.db, {
      response: request.body.response,
      contentId,
      publicKey,
      capability: request.body.capability,
      signingPublicKey: app.signingKeys.publicKey
    })
    if (result.error) return fail(reply, result.status, result.error)
    setSessionCookie(reply, request, result.credentialId)
    setGrantCookie(reply, request, result.grantId)
    writeAudit(app.db, 'human.verified', { contentId, credentialId: result.credentialId })
    return { status: 'ok', grantId: result.grantId, expiresAt: result.expiresAt }
  })
}

export { readGrant }
