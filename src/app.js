import path from 'node:path'
import Fastify from 'fastify'
import fastifyStatic from '@fastify/static'
import fastifyCookie from '@fastify/cookie'
import { openDatabase } from './db.js'
import { loadCookieSecret, loadMasterKey, loadSigningKeys } from './keys.js'
import { createFirewallHook } from './middleware/firewall.js'
import contentRoutes from './routes/content.js'
import adminRoutes from './routes/admin.js'
import mailRoutes from './routes/mail.js'
import webauthnRoutes from './routes/webauthn.js'
import payRoutes from './routes/pay.js'
import sourceRoutes from './routes/sources.js'
import { manualPayment, registerModule } from './modules.js'
import { matchMount } from './sources.js'
import { startSmtp } from './smtp.js'

export async function createApp ({ https = null } = {}) {
  const app = Fastify({
    bodyLimit: 12 * 1024 * 1024,
    ...(https ? { https } : {})
  })

  const cookieSecret = loadCookieSecret()
  app.decorate('db', openDatabase())
  app.decorate('masterKey', loadMasterKey())
  app.decorate('signingKeys', await loadSigningKeys())
  app.decorate('cookieSecret', cookieSecret)
  app.decorateRequest('rawBody', '')
  registerModule(manualPayment)

  app.addContentTypeParser('application/json', { parseAs: 'string' }, (request, body, done) => {
    request.rawBody = body
    if (!body) {
      done(null, {})
      return
    }
    try {
      done(null, JSON.parse(body))
    } catch (error) {
      error.statusCode = 400
      done(error)
    }
  })

  await app.register(fastifyCookie, { secret: cookieSecret })
  app.addHook('onRequest', createFirewallHook())
  if (process.env.VERCEL) {
    app.addHook('onClose', async () => {
      app.db.close()
    })
  } else {
    const smtp = startSmtp({ db: app.db, masterKey: app.masterKey })
    app.addHook('onClose', async () => {
      await new Promise((resolve) => smtp.close(resolve))
      app.db.close()
    })
  }

  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('X-Robots-Tag', 'noindex, nofollow, noarchive')
    return payload
  })

  app.get('/health', async () => {
    return { status: 'ok' }
  })

  app.addHook('onRequest', async (request, reply) => {
    if (request.method !== 'GET' && request.method !== 'HEAD') return
    const match = matchMount(app.db, request.url)
    if (!match) return
    return reply.redirect(`/view.html?id=${encodeURIComponent(match.id)}`)
  })

  await app.register(webauthnRoutes)
  await app.register(contentRoutes)
  await app.register(adminRoutes)
  await app.register(mailRoutes)
  await app.register(payRoutes)
  await app.register(sourceRoutes)

  await app.register(fastifyStatic, {
    root: path.resolve('public')
  })

  return app
}
