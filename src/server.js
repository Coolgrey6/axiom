import fs from 'node:fs'
import path from 'node:path'
import { createApp } from './createApp.js'

const keyPath = path.resolve('certs', 'key.pem')
const certPath = path.resolve('certs', 'cert.pem')

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  console.error('HTTPS certificates are required. Place key.pem and cert.pem in ./certs/')
  process.exit(1)
}

const app = await createApp({
  https: {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  }
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    await app.close()
    process.exit(0)
  })
}

try {
  await app.listen({ port: 8443, host: '0.0.0.0' })
} catch (error) {
  app.log.error(error)
  process.exit(1)
}
