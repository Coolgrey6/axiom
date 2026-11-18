const host = process.env.VERCEL_URL
if (host && !process.env.AXIOM_ORIGIN) {
  process.env.AXIOM_ORIGIN = `https://${host}`
  process.env.AXIOM_RP_ID = host
}

const { createApp } = await import('../src/app.js')
const app = await createApp()
await app.ready()

export default function handler (request, response) {
  app.server.emit('request', request, response)
}
