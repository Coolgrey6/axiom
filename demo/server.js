import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public')
const app = express()
app.use(express.static(root))

const port = Number(process.env.DEMO_PORT || 3000)
app.listen(port, '127.0.0.1', () => {
  console.log(`Harbor Office demo at http://127.0.0.1:${port}/`)
})
