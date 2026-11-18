import { SMTPServer } from 'smtp-server'
import { canonicalKemKey } from './crypto.js'
import { storeMessage } from './routes/mail.js'

function textBody (raw) {
  const text = raw.toString('utf8')
  const parts = text.split(/\r?\n\r?\n/)
  const body = parts.slice(1).join('\n\n').trim()
  return body || text.trim()
}

export function startSmtp ({ db, masterKey, port = Number(process.env.AXIOM_SMTP_PORT || 2525) }) {
  const server = new SMTPServer({
    disabledCommands: ['AUTH', 'STARTTLS'],
    authOptional: true,
    onData (stream, session, callback) {
      const chunks = []
      stream.on('data', (chunk) => chunks.push(chunk))
      stream.on('end', async () => {
        try {
          const recipient = session.envelope.rcptTo[0]?.address?.toLowerCase()
          const row = db.prepare('SELECT public_key FROM addresses WHERE address = ?').get(recipient)
          const publicKey = canonicalKemKey(row?.public_key)
          const plaintext = textBody(Buffer.concat(chunks))
          if (!publicKey || !plaintext) {
            callback(new Error('recipient is not registered'))
            return
          }
          await storeMessage(db, masterKey, { recipient: publicKey, plaintext })
          callback()
        } catch (error) {
          callback(error)
        }
      })
    }
  })
  server.on('error', (error) => {
    console.error(`SMTP listener failed: ${error.message}`)
  })
  server.listen(port, '127.0.0.1')
  return server
}
