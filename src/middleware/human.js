import { signCookie, unsignCookie } from '../cookies.js'

const SESSION_MS = 60 * 60 * 1000
const GRANT_MS = 5 * 60 * 1000

function cookieOptions (maxAge) {
  return {
    signed: false,
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge
  }
}

export function setSessionCookie (reply, request, credentialId) {
  reply.setCookie('axiom_session', signCookie(credentialId, request.server.cookieSecret), cookieOptions(SESSION_MS / 1000))
}

export function setGrantCookie (reply, request, grantId) {
  reply.setCookie('axiom_grant', signCookie(grantId, request.server.cookieSecret), cookieOptions(GRANT_MS / 1000))
}

export function readSession (request) {
  return unsignCookie(request.cookies?.axiom_session, request.server.cookieSecret)
}

export function readGrant (request) {
  return unsignCookie(request.cookies?.axiom_grant, request.server.cookieSecret)
}

export function requireSession (request, reply) {
  const session = readSession(request)
  if (!session.valid) return reply.code(401).send({ error: 'human verification required' })
  request.credentialId = session.value
}
