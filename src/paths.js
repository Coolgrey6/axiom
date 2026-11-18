import path from 'node:path'

export function dataDir () {
  if (process.env.VERCEL) return '/tmp/axiom'
  return path.resolve('data')
}
