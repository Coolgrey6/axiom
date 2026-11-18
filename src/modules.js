const modules = []

export function registerModule (mod) {
  if (!mod?.name || !mod?.kind) throw new Error('invalid module')
  if (modules.some((entry) => entry.name === mod.name && entry.kind === mod.kind)) return mod
  modules.push(mod)
  return mod
}

export function modulesByKind (kind) {
  return modules.filter((entry) => entry.kind === kind)
}

export async function runGates (ctx) {
  for (const mod of modulesByKind('gate')) {
    const result = await mod.check(ctx)
    if (!result?.ok) return { ok: false, reason: result?.reason || mod.name }
  }
  return { ok: true }
}

export const manualPayment = {
  name: 'manual',
  kind: 'payment',
  async isPaid ({ db, contentId, publicKey }) {
    const row = db.prepare(`
      SELECT id FROM invoices
      WHERE content_id = ? AND public_key = ? AND status = 'paid'
    `).get(contentId, publicKey)
    return Boolean(row)
  }
}
