export function writeAudit (db, event, details) {
  db.prepare(
    'INSERT INTO audit_log (event, details, created_at) VALUES (?, ?, ?)'
  ).run(event, JSON.stringify(details ?? {}), Date.now())
}
