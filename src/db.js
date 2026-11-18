import fs from 'node:fs'
import path from 'node:path'
import Database from 'better-sqlite3'
import { dataDir } from './paths.js'

const SCHEMA = `
CREATE TABLE IF NOT EXISTS content (
  id TEXT PRIMARY KEY,
  title TEXT,
  is_public INTEGER,
  ciphertext_path TEXT,
  wrapped_key TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY,
  content_id TEXT,
  public_key TEXT,
  fingerprint TEXT,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS firewall_ip (
  id INTEGER PRIMARY KEY,
  cidr TEXT,
  action TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS firewall_geo (
  id INTEGER PRIMARY KEY,
  country_code TEXT,
  action TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  event TEXT,
  details TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY,
  public_key TEXT,
  fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS mailbox (
  id INTEGER PRIMARY KEY,
  recipient_public_key TEXT,
  ciphertext_path TEXT,
  wrapped_key TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS credentials (
  credential_id TEXT PRIMARY KEY,
  public_key TEXT,
  counter INTEGER,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge TEXT PRIMARY KEY,
  kind TEXT,
  content_id TEXT,
  public_key TEXT,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  content_id TEXT,
  public_key TEXT,
  credential_id TEXT,
  expires_at INTEGER,
  spent INTEGER,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  content_id TEXT,
  public_key TEXT,
  amount INTEGER,
  currency TEXT,
  status TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS addresses (
  address TEXT PRIMARY KEY,
  public_key TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS protected_urls (
  id TEXT PRIMARY KEY,
  label TEXT,
  source_url TEXT,
  mount_path TEXT,
  created_at INTEGER
);
`

function ensureColumn (db, table, column, type) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all()
  if (!columns.some((entry) => entry.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`)
  }
}

export function openDatabase () {
  const dbPath = path.join(dataDir(), 'axiom.db')
  fs.mkdirSync(path.dirname(dbPath), { recursive: true })
  const db = new Database(dbPath)
  db.exec(SCHEMA)
  ensureColumn(db, 'content', 'wrapped_key', 'TEXT')
  ensureColumn(db, 'content', 'payment_required', 'INTEGER')
  ensureColumn(db, 'content', 'price', 'INTEGER')
  ensureColumn(db, 'content', 'filename', 'TEXT')
  ensureColumn(db, 'content', 'mime', 'TEXT')
  ensureColumn(db, 'content', 'summary', 'TEXT')
  ensureColumn(db, 'protected_urls', 'summary', 'TEXT')
  ensureColumn(db, 'mailbox', 'wrapped_key', 'TEXT')
  return db
}
