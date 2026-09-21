-- Adds per-person client login accounts (users, zones, user_zone_access,
-- invites) alongside the existing shared KFTL/KWL/PAJ env-var logins, which
-- keep working unchanged. This codebase has no migration runner — apply
-- this file manually against the production Postgres database (e.g. via
-- `psql "$DATABASE_URL" -f migrations/001_client_user_accounts.sql`) before
-- deploying the server.js changes that reference these tables. Safe to
-- re-run: every statement is idempotent.

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('client_admin','client_user')),
  invited_by TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS zones (
  id SERIAL PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  UNIQUE(client_id, name)
);

CREATE TABLE IF NOT EXISTS user_zone_access (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, zone_id)
);

-- token_hash stores a SHA-256 hash of the invite token, never the plaintext
-- token itself (the plaintext only ever exists in the emailed link).
-- zone_ids carries which zones to grant on acceptance for a client_user
-- invite; empty for a client_admin invite (they get all zones implicitly).
CREATE TABLE IF NOT EXISTS invites (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('client_admin','client_user')),
  invited_by TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  zone_ids INTEGER[] NOT NULL DEFAULT '{}',
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_client_id ON users(client_id);
CREATE INDEX IF NOT EXISTS idx_zones_client_id ON zones(client_id);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
