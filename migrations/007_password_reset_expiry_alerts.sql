-- Adds forgot-password links for client accounts and warranty/licence expiry
-- alerts. password_resets stores only the SHA-256 of each emailed token (like
-- invites); users.password_changed_at signs out sessions issued before a
-- reset. expiry_alerts_sent records each 60- and 30-day alert per item and
-- expiry date, so a changed date starts fresh alerts.
-- client_report_settings.expiry_alerts turns a client's daily digest off
-- (their items still appear in the staff digest), report_admin_settings
-- .expiry_last_run keeps the daily check to once a day, and reports.kind
-- gains 'expiry' for the saved digests. Requires migrations/006. The server
-- runs these same statements automatically on startup once the database
-- connects, so applying this file by hand (e.g.
-- `psql "$DATABASE_URL" -f migrations/007_password_reset_expiry_alerts.sql`)
-- is optional. Safe to re-run: every statement is idempotent.

CREATE TABLE IF NOT EXISTS password_resets (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS password_resets_user_idx ON password_resets (user_id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS expiry_alerts_sent (
  id SERIAL PRIMARY KEY,
  asset_table TEXT NOT NULL,
  asset_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('warranty', 'licence')),
  expiry_date DATE NOT NULL,
  threshold INTEGER NOT NULL CHECK (threshold IN (60, 30)),
  report_id INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (asset_table, asset_id, kind, expiry_date, threshold)
);

ALTER TABLE client_report_settings ADD COLUMN IF NOT EXISTS expiry_alerts BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE report_admin_settings ADD COLUMN IF NOT EXISTS expiry_last_run DATE;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'reports_kind_check' AND pg_get_constraintdef(oid) LIKE '%expiry%') THEN
    ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_kind_check;
    ALTER TABLE reports ADD CONSTRAINT reports_kind_check CHECK (kind IN ('admin', 'client', 'expiry'));
  END IF;
END $$;
