-- Adds stored monthly reports: reports (each generated report's subject,
-- HTML and key figures), report_deliveries (one row per recipient, sent or
-- failed, with retry attempts), client_report_settings (per-client
-- recipients; no row means the defaults: contact email plus every active
-- client user) and report_admin_settings (extra recipients for the admin
-- report, which always goes to support@). The partial unique index allows one
-- scheduled report per client (and one admin report) per month.
-- report_admin_settings.installed_at records when stored reports began; the
-- missed-report catch-up only sends months that fell due after it. The server
-- runs these same statements automatically on startup once the database
-- connects, so applying this file by hand (e.g.
-- `psql "$DATABASE_URL" -f migrations/006_reports.sql`) is optional. Safe to
-- re-run: every statement is idempotent.

CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('admin', 'client')),
  client_id INTEGER,
  period_start DATE NOT NULL,
  period_end DATE NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  html TEXT NOT NULL DEFAULT '',
  summary JSONB NOT NULL DEFAULT '{}',
  source TEXT NOT NULL CHECK (source IN ('scheduled', 'manual')),
  created_by TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS reports_one_scheduled_per_month ON reports (kind, COALESCE(client_id, 0), period_start) WHERE source = 'scheduled';
CREATE INDEX IF NOT EXISTS reports_created_at_idx ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS reports_client_idx ON reports (client_id, period_start DESC);

CREATE TABLE IF NOT EXISTS report_deliveries (
  id SERIAL PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  recipient TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
  error TEXT,
  attempts INTEGER NOT NULL DEFAULT 1,
  sent_by TEXT,
  last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS report_deliveries_report_recipient ON report_deliveries (report_id, recipient);
CREATE INDEX IF NOT EXISTS report_deliveries_status_idx ON report_deliveries (status, created_at);

CREATE TABLE IF NOT EXISTS client_report_settings (
  client_id INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  include_users BOOLEAN NOT NULL DEFAULT TRUE,
  excluded_user_ids INTEGER[] NOT NULL DEFAULT '{}',
  extra_recipients TEXT[] NOT NULL DEFAULT '{}',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS report_admin_settings (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  extra_recipients TEXT[] NOT NULL DEFAULT '{}',
  installed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO report_admin_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
