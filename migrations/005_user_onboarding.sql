-- Adds users.onboarded_at: when a client user finished the first-login
-- walkthrough in the dashboard. NULL means they haven't, so every existing
-- client user sees the walkthrough once (intended). An E-Tech admin can set
-- it back to NULL from the Users panel ("Reset tutorial"). The server runs
-- this same statement automatically on startup once the database connects,
-- so applying this file by hand (e.g.
-- `psql "$DATABASE_URL" -f migrations/005_user_onboarding.sql`) is optional.
-- Safe to re-run: the statement is idempotent.

ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarded_at TIMESTAMP;
