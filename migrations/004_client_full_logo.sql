-- Adds clients.logo_full_url: the client's full (top-bar) logo as a PNG data
-- URL, uploaded from the Add/Edit Client modals. clients.logo_url keeps the
-- icon used in the sidebar and avatar. The server runs this same statement
-- automatically on startup once the database connects, so applying this file
-- by hand (e.g. `psql "$DATABASE_URL" -f migrations/004_client_full_logo.sql`)
-- is optional. Safe to re-run: the statement is idempotent.

ALTER TABLE clients ADD COLUMN IF NOT EXISTS logo_full_url TEXT;
