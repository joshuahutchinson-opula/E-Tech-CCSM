-- Indexes for the SR tab's server-side search (GET
-- /api/service-requests/search): client-scoped lists ordered/filtered by
-- created_at, status filters and the open/high-priority summary counts, and
-- the single batched sr_history lookup (sr_id = ANY(...) ORDER BY
-- created_at) for each results page. This codebase has no migration runner
-- — apply this file manually against the production Postgres database (e.g.
-- via `psql "$DATABASE_URL" -f migrations/003_sr_search_indexes.sql`) before
-- deploying the server.js changes that add the search endpoint. Safe to
-- re-run: every statement is idempotent. Nothing here changes data, and the
-- endpoint still works (just slower on large tables) if this hasn't run yet.

CREATE INDEX IF NOT EXISTS idx_service_requests_client_created ON service_requests (client_id, created_at);

CREATE INDEX IF NOT EXISTS idx_service_requests_status ON service_requests (status);

CREATE INDEX IF NOT EXISTS idx_sr_history_sr_created ON sr_history (sr_id, created_at);
