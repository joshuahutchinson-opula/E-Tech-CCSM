-- Gives each access-control door three warranty dates (controller, reader,
-- lock) in place of the single doors.warranty_expiry, which is kept but no
-- longer read or written. In the run that creates the new columns, every door
-- with an old date and no part dates gets that date copied into all three; a
-- value that isn't a readable YYYY-MM-DD date is skipped. Because the copy is
-- tied to creating the columns, re-running never refills a part cleared since.
-- expiry_alerts_sent then tracks each part separately, so its kind CHECK is
-- widened to the part kinds. Requires migrations/007. The server runs these
-- same statements automatically on startup once the database connects, so
-- applying this file by hand (e.g.
-- `psql "$DATABASE_URL" -f migrations/008_door_component_warranties.sql`)
-- is optional. Safe to re-run: every statement is idempotent.

DO $$
DECLARE r RECORD;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'doors' AND column_name = 'controller_warranty_expiry') THEN
    ALTER TABLE doors ADD COLUMN controller_warranty_expiry DATE;
    ALTER TABLE doors ADD COLUMN IF NOT EXISTS reader_warranty_expiry DATE;
    ALTER TABLE doors ADD COLUMN IF NOT EXISTS lock_warranty_expiry DATE;
    FOR r IN SELECT id, substring(warranty_expiry::text from '^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}') AS w FROM doors
        WHERE warranty_expiry IS NOT NULL AND controller_warranty_expiry IS NULL AND reader_warranty_expiry IS NULL AND lock_warranty_expiry IS NULL LOOP
      CONTINUE WHEN r.w IS NULL;
      BEGIN
        UPDATE doors SET controller_warranty_expiry = r.w::date, reader_warranty_expiry = r.w::date, lock_warranty_expiry = r.w::date WHERE id = r.id;
      EXCEPTION WHEN others THEN NULL;
      END;
    END LOOP;
  END IF;
END $$;

ALTER TABLE doors ADD COLUMN IF NOT EXISTS reader_warranty_expiry DATE;
ALTER TABLE doors ADD COLUMN IF NOT EXISTS lock_warranty_expiry DATE;

DO $$
DECLARE c RECORD; dropped BOOLEAN := FALSE;
BEGIN
  FOR c IN SELECT conname FROM pg_constraint WHERE conrelid = 'expiry_alerts_sent'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%kind%' AND pg_get_constraintdef(oid) NOT LIKE '%warranty-lock%' LOOP
    EXECUTE format('ALTER TABLE expiry_alerts_sent DROP CONSTRAINT %I', c.conname);
    dropped := TRUE;
  END LOOP;
  IF dropped THEN
    ALTER TABLE expiry_alerts_sent ADD CONSTRAINT expiry_alerts_sent_kind_check
      CHECK (kind IN ('warranty', 'licence', 'warranty-controller', 'warranty-reader', 'warranty-lock'));
  END IF;
END $$;
