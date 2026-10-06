-- ============================================================================
-- tenancy-validate.sql -- operator follow-up to migrations 045-048
--
-- Read-only. Run against the deployed database whenever convenient:
--
--   psql "$DATABASE_URL" -X -f scripts/tenancy-validate.sql
--
-- 047 added its constraints NOT VALID: they hold for new writes, but rows
-- that existed before were never checked. This script lists, for each such
-- constraint, how many existing rows violate it and the statement to run once
-- that count is zero. VALIDATE CONSTRAINT scans the table under a SHARE UPDATE
-- EXCLUSIVE lock (reads and writes continue), so it can run online.
--
-- Tables where 047 installed trg_tenancy_require_ws instead of a CHECK (they
-- still had rows without a workspace) are listed with the CHECK to add and the
-- trigger to drop once their NULL count is zero.
--
-- Fix violations by resolving the rows in tenancy_backfill_orphans (listed at
-- the end), then re-run SELECT * FROM public.tenancy_backfill_workspace_ids();
-- never by assigning rows to a guessed or customer workspace.
-- ============================================================================

CREATE OR REPLACE FUNCTION pg_temp.tenancy_validate()
RETURNS TABLE (tbl text, constraint_name text, kind text, violating_rows bigint, next_step text)
LANGUAGE plpgsql
AS $fn$
DECLARE
    c record;
    cond text;
    i int;
BEGIN
    -- NOT VALID foreign keys and checks added by the tenancy migrations.
    FOR c IN
        SELECT k.oid, k.conname, k.contype, k.conrelid, k.confrelid, k.conkey, k.confkey,
               k.conrelid::regclass::text AS rel, k.confrelid::regclass::text AS frel
          FROM pg_constraint k
          JOIN pg_namespace n ON n.oid = k.connamespace AND n.nspname = 'public'
         WHERE NOT k.convalidated
           AND k.contype IN ('f', 'c')
         ORDER BY k.conrelid::regclass::text, k.conname
    LOOP
        tbl := c.rel;
        constraint_name := c.conname;
        IF c.contype = 'f' THEN
            kind := 'foreign key';
            cond := '';
            FOR i IN 1 .. array_length(c.conkey, 1) LOOP
                cond := cond || format(' AND x.%I IS NOT NULL',
                    (SELECT attname FROM pg_attribute WHERE attrelid = c.conrelid AND attnum = c.conkey[i]));
            END LOOP;
            cond := cond || ' AND NOT EXISTS (SELECT 1 FROM ' || c.frel || ' p WHERE true';
            FOR i IN 1 .. array_length(c.conkey, 1) LOOP
                cond := cond || format(' AND p.%I = x.%I',
                    (SELECT attname FROM pg_attribute WHERE attrelid = c.confrelid AND attnum = c.confkey[i]),
                    (SELECT attname FROM pg_attribute WHERE attrelid = c.conrelid AND attnum = c.conkey[i]));
            END LOOP;
            cond := cond || ')';
            EXECUTE 'SELECT count(*) FROM ' || c.rel || ' x WHERE true' || cond INTO violating_rows;
        ELSE
            kind := 'check';
            EXECUTE format('SELECT count(*) FROM %s x WHERE (%s) IS FALSE',
                           c.rel, pg_get_expr((SELECT conbin FROM pg_constraint WHERE oid = c.oid), c.conrelid))
               INTO violating_rows;
        END IF;
        next_step := CASE
            WHEN violating_rows = 0
                THEN format('ALTER TABLE %s VALIDATE CONSTRAINT %I;', c.rel, c.conname)
            ELSE 'resolve the violating rows first'
        END;
        RETURN NEXT;
    END LOOP;

    -- Tables still guarded by the trigger instead of a CHECK.
    FOR c IN
        SELECT t.tgrelid::regclass::text AS rel, cl.relname
          FROM pg_trigger t
          JOIN pg_class cl ON cl.oid = t.tgrelid
         WHERE t.tgname = 'trg_tenancy_require_ws' AND NOT t.tgisinternal
         ORDER BY 1
    LOOP
        tbl := c.rel;
        constraint_name := 'ck_' || c.relname || '_tenancy_ws_nn';
        kind := 'pending check (trigger guard)';
        EXECUTE format('SELECT count(*) FROM %s WHERE workspace_id IS NULL', c.rel) INTO violating_rows;
        next_step := CASE
            WHEN violating_rows = 0 THEN format(
                'ALTER TABLE %1$s ADD CONSTRAINT %2$I CHECK (workspace_id IS NOT NULL) NOT VALID; '
                'ALTER TABLE %1$s VALIDATE CONSTRAINT %2$I; '
                'DROP TRIGGER trg_tenancy_require_ws ON %1$s;',
                c.rel, 'ck_' || c.relname || '_tenancy_ws_nn')
            ELSE 'resolve the rows with NULL workspace_id first'
        END;
        RETURN NEXT;
    END LOOP;
END
$fn$;

\echo '== NOT VALID tenancy constraints and their violations =='
SELECT * FROM pg_temp.tenancy_validate();

\echo '== Unattributed rows recorded by the backfill (tenancy_backfill_orphans) =='
SELECT table_name, reason, count(*) AS rows, min(recorded_at) AS first_recorded
  FROM public.tenancy_backfill_orphans
 GROUP BY table_name, reason
 ORDER BY table_name, reason;
