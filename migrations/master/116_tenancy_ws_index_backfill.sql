-- ============================================================================
-- 116: a full workspace_id-leading index on every workspace table (AS-080)
--
-- 048 created idx_<table>_tenancy_ws where a table had no index leading with
-- workspace_id. It counted partial indexes, which cannot serve an arbitrary
-- workspace-scoped query (cloud_permission had only
-- idx_cloud_permission_constrained ... WHERE constraint_state <> ...), and it
-- ran before 068 gave otp_entries a workspace_id. A fresh bootstrap re-runs
-- the step at its end, so fresh and upgraded databases differed by these
-- indexes (scripts/schema-parity.sh). This repeats the step, counting only
-- non-partial indexes.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
          JOIN pg_attribute a ON a.attrelid = c.oid
                             AND a.attname = 'workspace_id'
                             AND NOT a.attisdropped
                             AND a.atttypid = 'uuid'::regtype
         WHERE c.relkind = 'r'
           AND NOT EXISTS (SELECT 1 FROM pg_index i
                            WHERE i.indrelid = c.oid AND i.indkey[0] = a.attnum
                              AND i.indpred IS NULL)
         ORDER BY c.relname
    LOOP
        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON public.%I (workspace_id)',
                       'idx_' || r.relname || '_tenancy_ws', r.relname);
    END LOOP;
END $$;
