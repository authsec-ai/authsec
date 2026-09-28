-- Validate 048 outside the deploy transaction.
--
-- 048 only creates indexes on the 043 runtime-policy tables. It does not
-- ALTER columns and does not take ACCESS EXCLUSIVE beyond the index build
-- itself. This script asserts the four index names exist. Run it with
-- autocommit, not inside psql -1 and not inside the migration runner's
-- transaction:
--
--   psql -v ON_ERROR_STOP=1 -f scripts/validate-048-policy-delivery-indexes.sql
--
-- Re-runnable. A second run asserts the same thing and changes nothing.

DO $$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(wanted, ', ' ORDER BY wanted)
      INTO missing
      FROM (
          VALUES
              ('idx_runtime_policy_targets_collector_delivery'),
              ('idx_runtime_policy_receipts_target_delivery'),
              ('idx_runtime_policy_publications_policy_created'),
              ('idx_runtime_policy_publications_canary')
      ) AS names(wanted)
     WHERE NOT EXISTS (
         SELECT 1 FROM pg_indexes
          WHERE schemaname = 'public' AND indexname = wanted
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION '048 indexes missing: %', missing;
    END IF;
END $$;
