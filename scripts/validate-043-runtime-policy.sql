-- Validate 043 outside the deploy transaction.
--
-- 043 creates only new, empty tables. Their checks and foreign keys are
-- added already valid, so this script does not ALTER anything and does not
-- take ACCESS EXCLUSIVE. It asserts that no 043 constraint was left
-- NOT VALID. Run it with autocommit, not inside psql -1 and not inside the
-- migration runner's transaction:
--
--   psql -v ON_ERROR_STOP=1 -f scripts/validate-043-runtime-policy.sql
--
-- Re-runnable. A second run asserts the same thing and changes nothing.
-- Rollback of 043 is IGA_V2_POLICY off; do not drop these tables to roll back.
--
-- Ops step, same shape as 040/041/042/045: run this file once after 043
-- commits, on the primary, outside the deploy transaction. There is nothing
-- to VALIDATE today. If a later edit adds a NOT VALID constraint on one of
-- these tables, this script fails until that constraint is validated here.

DO $$
DECLARE
    pending text;
BEGIN
    SELECT string_agg(conname, ', ' ORDER BY conname)
      INTO pending
      FROM pg_constraint
     WHERE NOT convalidated
       AND (
            conname LIKE 'runtime_policy%'
         OR conname LIKE 'collector_capability_reports%'
       );
    IF pending IS NOT NULL THEN
        RAISE EXCEPTION '043 left NOT VALID constraints: %', pending;
    END IF;
END $$;
