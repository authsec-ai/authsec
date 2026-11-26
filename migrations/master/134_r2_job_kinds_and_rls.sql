-- ============================================================================
-- 134: iga_gov_job's kind CHECK keeps the R2 kinds; RLS on the R1b/R2/R3
--      tables of a database that applied 060-062 after 131
--
-- 1. 133 re-created iga_gov_job_kind_check with the kinds of 052 (up to
--    resolve_unknown). 061 (R2, merged from authsec-staging) had widened the
--    same CHECK with 'temp_grant', 'session_revoke' and 'time_bound'; 133 runs
--    after 061 on every database (fresh: 001 then 002..133 in order;
--    upgraded staging: 133 is new) and dropped them, so R2 jobs were refused
--    and VerifyPolicyR2Schema kept IGA_POLICY_R2 misconfigured. The CHECK is
--    re-created with every kind (repositories.GovJobKinds; checked by
--    tests/igagovschema TestGovJobKindsMatch052Check).
--
-- 2. 060-062 sort before 111 but a database built from the tenancy branch
--    before it merged authsec-staging applies them after 111 and 131, and
--    their tables were left without the tenancy_isolation policy. Every
--    public table with a workspace_id column and no policy gets it (131's
--    loop, again). A fresh or upgraded staging database already has it.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
BEGIN
    IF to_regclass('public.iga_gov_job') IS NOT NULL THEN
        ALTER TABLE public.iga_gov_job DROP CONSTRAINT IF EXISTS iga_gov_job_kind_check;
        ALTER TABLE public.iga_gov_job ADD CONSTRAINT iga_gov_job_kind_check
            CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                            'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync',
                            'prune_evidence','metrics_rollup','resolve_unknown',
                            'temp_grant','session_revoke','time_bound'));
    END IF;
END $$;

DO $$
DECLARE
    t regclass;
BEGIN
    FOR t IN
        SELECT c.oid::regclass
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
           AND NOT EXISTS (SELECT 1 FROM pg_policies p
                            WHERE p.schemaname = 'public' AND p.tablename = c.relname
                              AND p.policyname = 'tenancy_isolation')
         ORDER BY 1
    LOOP
        PERFORM public.tenancy_enable_rls(t);
    END LOOP;
END $$;
