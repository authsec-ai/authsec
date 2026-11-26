-- ============================================================================
-- 133: iga_gov_job's kind CHECK carries every job kind
--
-- 052 was edited in place (eef366a0) to add the kind 'resolve_unknown' to
-- the iga_gov_job.kind CHECK. A database that applied the earlier 052 still
-- has the old constraint, refuses a resolve_unknown job, and is not caught
-- by the runner (052 is recorded as applied). The constraint is re-created
-- here with 052's current kind list (repositories.GovJobKinds; checked by
-- tests/igagovschema TestGovJobKindsMatch052Check).
--
-- Idempotent: dropped and re-added under its own name, skipped when the
-- table does not exist. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
BEGIN
    IF to_regclass('public.iga_gov_job') IS NOT NULL THEN
        ALTER TABLE public.iga_gov_job DROP CONSTRAINT IF EXISTS iga_gov_job_kind_check;
        ALTER TABLE public.iga_gov_job ADD CONSTRAINT iga_gov_job_kind_check
            CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                            'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync',
                            'prune_evidence','metrics_rollup','resolve_unknown'));
    END IF;
END $$;
