-- Index-only follow-up for the 043 runtime-policy tables.
--
-- 043 already created the publication, target, and receipt tables. This file
-- does not add columns or tables. It only adds the indexes the sync, rollout,
-- and collector-list paths filter on. The runner wraps each file in one
-- transaction, so these statements are not CREATE INDEX CONCURRENTLY.
--
-- Rehearsals apply every master file except 043, then apply 043 afterwards.
-- When that happens the tables are not here yet, so the indexes are skipped.
-- A normal apply runs 043 before 048 and creates them.
--
-- Rollback of delivery is IGA_V2_POLICY off. Do not drop these indexes to
-- roll back a publication.

DO $$
BEGIN
    IF to_regclass('public.runtime_policy_targets') IS NULL
       OR to_regclass('public.runtime_policy_receipts') IS NULL
       OR to_regclass('public.runtime_policy_publications') IS NULL THEN
        RAISE NOTICE '048 skipped: runtime policy tables are not present yet';
        RETURN;
    END IF;
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_runtime_policy_targets_collector_delivery ON public.runtime_policy_targets (workspace_id, collector_id, desired_delivery_revision DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_runtime_policy_receipts_target_delivery ON public.runtime_policy_receipts (workspace_id, target_id, delivery_revision, observed_at DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_runtime_policy_publications_policy_created ON public.runtime_policy_publications (workspace_id, policy_id, created_at DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_runtime_policy_publications_canary ON public.runtime_policy_publications ((rollout_plan->>''phase'')) WHERE (rollout_plan->>''phase'') = ''canary''';
END $$;
