-- ============================================================================
-- Forward delta: workload deletion (phase 7 of ENFORCEMENT-ARCHITECTURE.md §7).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_workload_delete.sql
--
-- Depends on governance_eviction.sql.
--
-- WHAT THIS IS
-- The last and largest cluster action: removing the owning controller of a
-- contained agent, and letting a policy's on_expiry='evict' actually carry it out
-- instead of only planning it.
--
-- WHY IT IS SEPARATE FROM EVICTION (EN-9)
-- Evicting a pod stops the current process and the controller reschedules it.
-- Deleting the controller destroys something the customer created. Those are
-- categorically different acts, so nothing about enabling eviction enables this:
-- its own agent switch, its own namespace list, its own RBAC.
--
-- AND IT DOES NOT SURVIVE GITOPS. A Deployment declared in git is recreated on the
-- next sync, typically within minutes. That limit is REPORTED on every deletion
-- rather than hidden, because a workload that reappears looks like a failed
-- enforcement when it is actually the reconciler doing its job. The durable fix is
-- removing it from git, which this system cannot and should not do.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

DO $$
BEGIN
    ALTER TABLE public.provisioning_instructions
        DROP CONSTRAINT IF EXISTS provisioning_instructions_kind_chk;
    ALTER TABLE public.provisioning_instructions
        ADD CONSTRAINT provisioning_instructions_kind_chk CHECK (
            kind IN ('quarantine', 'unquarantine', 'verify_uptake',
                     'evict_pods', 'delete_workload'));
END $$;

-- What the cluster says it can do, alongside enforcement_evict. An observation
-- reported on the plan poll, never a setting pushed to the cluster: the control
-- plane queues a deletion only for a connector that said it can carry one out.
ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_delete boolean NOT NULL DEFAULT false;
