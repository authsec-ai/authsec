-- ============================================================================
-- Forward delta: force-delete escalation (phase 8 of ENFORCEMENT-ARCHITECTURE.md §7).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_force_evict.sql
--
-- Depends on governance_eviction.sql.
--
-- WHAT THIS IS
-- The override for an eviction a PodDisruptionBudget refused. `DELETE pod` with
-- gracePeriodSeconds=0 bypasses the budget entirely, which is exactly why eviction
-- uses the Eviction API in the first place (EN-6) -- so this is the one operation
-- in the system that deliberately overrules something the cluster owner declared.
--
-- IT IS NEVER AUTOMATIC. No reconciler, no policy expiry, and no retry path can
-- reach it. It exists only behind an explicit human action, and the schema makes
-- that structural rather than conventional: a force_delete_pods instruction that
-- does not name WHO asked for it and WHY cannot be written at all.
--
-- The service adds one more precondition the schema cannot express: there must be
-- a PDB-blocked eviction on record for that agent. You cannot force-delete
-- something that was never refused -- that would make this a first resort, and a
-- first resort is not an escalation.
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
                     'evict_pods', 'delete_workload', 'force_delete_pods'));

    -- ATTRIBUTION IS STRUCTURAL. Overriding a disruption budget is a decision a
    -- person has to answer for, so an unattributed or unjustified one is rejected
    -- by the database rather than by whichever code path happened to remember.
    ALTER TABLE public.provisioning_instructions
        DROP CONSTRAINT IF EXISTS provisioning_instructions_force_chk;
    ALTER TABLE public.provisioning_instructions
        ADD CONSTRAINT provisioning_instructions_force_chk CHECK (
            kind <> 'force_delete_pods'
            OR (created_by <> '' AND coalesce(payload->>'reason', '') <> ''));
END $$;

-- What the cluster says it can do. Third and last of the capability flags, and
-- separate from enforcement_delete on purpose: an operator may well want to permit
-- deleting a workload while never permitting a disruption budget to be overruled.
ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_force_evict boolean NOT NULL DEFAULT false;
