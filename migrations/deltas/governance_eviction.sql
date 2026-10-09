-- ============================================================================
-- Forward delta: eviction (phase 5 of ENFORCEMENT-ARCHITECTURE.md §7).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_eviction.sql
--
-- Depends on governance_actuation.sql and governance_enforcement_plan.sql.
--
-- WHAT THIS IS
-- Quarantine cuts an agent's network and leaves the process running. This adds the
-- half that stops it: an evict_pods instruction the in-cluster agent applies through
-- the Kubernetes Eviction API, so PodDisruptionBudgets are honoured (EN-6).
--
-- WHY EVICTION IS A SEPARATE SWITCH (EN-5)
-- Deny without evict leaves the agent running; evict without deny recreates it in
-- seconds. Both are needed for quarantine to mean anything, and they carry different
-- risk, so they are enabled independently -- an operator should be able to run
-- eviction for a week before anything sits in the admission request path.
--
-- The switch is REPORTED BY THE AGENT, not pushed to it. The control plane never
-- calls into a cluster (EN-0), so a stored intent the cluster had not adopted would
-- read in the console exactly like one it had. enforcement_evict is what the agent
-- said about itself on its last plan poll, and the control plane only queues an
-- eviction for a connector that said it can carry one out -- so an install without
-- the switch never accumulates instructions nobody will ever execute.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- The new instruction kind.
DO $$
BEGIN
    ALTER TABLE public.provisioning_instructions
        DROP CONSTRAINT IF EXISTS provisioning_instructions_kind_chk;
    ALTER TABLE public.provisioning_instructions
        ADD CONSTRAINT provisioning_instructions_kind_chk CHECK (
            kind IN ('quarantine', 'unquarantine', 'verify_uptake', 'evict_pods'));
END $$;

-- What the cluster says it can do. An observation, like enforcement_mode.
ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_evict boolean NOT NULL DEFAULT false;
