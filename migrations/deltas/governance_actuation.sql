-- ============================================================================
-- Forward delta: in-cluster actuation.
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_actuation.sql
--
-- Phase 5 of PROVISIONING-GOVERNANCE-ARCHITECTURE.md §11. Depends on the discovery
-- lifecycle delta (discovery_sources) and governance_provenance.sql.
--
-- WHAT THIS IS FOR, AND WHAT IT IS NOT FOR
-- Phase 5 was originally scoped around delivering credentials into the cluster. That
-- turned out to be unnecessary: AuthSec's workload identity model is SECRETLESS. A
-- workload authenticates with a `spiffe-svid` client assertion using an SVID it already
-- holds -- see applications_machine_access_controller.go, "a confidential OAuth client
-- with spiffe-svid auth (no secret needed)". Governance grants access to an identity the
-- workload already has; nothing has to be shipped to it. Building credential delivery
-- would have been building the wrong thing well.
--
-- What DOES require in-cluster action:
--
--   quarantine / unquarantine -- ADR-9 says an admin quarantining an agent triggers an
--     enforcement-tier network deny. Today `discovered_agents.status='quarantined'` is
--     purely advisory: nothing in the codebase enforces it. This makes it real.
--
--   verify_uptake -- confirm the workload actually runs as the ServiceAccount
--     provisioning bound its entitlements to. If a pod really runs as `default` while
--     the grant is anchored to `system:serviceaccount:ns:agent-sa`, the entitlement is
--     attached to an identity the workload does not have, and everything downstream is
--     quietly wrong.
--
-- SECURITY POSTURE
-- Because no secret material crosses this channel, the threat is not interception --
-- it is a forged UNQUARANTINE lifting a deny policy, which fails OPEN. That is why the
-- endpoints are authenticated with a per-connector token even though the payloads are
-- not sensitive to read. A forged quarantine, by contrast, fails safe: it denies.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- The actuation credential ---------------------------------------------------
--
-- Only a HASH is stored: a leaked database backup must not yield a working actuation
-- credential. The token itself identifies which connector is calling, so the agent
-- never asserts its own cluster -- removing the "agent claims to be a different
-- cluster" case entirely.
ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS actuation_token_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS actuation_enabled_at timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS discovery_sources_actuation_token_key
    ON public.discovery_sources(actuation_token_hash)
    WHERE actuation_token_hash <> '';

-- provisioning_instructions -------------------------------------------------
--
-- A pull-based work queue, one row per cluster-side action. Pull rather than push
-- because the control plane cannot reach into a customer's cluster, and should not want
-- to: an inbound connection is a hole in their network, an outbound poll is not.
--
-- LEASES, NOT LOCKS. An agent claims work with a time-bounded lease. If it crashes
-- mid-apply the lease expires and the instruction returns to pending, so work is never
-- silently lost -- at the cost of a possible re-apply, which is why every instruction
-- kind must be idempotent.
CREATE TABLE IF NOT EXISTS public.provisioning_instructions (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    -- Which cluster is responsible. NOT NULL: an instruction nobody owns is one nobody
    -- applies, and silently queuing work for a cluster that has no agent is worse than
    -- refusing to queue it.
    discovery_source_id uuid NOT NULL,

    kind    text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- What this instruction is about, for the console and for dedupe.
    discovered_agent_id uuid,
    fingerprint         text NOT NULL DEFAULT '',

    -- Collapses a re-issued instruction onto the existing row rather than queuing the
    -- same action twice. Quarantining an already-quarantined agent should be a no-op,
    -- not a second NetworkPolicy write.
    idempotency_key text NOT NULL,

    status   text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,

    lease_expires_at timestamptz,
    leased_by        text NOT NULL DEFAULT '',
    applied_at       timestamptz,
    -- What the agent reported. For verify_uptake this is the ANSWER, not just an
    -- acknowledgement, which is why it is structured rather than a status flag.
    result jsonb,
    error  text NOT NULL DEFAULT '',

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT provisioning_instructions_pkey PRIMARY KEY (id),
    CONSTRAINT provisioning_instructions_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT provisioning_instructions_source_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE CASCADE,
    CONSTRAINT provisioning_instructions_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,
    CONSTRAINT provisioning_instructions_kind_chk CHECK (
        kind IN ('quarantine', 'unquarantine', 'verify_uptake')),
    CONSTRAINT provisioning_instructions_status_chk CHECK (
        status IN ('pending', 'leased', 'applied', 'failed')),
    -- A terminal instruction must say when it finished. An applied row with no
    -- timestamp cannot be reasoned about later.
    CONSTRAINT provisioning_instructions_terminal_chk CHECK (
        status NOT IN ('applied', 'failed') OR applied_at IS NOT NULL),
    -- A failure must say why, or the console can only report that something went wrong.
    CONSTRAINT provisioning_instructions_failure_chk CHECK (
        status <> 'failed' OR error <> '')
);

-- One OPEN instruction per idempotency key. Partial, so the history of completed
-- instructions is unconstrained and an agent can be quarantined, released, and
-- quarantined again.
CREATE UNIQUE INDEX IF NOT EXISTS provisioning_instructions_open_key
    ON public.provisioning_instructions(discovery_source_id, idempotency_key)
    WHERE status IN ('pending', 'leased');

-- The agent's poll: pending work for my cluster, oldest first.
CREATE INDEX IF NOT EXISTS idx_provisioning_instructions_queue
    ON public.provisioning_instructions(discovery_source_id, status, created_at);
-- The lease reaper.
CREATE INDEX IF NOT EXISTS idx_provisioning_instructions_leases
    ON public.provisioning_instructions(lease_expires_at)
    WHERE status = 'leased';
CREATE INDEX IF NOT EXISTS idx_provisioning_instructions_agent
    ON public.provisioning_instructions(discovered_agent_id)
    WHERE discovered_agent_id IS NOT NULL;

-- Quarantine enforcement state on the agent itself --------------------------
--
-- Separate from `status='quarantined'`, which is the DECISION. This records whether the
-- decision has actually been enforced in the cluster -- the same
-- decision-versus-observation split as status vs runtime_status. An admin needs to
-- know the difference between "I quarantined it" and "it is actually blocked".
ALTER TABLE public.discovered_agents
    ADD COLUMN IF NOT EXISTS quarantine_enforced_at timestamptz,
    ADD COLUMN IF NOT EXISTS quarantine_enforcement_error text NOT NULL DEFAULT '',
    -- The workload identity actually observed in the cluster, from verify_uptake. When
    -- this disagrees with the provisioned anchor, the entitlement is bound to an
    -- identity the workload does not have.
    ADD COLUMN IF NOT EXISTS observed_service_account text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS identity_verified_at timestamptz;

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.provisioning_instructions') AS instructions_table,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'discovery_sources'
           AND column_name IN ('actuation_token_hash','actuation_enabled_at')) AS source_cols,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'discovered_agents'
           AND column_name IN ('quarantine_enforced_at','quarantine_enforcement_error',
                               'observed_service_account','identity_verified_at')) AS agent_cols;
