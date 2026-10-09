-- ============================================================================
-- Forward delta: agent policies (phase 1 of ENFORCEMENT-ARCHITECTURE.md §7).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_agent_policies.sql
--
-- Depends on discovery_agent_registration_lifecycle.sql and governance_provenance.sql.
--
-- WHAT THIS IS
-- The declarative layer above enforcement. An operator attaches a policy to a claimed
-- agent -- or to a selector matching many -- stating the end state they want, and a
-- reconciler works toward it on a timer. Enforcement stops being a button that fires
-- an action and becomes the difference between what a policy says and what is true.
--
-- Deliberately the same shape as birthright_policies, which already established this
-- pattern for humans: a duration, an action on a condition, a justification, an
-- enabled flag, reconciled by a worker rather than triggered by an event.
--
-- THIS DELTA IS INERT ON ITS OWN. It creates tables. The reconciler that reads them
-- ships dry-run only (phase 1), so applying this changes no behaviour.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- agent_policies ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.agent_policies (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',

    -- TARGET. Either one named agent, or a selector the reconciler expands.
    -- The selector is evaluated in the CONTROL PLANE and never reaches the cluster
    -- agent, which only ever receives an explicit fingerprint list -- so a broad
    -- selector can produce a longer list but never a broader predicate.
    discovered_agent_id uuid,
    -- {cluster, namespace, labels, archetype, deployment_origin, framework}
    selector jsonb,

    -- ARM 1: entitlement. Never reaches the cluster.
    -- A CEILING, not a grant. Effective access is the intersection of this and what
    -- was provisioned, so a policy can only ever narrow (PG-5). A policy naming a
    -- scope the agent never held is a no-op on that scope, not a grant of it.
    scope_ceiling   text[],
    role_ceiling_id uuid,

    -- ARM 2: cluster. Every caveat in ENFORCEMENT-ARCHITECTURE.md §3 applies.
    desired_state text NOT NULL DEFAULT 'active',

    -- CLOCK. One or the other, never both -- two clocks make "when does this expire"
    -- ambiguous, and the answer would depend on evaluation order.
    duration   interval,
    expires_at timestamptz,

    -- What happens when the clock runs out. 'revoke' is the default deliberately:
    -- it is today's behaviour (entitlements lapse, workload untouched), so the blast
    -- radius of a mis-set expiry is lost access rather than a deleted workload.
    on_expiry text NOT NULL DEFAULT 'revoke',

    -- PRE-AUTHORIZATION. A destructive on_expiry executes unattended, with no human
    -- present at the deadline. The reason and confirmation are therefore captured
    -- HERE, at authoring time -- the policy is the authorization.
    --
    -- The rejected alternative was raising an approval at expiry, which means the
    -- policy sometimes does nothing: an ignored queue turns "delete in 30 days" into
    -- "runs forever" while the author believes it is handled. Silent non-execution is
    -- the worse failure, because only the blunt one is visible.
    reason       text NOT NULL DEFAULT '',
    confirmed_by uuid,
    confirmed_at timestamptz,

    enabled    boolean NOT NULL DEFAULT true,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_policies_pkey PRIMARY KEY (id),
    CONSTRAINT agent_policies_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_policies_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE CASCADE,
    CONSTRAINT agent_policies_role_fkey FOREIGN KEY (role_ceiling_id)
        REFERENCES public.roles(id) ON DELETE SET NULL,

    -- A target, and exactly one kind of it. Both set would make the policy's scope
    -- ambiguous; neither set would make it apply to nothing while looking active.
    CONSTRAINT agent_policies_target_chk CHECK (
        (discovered_agent_id IS NOT NULL AND selector IS NULL)
     OR (discovered_agent_id IS NULL     AND selector IS NOT NULL)),

    CONSTRAINT agent_policies_desired_chk CHECK (
        desired_state IN ('active', 'quarantined')),
    CONSTRAINT agent_policies_expiry_chk CHECK (
        on_expiry IN ('revoke', 'quarantine', 'evict')),
    CONSTRAINT agent_policies_clock_chk CHECK (
        duration IS NULL OR expires_at IS NULL),

    -- A destructive expiry must be justified AND confirmed. Same pattern as the
    -- standing-grant rule: make the dangerous option the one that costs something.
    CONSTRAINT agent_policies_destructive_chk CHECK (
        on_expiry <> 'evict'
        OR (reason <> '' AND confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)),

    -- A clock that has already been decided must say when. An expiry action with no
    -- expiry is a policy that can never fire, which is worse than being rejected.
    CONSTRAINT agent_policies_actionable_chk CHECK (
        on_expiry = 'revoke' OR duration IS NOT NULL OR expires_at IS NOT NULL),

    CONSTRAINT agent_policies_name_key UNIQUE (workspace_id, name)
);

-- One active DIRECT policy per agent. Selector policies may overlap -- forbidding
-- that is impractical once selectors exist -- and conflicts are resolved by the
-- most-restrictive lattice in the reconciler instead.
CREATE UNIQUE INDEX IF NOT EXISTS agent_policies_one_direct_key
    ON public.agent_policies(workspace_id, discovered_agent_id)
    WHERE enabled AND discovered_agent_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_policies_enabled
    ON public.agent_policies(workspace_id) WHERE enabled;
-- The reconciler's due-work scan, and the lookahead's "what happens this week".
CREATE INDEX IF NOT EXISTS idx_agent_policies_expiring
    ON public.agent_policies(expires_at)
    WHERE enabled AND expires_at IS NOT NULL;

-- agent_policy_confirmations ------------------------------------------------
--
-- What a confirmation was actually bound to.
--
-- A selector policy carrying a destructive on_expiry confirms against the EXPANSION
-- -- these named agents -- never against the selector. One typed confirmation must
-- not authorize the deletion of workloads nobody enumerated, and an agent that starts
-- matching the selector later is not covered by an earlier confirmation.
CREATE TABLE IF NOT EXISTS public.agent_policy_confirmations (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id    uuid NOT NULL,

    -- The agents this confirmation authorizes. Snapshotted rather than recomputed:
    -- "what did you actually confirm" must stay answerable months later, after the
    -- selector's membership has moved on.
    expanded_agent_ids uuid[] NOT NULL,

    on_expiry    text NOT NULL,
    reason       text NOT NULL,
    confirmed_by uuid NOT NULL,
    confirmed_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_policy_confirmations_pkey PRIMARY KEY (id),
    CONSTRAINT agent_policy_confirmations_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_confirmations_policy_fkey FOREIGN KEY (policy_id)
        REFERENCES public.agent_policies(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_confirmations_expiry_chk CHECK (
        on_expiry IN ('revoke', 'quarantine', 'evict')),
    -- A confirmation that authorizes nothing is a UI bug, not a valid record.
    --
    -- cardinality(), NOT array_length(): array_length('{}', 1) returns NULL, and a
    -- CHECK only fails on FALSE -- so the obvious `array_length(...) > 0` evaluates
    -- to NULL for an empty array and lets it straight through. cardinality() returns
    -- 0, which fails as intended.
    CONSTRAINT agent_policy_confirmations_nonempty_chk CHECK (
        cardinality(expanded_agent_ids) > 0)
);

CREATE INDEX IF NOT EXISTS idx_agent_policy_confirmations_policy
    ON public.agent_policy_confirmations(workspace_id, policy_id);

-- agent_policy_actions ------------------------------------------------------
--
-- What the reconciler did, so a scheduled destruction is explicable after the fact.
-- Append-only in practice; nothing updates a row here.
CREATE TABLE IF NOT EXISTS public.agent_policy_actions (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id    uuid,
    discovered_agent_id uuid,

    action text NOT NULL,
    arm    text NOT NULL,
    reason text NOT NULL DEFAULT '',

    -- True for a reconcile that only computed what it would do. Phase 1 ships with
    -- this always true.
    dry_run boolean NOT NULL DEFAULT false,

    outcome text NOT NULL DEFAULT 'applied',
    -- Why, when the outcome is not 'applied' -- e.g. the PodDisruptionBudget that
    -- blocked an eviction, or the scope a policy named that the agent never held.
    detail text NOT NULL DEFAULT '',

    -- Was the operator warned before this happened? NULL for a non-destructive
    -- action. FALSE is a governance exception the console must surface: the action
    -- executed and nobody was told.
    --
    -- A failed warning deliberately does NOT block execution -- blocking would let an
    -- SMTP outage silently no-op every destructive policy, which is the same
    -- silent-non-execution failure the pre-authorization model exists to avoid.
    warning_delivered boolean,

    acted_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_policy_actions_pkey PRIMARY KEY (id),
    CONSTRAINT agent_policy_actions_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- The action outlives the policy. Deleting a policy must not erase the record of
    -- what it did -- that is the audit trail an operator asks for afterwards.
    CONSTRAINT agent_policy_actions_policy_fkey FOREIGN KEY (policy_id)
        REFERENCES public.agent_policies(id) ON DELETE SET NULL,
    CONSTRAINT agent_policy_actions_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,

    CONSTRAINT agent_policy_actions_action_chk CHECK (
        action IN ('narrowed', 'revoked', 'quarantined', 'released', 'evicted', 'noop')),
    CONSTRAINT agent_policy_actions_arm_chk CHECK (arm IN ('entitlement', 'cluster')),
    CONSTRAINT agent_policy_actions_outcome_chk CHECK (
        outcome IN ('applied', 'failed', 'refused', 'planned')),
    -- A non-applied outcome must say why, or the console can only report that
    -- something went wrong.
    CONSTRAINT agent_policy_actions_detail_chk CHECK (
        outcome = 'applied' OR detail <> ''),
    -- A dry run never claims to have applied anything.
    CONSTRAINT agent_policy_actions_dryrun_chk CHECK (
        NOT dry_run OR outcome = 'planned')
);

CREATE INDEX IF NOT EXISTS idx_agent_policy_actions_agent
    ON public.agent_policy_actions(workspace_id, discovered_agent_id, acted_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_policy_actions_policy
    ON public.agent_policy_actions(workspace_id, policy_id, acted_at DESC);
-- A reviewer's queue: destructive actions that executed with no delivered warning.
CREATE INDEX IF NOT EXISTS idx_agent_policy_actions_unwarned
    ON public.agent_policy_actions(workspace_id, acted_at DESC)
    WHERE warning_delivered IS FALSE;

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.agent_policies')              AS policies,
       to_regclass('public.agent_policy_confirmations')  AS confirmations,
       to_regclass('public.agent_policy_actions')        AS actions,
       (SELECT count(*) FROM pg_constraint
         WHERE conrelid = 'public.agent_policies'::regclass AND contype = 'c') AS policy_checks;
