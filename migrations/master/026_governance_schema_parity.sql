-- ============================================================================
-- 026: give EXISTING databases the governance schema that only new ones have.
--
-- The same defect as 023, in a part of the schema 023 did not reach. The
-- enforcement work added six tables and two CHECKs to 001_bootstrap.sql and no
-- numbered migration. A database created from that bootstrap has them.
-- Production was created earlier and never did.
--
-- Found by the Phase 2 migration rehearsal: the production schema, restored
-- into a scratch database, against a fresh 001-025 bootstrap --
--
--     fresh 153 tables, production 148
--
-- -- every table, all 70 columns and both CHECKs that differ traced to
-- 001_bootstrap.sql: the tables to lines 5565-5975, the CHECKs to 5222-5230.
--
-- This is live in production, not latent. The deployed binary registers
--   POST/GET/DELETE /governance/agent-policies, POST .../reconcile
--   GET /actuation/enforcement-plan
-- and every call fails with `relation "agent_policies" does not exist`. The
-- pods start healthy; the failure is at first use -- the worse shape.
--
-- WHAT IS HERE
--
--   * The six tables, their indexes and their inline constraints, copied
--     VERBATIM from 001_bootstrap.sql:5577-5975 rather than rewritten, so an
--     existing database ends up identical to a fresh one and not merely
--     similar. Already IF NOT EXISTS there, so this is a no-op on any
--     database created from the current bootstrap.
--
--   * provisioning_instructions_kind_chk, WIDENED. Production allows only
--     quarantine | unquarantine | verify_uptake; the bootstrap also allows
--     evict_pods | delete_workload | force_delete_pods. So production's
--     DATABASE rejects every eviction, delete and force-delete instruction --
--     the destruction actions cannot be created at all. This one is invisible
--     to a comparison by constraint NAME: both databases have a constraint
--     called provisioning_instructions_kind_chk. Only comparing definitions
--     found it. Widening a CHECK is safe for existing rows: each already
--     satisfied the narrower set.
--
--   * provisioning_instructions_force_chk, ADDED. A force_delete_pods
--     instruction must name who created it and why. Added fully VALID, not
--     NOT VALID, because production's narrow kind_chk above is VALIDATED --
--     every existing row is quarantine, unquarantine or verify_uptake -- so no
--     force_delete_pods row can exist there, and every existing row already
--     satisfies this check. Order within this file does not matter: it is one
--     transaction, holding the table's lock throughout.
--
-- WHY THIS KEEPS HAPPENING, AGAIN. 023's header named the cause and the
-- remedy -- compare a restored production schema against a fresh bootstrap
-- before every release -- and that comparison is what found this. Two
-- occurrences of one mistake is the argument for making it a CI gate, not a
-- habit someone has to remember.
-- ============================================================================

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


-- ===========================================================================
-- enforcement_plans -- the document the in-cluster agent polls.
--
-- The control plane originates no connection into a customer cluster (EN-0), so a
-- quarantine decision reaches the cluster exactly one way: the agent asks on its
-- actuation interval and is handed a WHOLE plan. Whole, not a delta -- a missed
-- delta silently un-enforces, whereas a whole plan is self-correcting on the next
-- poll. The list is an explicit set of fingerprints (EN-3), never a predicate, so a
-- detection bug can lengthen the list but can never widen what the agent evaluates.
--
-- Persisted rather than computed and discarded because the question asked after a
-- workload was blocked is "what were we enforcing at the time", which today's state
-- cannot answer.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.enforcement_plans (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    -- WHICH CLUSTER. Per-connector, so one cluster's plan can never contain
    -- another's fingerprints -- what bounds a leaked actuation token to the cluster
    -- it was minted for.
    discovery_source_id uuid NOT NULL,

    -- Monotonic per connector. The agent reports the version it is enforcing; the
    -- difference between that and this IS the enforcement gap.
    version bigint NOT NULL,

    -- The document that was served. jsonb rather than json so it stays QUERYABLE
    -- -- "which clusters were ever told to contain this fingerprint" is one scan
    -- -- at the cost of normalised key order, which no reader depends on.
    plan jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Content hash over the deny list. A poll that finds the plan unchanged mints
    -- NO row: version is bumped by content, not by traffic, or a 30-second poll
    -- would write 2,880 identical rows a day and the version number would stop
    -- meaning "something changed".
    content_hash text NOT NULL DEFAULT '',

    generated_at timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT enforcement_plans_pkey PRIMARY KEY (id),
    CONSTRAINT enforcement_plans_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT enforcement_plans_source_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE CASCADE,
    -- Monotonicity is enforced HERE, not in application code. Two agent replicas
    -- polling in the same instant both compute version N+1; one insert wins and the
    -- loser re-reads. Without this the two would publish divergent plans under one
    -- version number, and the version would stop identifying a document.
    CONSTRAINT enforcement_plans_version_key UNIQUE (discovery_source_id, version),
    CONSTRAINT enforcement_plans_version_chk CHECK (version > 0)
);

CREATE INDEX IF NOT EXISTS idx_enforcement_plans_latest
    ON public.enforcement_plans(discovery_source_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_enforcement_plans_workspace
    ON public.enforcement_plans(workspace_id, generated_at DESC);


-- ===========================================================================
-- governance_notification_settings + agent_policy_warnings
--
-- §3A.4 requires that a destructive deadline is warned about BEFORE it fires.
-- This is the durable side of that: a row per (policy, agent, deadline, channel,
-- recipient), scheduled at deadline-minus-lead, retried on failure, and sent once
-- across replicas.
--
-- A FAILED WARNING NEVER BLOCKS THE ACTION. Blocking would mean an SMTP outage
-- silently turns every destructive policy into a no-op -- exactly the
-- silent-non-execution failure §3A.4 exists to prevent. The failure is recorded
-- instead: a destructive action that ran without a delivered warning is a
-- governance exception (agent_policy_actions.warning_delivered = false), which is
-- an auditable finding rather than a swallowed error.
--
-- The LOOKAHEAD (GET /governance/policies/upcoming) remains the system of record.
-- It is a pull, so it has no delivery to fail. Everything here is escalation on
-- top of it.
--
-- WHY NOT iga_durable_jobs, WHICH ALREADY LOOKS LIKE THIS QUEUE
-- Two structural reasons. Its integration_id is NOT NULL with an FK to
-- iga_integrations, and a policy warning belongs to a policy rather than to a
-- connected IGA system -- so every row would need a synthetic integration, and
-- removing an unrelated integration would cascade warnings away. And nothing
-- drains it: IGAManager.RunWorkerOnce is called from no running process. This
-- reuses the pattern (available_at, a dedupe key, attempt_count, FOR UPDATE SKIP
-- LOCKED) without borrowing a table that cannot hold the row.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.governance_notification_settings (
    workspace_id uuid PRIMARY KEY,

    -- How far ahead of a destructive deadline to warn. Seven days: long enough to
    -- act on during a normal working week, including a weekend.
    warning_lead interval NOT NULL DEFAULT '7 days',

    -- OPTIONAL second channel, so customers reach Slack or PagerDuty without us
    -- integrating each one. OUTBOUND, so it costs nothing against EN-0: the control
    -- plane calling a customer's Slack is not the control plane calling into a
    -- customer's cluster.
    webhook_url    text NOT NULL DEFAULT '',
    webhook_secret text NOT NULL DEFAULT '',
    email_enabled  boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT gov_notif_settings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- A lead of zero would "warn" at the instant of destruction, which is not a
    -- warning. The upper bound stops a typo scheduling one years out, where it
    -- would sit pending and look like the system had gone quiet.
    CONSTRAINT gov_notif_settings_lead_chk CHECK (
        warning_lead >= interval '1 hour' AND warning_lead <= interval '90 days'),
    -- https only. A warning naming which workload is about to be deleted is a map
    -- of what to attack during the window in which nobody is watching it.
    CONSTRAINT gov_notif_settings_webhook_chk CHECK (
        webhook_url = '' OR webhook_url LIKE 'https://%')
);

CREATE TABLE IF NOT EXISTS public.agent_policy_warnings (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id    uuid NOT NULL,

    -- A warning names ONE agent, not a policy: "three of your agents will be
    -- deleted" is a summary, and the person who has to act needs to know which one
    -- is theirs.
    discovered_agent_id uuid NOT NULL,

    -- The deadline being warned about, and part of the dedupe key -- so moving a
    -- policy's expiry schedules a FRESH warning instead of reusing a sent one.
    -- Keyed on policy alone, an operator who pushed a deletion out by a month would
    -- never be warned again, because a warning had already gone out for a deadline
    -- that no longer exists.
    deadline timestamptz NOT NULL,
    -- Snapshotted, not read from the policy at send time: the warning has to
    -- describe what was scheduled when it was scheduled.
    on_expiry text NOT NULL,

    channel   text NOT NULL,
    -- The address actually used, so "who was told" is answerable later. In the
    -- dedupe key, so adding a recipient warns THEM without re-warning everyone who
    -- already knew.
    recipient      text NOT NULL,
    recipient_role text NOT NULL DEFAULT '',

    available_at  timestamptz NOT NULL,
    state         text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    last_error    text NOT NULL DEFAULT '',
    sent_at       timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_policy_warnings_pkey PRIMARY KEY (id),
    CONSTRAINT agent_policy_warnings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_warnings_policy_fkey FOREIGN KEY (policy_id)
        REFERENCES public.agent_policies(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_warnings_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_warnings_channel_chk CHECK (channel IN ('email', 'webhook')),
    CONSTRAINT agent_policy_warnings_state_chk CHECK (
        state IN ('pending', 'sent', 'failed', 'dead')),
    -- 'sent' must carry its timestamp, or "was this warned about" degrades to a
    -- boolean with no time attached and cannot be compared against the deadline.
    CONSTRAINT agent_policy_warnings_sent_chk CHECK (
        (state = 'sent') = (sent_at IS NOT NULL)),
    -- Fires ONCE. Two replicas scheduling in the same tick collide here rather than
    -- double-mailing an operator about the deletion of their workload.
    CONSTRAINT agent_policy_warnings_dedupe_key UNIQUE (
        policy_id, discovered_agent_id, deadline, channel, recipient)
);

-- The delivery worker's claim path: due, not yet sent, oldest first.
CREATE INDEX IF NOT EXISTS idx_agent_policy_warnings_due
    ON public.agent_policy_warnings(available_at)
    WHERE state IN ('pending', 'failed');

-- "Was this action warned about?" -- read by the reconciler when it records a
-- destructive action, and by the console when it lists governance exceptions.
CREATE INDEX IF NOT EXISTS idx_agent_policy_warnings_lookup
    ON public.agent_policy_warnings(workspace_id, discovered_agent_id, deadline);



-- provisioning_instructions_kind_chk -----------------------------------------
-- DROP + ADD rather than a guarded ADD: the constraint exists in both kinds of
-- database, with different definitions, and the wider one must win in both.
-- On a database already created from the current bootstrap this re-adds the
-- identical definition -- a no-op in effect.
ALTER TABLE public.provisioning_instructions
    DROP CONSTRAINT IF EXISTS provisioning_instructions_kind_chk;
ALTER TABLE public.provisioning_instructions
    ADD CONSTRAINT provisioning_instructions_kind_chk CHECK (
        kind IN ('quarantine', 'unquarantine', 'verify_uptake',
                 'evict_pods', 'delete_workload', 'force_delete_pods'));

-- provisioning_instructions_force_chk ----------------------------------------
-- Guarded, because a database created from the current bootstrap already has
-- it inline and ADD CONSTRAINT would fail on the duplicate name. VALID: see
-- the header for why no existing row can violate it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.provisioning_instructions'::regclass
           AND conname  = 'provisioning_instructions_force_chk'
    ) THEN
        ALTER TABLE public.provisioning_instructions
            ADD CONSTRAINT provisioning_instructions_force_chk CHECK (
                kind <> 'force_delete_pods'
                OR (created_by <> '' AND coalesce(payload->>'reason', '') <> ''));
    END IF;
END $$;

-- verify ---------------------------------------------------------------------
-- An assertion, not a report: if any of these is still missing the migration
-- fails and rolls back, rather than recording itself as applied.
DO $$
DECLARE missing text;
BEGIN
    SELECT string_agg(t, ', ') INTO missing
      FROM unnest(ARRAY['agent_policies', 'agent_policy_actions',
                        'agent_policy_confirmations', 'agent_policy_warnings',
                        'enforcement_plans', 'governance_notification_settings']) AS t
     WHERE to_regclass('public.' || t) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION '026: governance tables still missing: %', missing;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'provisioning_instructions_force_chk'
                      AND convalidated) THEN
        RAISE EXCEPTION '026: provisioning_instructions_force_chk missing or not validated';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'provisioning_instructions_kind_chk'
                      AND pg_get_constraintdef(oid) LIKE '%force_delete_pods%') THEN
        RAISE EXCEPTION '026: provisioning_instructions_kind_chk does not admit the destruction kinds';
    END IF;
END $$;
