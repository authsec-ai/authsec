-- 004_agentic_iga.sql
--
-- Adds the Agentic IGA canonical model and evidence layer to an
-- ALREADY-BOOTSTRAPPED database. 001_bootstrap.sql carries the same
-- definitions for fresh installs; the two must stay in agreement.
--
-- Applied automatically at boot by internal/migration/runner.go and recorded in
-- migration_logs. Every statement is IF NOT EXISTS / ON CONFLICT DO NOTHING, so
-- it is a no-op where these tables already exist.
--
-- Requires PostgreSQL 15 or newer: the composite foreign keys use the
-- column-list form of ON DELETE SET NULL, which is the only way to null a
-- pointer without also nulling the NOT NULL workspace_id that makes the key
-- workspace-safe.

-- =========================================================================
-- Agentic IGA — canonical model and evidence layer
-- =========================================================================
-- Implements the persistence contract in the GitHub Discovery Integration
-- specification (section 11.4). The GitHub Integration is the first consumer,
-- but nothing below is GitHub-specific: provider payloads live only in
-- iga_source_objects / iga_observations, never in a canonical table.
--
-- NAMING. The specification assumes an isolated IGA database, where these
-- tables would simply be called integrations, agents, observations and so on.
-- This deployment shares the AuthSec database, where `credentials` already
-- exists (WebAuthn) and `agents` / `resources` / `observations` are generic
-- enough to collide later. Every table is therefore prefixed `iga_`. Semantics
-- are unchanged; only the physical names differ.
--
-- THE CENTRAL IDEA. Evidence is preserved before it is interpreted:
--
--   source object  ->  observation  ->  candidate  ->  canonical object
--   (what GitHub     (a versioned     (a proposal    (agent, identity,
--    showed us)       fact + its       a human or     resource, edge)
--                     provenance)      rule makes)
--
-- Canonical rows never replace observations; iga_observation_links records
-- which observations support, contradict or previously supported each value.
-- That is what lets every displayed fact be drilled back to its evidence, and
-- what keeps "we did not look" distinct from "there is nothing there."
--
-- INVARIANTS ENFORCED IN THE DATABASE (spec 11.4.1):
--   * every tenant-owned row carries workspace_id NOT NULL
--   * every foreign key between tenant-owned tables is COMPOSITE and carries
--     workspace_id, so an object id from workspace A cannot bind to a row in
--     workspace B even if the id is valid
--   * a verified provider installation has exactly one active owner, enforced
--     by a uniqueness constraint that deliberately EXCLUDES workspace_id
--   * no secret material: only secret_ref plus non-secret key metadata
--   * coverage is stored per scope and object class and is never averaged
-- =========================================================================

-- ------------------------------------------------------------------ --
-- 1. Integration control plane                                        --
-- ------------------------------------------------------------------ --

-- iga_integrations — one verified binding between an AuthSec workspace and a
-- provider installation. requested_permissions and granted_permissions are
-- stored separately and never merged: the difference between what we asked for
-- and what we actually got is the honest basis for every coverage claim.
CREATE TABLE IF NOT EXISTS public.iga_integrations (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    provider              text NOT NULL,
    -- provider_host distinguishes github.com from a GHES hostname; it is part
    -- of the installation's global identity.
    provider_host         text NOT NULL,
    -- The AuthSec-side App registration this installation belongs to.
    app_registration_id   text NOT NULL,
    installation_id       text,
    account_native_id     text,
    capability_profile    jsonb NOT NULL DEFAULT '{}'::jsonb,
    requested_permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
    granted_permissions   jsonb NOT NULL DEFAULT '{}'::jsonb,
    status                text NOT NULL DEFAULT 'pending',
    -- Pointer into the approved secrets store. The App private key and any
    -- token material never touch this database.
    secret_ref            text NOT NULL DEFAULT '',
    -- NULL until the installation has been proven to belong to the
    -- authenticated provider administrator. A setup-URL installation_id is
    -- attacker-controllable, so it is untrusted until this is set.
    verified_at           timestamptz,
    -- One-time state for the install/authorize round trip. It is what ties the
    -- provider's callback back to the request WE started, so a callback that
    -- did not originate here cannot activate an integration.
    authorization_state      text,
    authorization_expires_at timestamptz,
    version               bigint NOT NULL DEFAULT 1,
    created_by            text NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_integrations_pkey PRIMARY KEY (id),
    CONSTRAINT iga_integrations_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_integrations_status_chk CHECK (
        status IN ('pending', 'active', 'degraded', 'disconnected', 'revoked')),
    -- Composite-FK target: children reference (workspace_id, id) as a pair.
    CONSTRAINT iga_integrations_workspace_id_key UNIQUE (workspace_id, id)
);

-- The cross-workspace rebinding guard. workspace_id is deliberately ABSENT
-- from this index: that is the entire point. Two workspaces cannot both hold a
-- verified binding to the same provider installation, so an installation
-- cannot be silently moved or duplicated into another tenant. Partial on
-- verified_at so abandoned half-finished authorizations do not block a retry.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_integrations_verified_installation
    ON public.iga_integrations (provider_host, app_registration_id, installation_id)
    WHERE verified_at IS NOT NULL AND installation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_iga_integrations_workspace_status
    ON public.iga_integrations (workspace_id, status);

-- The state must be globally unique and single-use: the callback arrives
-- unauthenticated, so the state is the only thing proving provenance.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_integrations_auth_state
    ON public.iga_integrations (authorization_state)
    WHERE authorization_state IS NOT NULL;

-- iga_integration_scopes — the estate the customer actually selected. A scope
-- stays on the books even when excluded or denied, because "you did not select
-- this" and "we could not read this" are different answers and neither is zero.
CREATE TABLE IF NOT EXISTS public.iga_integration_scopes (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    integration_id        uuid NOT NULL,
    estate_scope_id       uuid,
    native_scope_kind     text NOT NULL,
    native_scope_id       text NOT NULL,
    selection_state       text NOT NULL DEFAULT 'selected',
    filters               jsonb NOT NULL DEFAULT '{}'::jsonb,
    effective_permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_integration_scopes_pkey PRIMARY KEY (id),
    CONSTRAINT iga_integration_scopes_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_integration_scopes_selection_chk CHECK (
        selection_state IN ('selected', 'excluded', 'denied', 'unknown')),
    CONSTRAINT iga_integration_scopes_native_key
        UNIQUE (workspace_id, integration_id, native_scope_kind, native_scope_id),
    CONSTRAINT iga_integration_scopes_workspace_id_key UNIQUE (workspace_id, id)
);

-- ------------------------------------------------------------------ --
-- 2. Scans, coverage and durable ingress                              --
-- ------------------------------------------------------------------ --

-- iga_scan_runs — one enumeration attempt. A generation becomes authoritative
-- ONLY on successful completion (see the CHECK): an interrupted scan must
-- never be allowed to prove that something was deleted.
CREATE TABLE IF NOT EXISTS public.iga_scan_runs (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    integration_id      uuid NOT NULL,
    mode                text NOT NULL,
    generation          bigint NOT NULL,
    status              text NOT NULL DEFAULT 'pending',
    requested_by        text NOT NULL DEFAULT '',
    normalizer_version  text NOT NULL DEFAULT '',
    rule_catalog_version text NOT NULL DEFAULT '',
    started_at          timestamptz,
    completed_at        timestamptz,
    counters            jsonb NOT NULL DEFAULT '{}'::jsonb,
    failure_code        text NOT NULL DEFAULT '',
    -- Set in the same transaction that publishes coverage; see 11.4.4.
    is_authoritative    boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_scan_runs_pkey PRIMARY KEY (id),
    CONSTRAINT iga_scan_runs_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_scan_runs_mode_chk CHECK (mode IN ('full', 'incremental', 'targeted')),
    CONSTRAINT iga_scan_runs_status_chk CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    -- The deletion-safety rule, expressed as a constraint rather than a
    -- convention: only a succeeded run may be authoritative.
    CONSTRAINT iga_scan_runs_authoritative_chk CHECK (
        is_authoritative = false OR status = 'succeeded'),
    CONSTRAINT iga_scan_runs_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_scan_runs_workspace_integration
    ON public.iga_scan_runs (workspace_id, integration_id, created_at DESC);

-- iga_scan_checkpoints — resumable cursors. A worker that dies mid-scan leaves
-- a reclaimable lease and a cursor to resume from, so a restart never rescans
-- from zero and never silently skips a partition.
CREATE TABLE IF NOT EXISTS public.iga_scan_checkpoints (
    workspace_id  uuid NOT NULL,
    scan_run_id   uuid NOT NULL,
    object_class  text NOT NULL,
    partition_key text NOT NULL,
    cursor        text NOT NULL DEFAULT '',
    watermark     timestamptz,
    lease_owner   text,
    leased_until  timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_scan_checkpoints_pkey
        PRIMARY KEY (workspace_id, scan_run_id, object_class, partition_key),
    CONSTRAINT iga_scan_checkpoints_run_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id) ON DELETE CASCADE
);

-- iga_coverage_states — what could actually be inspected, per scope and per
-- object class. Deliberately has NO percentage column: averaging these states
-- into one reassuring number is the exact failure this table exists to prevent.
-- 'unknown' must never render as zero.
CREATE TABLE IF NOT EXISTS public.iga_coverage_states (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    integration_id        uuid NOT NULL,
    integration_scope_id  uuid NOT NULL,
    object_class          text NOT NULL,
    state                 text NOT NULL DEFAULT 'unknown',
    reason_code           text NOT NULL DEFAULT '',
    last_success_at       timestamptz,
    last_attempt_at       timestamptz,
    watermark             timestamptz,
    inspected_count       bigint NOT NULL DEFAULT 0,
    denied_count          bigint NOT NULL DEFAULT 0,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_coverage_states_pkey PRIMARY KEY (id),
    CONSTRAINT iga_coverage_states_scope_fkey
        FOREIGN KEY (workspace_id, integration_scope_id)
        REFERENCES public.iga_integration_scopes (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_coverage_states_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_coverage_states_state_chk CHECK (state IN (
        'complete_for_selected_scope',
        'partial',
        'unknown',
        'not_configured',
        'unsupported',
        'failed',
        'stale')),
    CONSTRAINT iga_coverage_states_key
        UNIQUE (workspace_id, integration_id, integration_scope_id, object_class)
);

CREATE INDEX IF NOT EXISTS idx_iga_coverage_states_workspace_class
    ON public.iga_coverage_states (workspace_id, object_class, state);

-- iga_webhook_deliveries — the provider ingress ledger.
--
-- workspace_id is NULLABLE here, unlike every other IGA table, and the reason
-- matters: a delivery is recorded at the moment it arrives, BEFORE the
-- App/installation binding has been resolved server-side. The payload's own
-- installation_id is never sufficient to establish a workspace, so there is
-- genuinely nothing trustworthy to write until resolution succeeds. It is
-- backfilled once the binding is known.
--
-- Uniqueness is (app_registration_id, delivery_id): redelivery of the same
-- event returns the previously committed acceptance and produces no second
-- canonical effect.
CREATE TABLE IF NOT EXISTS public.iga_webhook_deliveries (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    app_registration_id   text NOT NULL,
    delivery_id           text NOT NULL,
    workspace_id          uuid,
    integration_id        uuid,
    event_type            text NOT NULL DEFAULT '',
    action                text NOT NULL DEFAULT '',
    body_hash             text NOT NULL DEFAULT '',
    received_at           timestamptz NOT NULL DEFAULT now(),
    -- NULL means the signature was not verified. No parsed work may derive
    -- from such a row.
    signature_validated_at timestamptz,
    state                 text NOT NULL DEFAULT 'received',
    CONSTRAINT iga_webhook_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT iga_webhook_deliveries_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_webhook_deliveries_state_chk CHECK (
        state IN ('received', 'rejected_signature', 'rejected_binding', 'accepted', 'processed')),
    -- Accepted implies both a verified signature and a resolved workspace.
    CONSTRAINT iga_webhook_deliveries_accepted_chk CHECK (
        state NOT IN ('accepted', 'processed')
        OR (signature_validated_at IS NOT NULL AND workspace_id IS NOT NULL)),
    CONSTRAINT iga_webhook_deliveries_key UNIQUE (app_registration_id, delivery_id)
);

-- iga_durable_jobs — work accepted but not yet done. The webhook route commits
-- a delivery row and a job row in ONE transaction and only then returns 2xx;
-- acknowledging first would lose the event if the process died in between.
CREATE TABLE IF NOT EXISTS public.iga_durable_jobs (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    integration_id uuid NOT NULL,
    job_kind       text NOT NULL,
    dedupe_key     text NOT NULL,
    payload_ref    text NOT NULL DEFAULT '',
    state          text NOT NULL DEFAULT 'ready',
    available_at   timestamptz NOT NULL DEFAULT now(),
    lease_owner    text,
    leased_until   timestamptz,
    attempt_count  integer NOT NULL DEFAULT 0,
    last_error     text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_durable_jobs_pkey PRIMARY KEY (id),
    CONSTRAINT iga_durable_jobs_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_durable_jobs_state_chk CHECK (
        state IN ('ready', 'leased', 'done', 'failed', 'dead')),
    CONSTRAINT iga_durable_jobs_dedupe_key UNIQUE (workspace_id, integration_id, dedupe_key)
);

-- Worker claim path: find ready work whose time has come, oldest first.
CREATE INDEX IF NOT EXISTS idx_iga_durable_jobs_claimable
    ON public.iga_durable_jobs (workspace_id, state, available_at);

-- ------------------------------------------------------------------ --
-- 3. Append-preserving source evidence                                --
-- ------------------------------------------------------------------ --

-- iga_source_objects — what the provider showed us, keyed by a recognition key
-- built from immutable provider identifiers. The locator (owner/name/path) is
-- descriptive only: a repository rename or a file move changes the locator and
-- must NOT create a new object or silently merge two.
--
-- lifecycle is 'tombstoned' only after an authoritative enumeration of the
-- parent scope proved absence. A single 404 means nothing: it could be a
-- deletion, a permission loss, a transfer, or transient inconsistency.
CREATE TABLE IF NOT EXISTS public.iga_source_objects (
    id                 uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL,
    integration_id     uuid NOT NULL,
    object_type        text NOT NULL,
    recognition_key    text NOT NULL,
    native_id          text NOT NULL DEFAULT '',
    locator            jsonb NOT NULL DEFAULT '{}'::jsonb,
    normalized_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Hash of the raw body we parsed. The body itself is deliberately not kept.
    raw_hash           text NOT NULL DEFAULT '',
    source_version     text NOT NULL DEFAULT '',
    -- Deletion of provider payload is scoped by (workspace, integration,
    -- source_subject_key) while governed history survives.
    source_subject_key text NOT NULL DEFAULT '',
    scan_generation    bigint,
    lifecycle          text NOT NULL DEFAULT 'active',
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    tombstoned_at      timestamptz,
    CONSTRAINT iga_source_objects_pkey PRIMARY KEY (id),
    CONSTRAINT iga_source_objects_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_source_objects_lifecycle_chk CHECK (
        lifecycle IN ('active', 'tombstoned', 'redacted')),
    CONSTRAINT iga_source_objects_tombstone_chk CHECK (
        lifecycle <> 'tombstoned' OR tombstoned_at IS NOT NULL),
    CONSTRAINT iga_source_objects_recognition_key
        UNIQUE (workspace_id, integration_id, object_type, recognition_key),
    CONSTRAINT iga_source_objects_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_source_objects_workspace_type
    ON public.iga_source_objects (workspace_id, object_type, lifecycle);
CREATE INDEX IF NOT EXISTS idx_iga_source_objects_subject
    ON public.iga_source_objects (workspace_id, integration_id, source_subject_key);

-- iga_observations — versioned facts with provenance. APPEND-PRESERVING: a
-- later scan adds a new row, it does not rewrite an earlier one. That is what
-- makes contradiction visible instead of silently overwritten, and what lets a
-- canonical value name the exact evidence behind it.
--
-- Idempotent by dedupe_key, so a redelivered webhook or a re-run scan segment
-- cannot double-count.
CREATE TABLE IF NOT EXISTS public.iga_observations (
    id                 uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL,
    source_object_id   uuid NOT NULL,
    -- Exactly one provenance anchor: a scan or a webhook delivery.
    scan_run_id        uuid,
    delivery_id        uuid,
    -- Evidence mode, in descending semantic strength. This is the ceiling on
    -- what a rule may conclude: a dependency or a secret name can never on its
    -- own produce a confirmed agent.
    mode               text NOT NULL,
    fact_payload       jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_ref       text NOT NULL DEFAULT '',
    observed_at        timestamptz NOT NULL,
    ingested_at        timestamptz NOT NULL DEFAULT now(),
    normalizer_version text NOT NULL DEFAULT '',
    rule_id            text NOT NULL DEFAULT '',
    rule_version       text NOT NULL DEFAULT '',
    dedupe_key         text NOT NULL,
    CONSTRAINT iga_observations_pkey PRIMARY KEY (id),
    CONSTRAINT iga_observations_source_object_fkey
        FOREIGN KEY (workspace_id, source_object_id)
        REFERENCES public.iga_source_objects (workspace_id, id) ON DELETE CASCADE,
    -- CASCADE, not SET NULL. An observation is the OUTPUT of the scan or
    -- delivery that produced it, and iga_observations_provenance_chk below
    -- requires one of them to be present. Nulling the anchor would leave a fact
    -- that cannot be explained -- and would break the check on the very delete
    -- that caused it. Pruning a scan therefore prunes its observations; the
    -- source object and the curated governance history both survive separately.
    CONSTRAINT iga_observations_scan_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observations_delivery_fkey FOREIGN KEY (delivery_id)
        REFERENCES public.iga_webhook_deliveries (id) ON DELETE CASCADE,
    CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
        'platform_declared',
        'deployment_declared',
        'invocation_declared',
        'framework_dependency',
        'tool_configuration',
        'secret_reference',
        'identity_grant',
        'audit_event')),
    -- An observation with no provenance anchor is not evidence.
    CONSTRAINT iga_observations_provenance_chk CHECK (
        scan_run_id IS NOT NULL OR delivery_id IS NOT NULL),
    CONSTRAINT iga_observations_dedupe_key UNIQUE (workspace_id, dedupe_key),
    CONSTRAINT iga_observations_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_observations_source_time
    ON public.iga_observations (workspace_id, source_object_id, observed_at DESC);

-- iga_classification_candidates — a proposal that some source object is an
-- agent (or another canonical kind). Nothing is promoted silently: a candidate
-- carries the rule that produced it and waits for a decision. The partial
-- unique index allows exactly one PENDING proposal per signature while keeping
-- the full history of decided ones.
CREATE TABLE IF NOT EXISTS public.iga_classification_candidates (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    source_object_id    uuid NOT NULL,
    proposed_object_kind text NOT NULL,
    proposal_signature  text NOT NULL,
    rule_id             text NOT NULL DEFAULT '',
    rule_version        text NOT NULL DEFAULT '',
    evidence_mode       text NOT NULL DEFAULT '',
    state               text NOT NULL DEFAULT 'pending',
    decided_by          text,
    decided_at          timestamptz,
    reason              text NOT NULL DEFAULT '',
    version             bigint NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_classification_candidates_pkey PRIMARY KEY (id),
    CONSTRAINT iga_classification_candidates_source_fkey
        FOREIGN KEY (workspace_id, source_object_id)
        REFERENCES public.iga_source_objects (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_classification_candidates_state_chk CHECK (
        state IN ('pending', 'confirmed', 'rejected', 'insufficient_evidence', 'superseded')),
    CONSTRAINT iga_classification_candidates_decided_chk CHECK (
        state = 'pending' OR decided_at IS NOT NULL),
    CONSTRAINT iga_classification_candidates_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_classification_candidates_active
    ON public.iga_classification_candidates (workspace_id, proposal_signature)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_iga_classification_candidates_state
    ON public.iga_classification_candidates (workspace_id, state);

-- iga_correlations — the reversible mapping from a source object to a canonical
-- object. Weak joins (name, path, label similarity) stay proposals forever
-- unless a human accepts them. A split flips state; it never deletes the
-- observations that justified the original join.
CREATE TABLE IF NOT EXISTS public.iga_correlations (
    id               uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL,
    source_object_id uuid NOT NULL,
    canonical_kind   text NOT NULL,
    canonical_id     uuid NOT NULL,
    join_key         text NOT NULL DEFAULT '',
    strength         text NOT NULL DEFAULT 'weak',
    state            text NOT NULL DEFAULT 'proposed',
    decided_by       text,
    decided_at       timestamptz,
    version          bigint NOT NULL DEFAULT 1,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_correlations_pkey PRIMARY KEY (id),
    CONSTRAINT iga_correlations_source_fkey
        FOREIGN KEY (workspace_id, source_object_id)
        REFERENCES public.iga_source_objects (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_correlations_strength_chk CHECK (strength IN ('strong', 'weak')),
    CONSTRAINT iga_correlations_state_chk CHECK (
        state IN ('proposed', 'accepted', 'rejected', 'split')),
    -- Only a provider-exposed relationship may auto-link; a weak join that
    -- claims accepted status without a decision is a bug.
    CONSTRAINT iga_correlations_weak_chk CHECK (
        state <> 'accepted' OR strength = 'strong' OR decided_by IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_iga_correlations_canonical
    ON public.iga_correlations (workspace_id, canonical_kind, canonical_id);

-- ------------------------------------------------------------------ --
-- 4. Canonical graph — provider-neutral                               --
-- ------------------------------------------------------------------ --
-- No column below may hold a provider-specific field. GitHub specifics belong
-- in iga_source_objects.normalized_payload or iga_observations.fact_payload.

-- iga_estate_scopes — containment only (organization, project, cluster).
-- Containment confers NO access inheritance; an access path must be evidenced.
CREATE TABLE IF NOT EXISTS public.iga_estate_scopes (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    scope_kind      text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    parent_scope_id uuid,
    stage           text NOT NULL DEFAULT 'unknown',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_estate_scopes_pkey PRIMARY KEY (id),
    CONSTRAINT iga_estate_scopes_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_estate_scopes_parent_fkey
        FOREIGN KEY (workspace_id, parent_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (parent_scope_id),
    CONSTRAINT iga_estate_scopes_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_estate_scopes_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_agents — the LOGICAL agent only. A candidate is not an agent: proposals
-- live in iga_classification_candidates until confirmed. rollup_state carries
-- the honesty of the record (confirmed / contested / unknown / stale) and is
-- separate from any displayed value.
CREATE TABLE IF NOT EXISTS public.iga_agents (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    estate_scope_id uuid,
    display_name text NOT NULL DEFAULT '',
    classification text NOT NULL DEFAULT 'unknown',
    status       text NOT NULL DEFAULT 'active',
    rollup_state text NOT NULL DEFAULT 'unknown',
    lifecycle    text NOT NULL DEFAULT 'active',
    version      bigint NOT NULL DEFAULT 1,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_agents_pkey PRIMARY KEY (id),
    CONSTRAINT iga_agents_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_agents_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_agents_rollup_chk CHECK (
        rollup_state IN ('confirmed', 'contested', 'unknown', 'stale')),
    CONSTRAINT iga_agents_lifecycle_chk CHECK (
        lifecycle IN ('active', 'retired', 'tombstoned')),
    CONSTRAINT iga_agents_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_agents_workspace_rollup
    ON public.iga_agents (workspace_id, rollup_state, lifecycle);

-- iga_agent_instances — a REALIZATION proven by a source that can prove
-- deployment (a Kubernetes workload, a hosted agent, an endpoint install).
-- A repository declaration alone never produces a row here: declared is not
-- running.
CREATE TABLE IF NOT EXISTS public.iga_agent_instances (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    agent_id          uuid NOT NULL,
    estate_scope_id   uuid,
    native_workload_id text NOT NULL DEFAULT '',
    runtime_kind      text NOT NULL DEFAULT '',
    stage             text NOT NULL DEFAULT 'unknown',
    lifecycle         text NOT NULL DEFAULT 'active',
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_agent_instances_pkey PRIMARY KEY (id),
    CONSTRAINT iga_agent_instances_agent_fkey
        FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_agent_instances_scope_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_agent_instances_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_agent_instances_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_identity_accounts — a programmatic principal. Never a credential, and
-- never automatically an agent: an App installation or a PAT owner is an
-- identity until evidence links it to an agent.
CREATE TABLE IF NOT EXISTS public.iga_identity_accounts (
    id               uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL,
    estate_scope_id  uuid,
    display_name     text NOT NULL DEFAULT '',
    account_kind     text NOT NULL,
    identity_backing text NOT NULL DEFAULT 'unknown',
    lifecycle        text NOT NULL DEFAULT 'active',
    rollup_state     text NOT NULL DEFAULT 'unknown',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_identity_accounts_pkey PRIMARY KEY (id),
    CONSTRAINT iga_identity_accounts_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_identity_accounts_scope_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_identity_accounts_rollup_chk CHECK (
        rollup_state IN ('confirmed', 'contested', 'unknown', 'stale')),
    CONSTRAINT iga_identity_accounts_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_credentials — NON-SECRET metadata about how an identity authenticates.
-- No value, no token, no private key, ever. Rotation appends a lifecycle event
-- under the SAME identity account; it does not create an identity or an agent.
CREATE TABLE IF NOT EXISTS public.iga_credentials (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    identity_account_id uuid NOT NULL,
    credential_type     text NOT NULL,
    issuer              text NOT NULL DEFAULT '',
    key_identifier      text NOT NULL DEFAULT '',
    -- Pointer into the secrets store, never the material itself.
    secret_ref          text NOT NULL DEFAULT '',
    issued_at           timestamptz,
    expires_at          timestamptz,
    last_used_at        timestamptz,
    rotation_posture    text NOT NULL DEFAULT 'unknown',
    lifecycle           text NOT NULL DEFAULT 'active',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT iga_credentials_identity_fkey
        FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_credentials_lifecycle_chk CHECK (
        lifecycle IN ('active', 'expired', 'revoked', 'rotated')),
    CONSTRAINT iga_credentials_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_credentials_identity
    ON public.iga_credentials (workspace_id, identity_account_id);

-- iga_resources — the protected thing: a repository, API, tool, model or
-- application. Provider-neutral by contract.
CREATE TABLE IF NOT EXISTS public.iga_resources (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    estate_scope_id uuid,
    resource_kind   text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    stage           text NOT NULL DEFAULT 'unknown',
    lifecycle       text NOT NULL DEFAULT 'active',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_resources_pkey PRIMARY KEY (id),
    CONSTRAINT iga_resources_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_resources_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_resources_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_resources_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_entitlements — one native access unit. native_rights preserves the
-- provider's own wording; normalized_rights is our derived reading. Both are
-- kept so a reviewer can always see what the provider actually said.
CREATE TABLE IF NOT EXISTS public.iga_entitlements (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    resource_id       uuid,
    native_grant_kind text NOT NULL,
    native_rights     jsonb NOT NULL DEFAULT '{}'::jsonb,
    normalized_rights jsonb NOT NULL DEFAULT '{}'::jsonb,
    native_scope      text NOT NULL DEFAULT '',
    -- Whether this grant can actually be revoked through a supported path.
    remediable        boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_entitlements_pkey PRIMARY KEY (id),
    CONSTRAINT iga_entitlements_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_entitlements_resource_fkey
        FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_entitlements_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_access_edges — subject -> entitlement -> resource.
--
-- calculation_state is the load-bearing column. A source grant is NOT
-- automatically effective access: unsupported conditional controls, policy
-- layers or missing membership evidence leave the effective conclusion
-- unknown, and the UI must say so rather than implying access was proven.
CREATE TABLE IF NOT EXISTS public.iga_access_edges (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    subject_kind   text NOT NULL,
    subject_id     uuid NOT NULL,
    entitlement_id uuid,
    resource_id    uuid,
    direction      text NOT NULL,
    path_kind      text NOT NULL DEFAULT '',
    calculation_state text NOT NULL DEFAULT 'unknown',
    effective_conclusion text NOT NULL DEFAULT 'unknown',
    native_scope   text NOT NULL DEFAULT '',
    observed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_access_edges_pkey PRIMARY KEY (id),
    CONSTRAINT iga_access_edges_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_access_edges_entitlement_fkey
        FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_access_edges_resource_fkey
        FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_access_edges_subject_chk CHECK (
        subject_kind IN ('agent', 'agent_instance', 'identity_account', 'user', 'team')),
    CONSTRAINT iga_access_edges_direction_chk CHECK (direction IN ('inbound', 'outbound')),
    CONSTRAINT iga_access_edges_calculation_chk CHECK (
        calculation_state IN ('complete', 'partial', 'unknown')),
    CONSTRAINT iga_access_edges_conclusion_chk CHECK (
        effective_conclusion IN ('effective', 'not_effective', 'unknown')),
    -- An edge may only claim a decided conclusion when the calculation is
    -- complete. Partial or unknown evidence yields an unknown conclusion.
    CONSTRAINT iga_access_edges_honesty_chk CHECK (
        effective_conclusion = 'unknown' OR calculation_state = 'complete'),
    CONSTRAINT iga_access_edges_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_access_edges_subject
    ON public.iga_access_edges (workspace_id, subject_kind, subject_id, direction);
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_resource
    ON public.iga_access_edges (workspace_id, resource_id, direction);

-- iga_canonical_attribute_values — survivorship. When two sources disagree
-- about the same attribute, both values are kept with their authority rank and
-- the observation that supplied each; the winner is a decision, not a
-- last-write-wins accident.
CREATE TABLE IF NOT EXISTS public.iga_canonical_attribute_values (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    entity_kind    text NOT NULL,
    entity_id      uuid NOT NULL,
    attribute      text NOT NULL,
    value          jsonb,
    observation_id uuid,
    authority_rank integer NOT NULL DEFAULT 0,
    state          text NOT NULL DEFAULT 'surviving',
    valid_from     timestamptz,
    valid_to       timestamptz,
    fallback_reason text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_canonical_attribute_values_pkey PRIMARY KEY (id),
    CONSTRAINT iga_canonical_attribute_values_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_canonical_attribute_values_observation_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE SET NULL (observation_id),
    CONSTRAINT iga_canonical_attribute_values_state_chk CHECK (
        state IN ('surviving', 'superseded', 'contested', 'rejected'))
);

-- Exactly one surviving value per (entity, attribute).
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_canonical_attribute_surviving
    ON public.iga_canonical_attribute_values (workspace_id, entity_kind, entity_id, attribute)
    WHERE state = 'surviving';

-- iga_attribute_authority_policies — which source wins for which attribute, and
-- whether an authoritative source is allowed to assert null.
CREATE TABLE IF NOT EXISTS public.iga_attribute_authority_policies (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    entity_kind    text NOT NULL,
    attribute      text NOT NULL,
    provider       text NOT NULL DEFAULT '',
    authority_rank integer NOT NULL DEFAULT 0,
    allow_authoritative_null boolean NOT NULL DEFAULT false,
    version        bigint NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_attribute_authority_policies_pkey PRIMARY KEY (id),
    CONSTRAINT iga_attribute_authority_policies_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_attribute_authority_policies_key
        UNIQUE (workspace_id, entity_kind, attribute, provider)
);

-- iga_observation_links — the drill-down path. Every canonical value and edge
-- must resolve to the observations that support it, and crucially to those
-- that CONTRADICT it, which is how a contested rollup state is justified.
CREATE TABLE IF NOT EXISTS public.iga_observation_links (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    observation_id uuid NOT NULL,
    target_kind    text NOT NULL,
    target_id      uuid NOT NULL,
    relation       text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_observation_links_pkey PRIMARY KEY (id),
    CONSTRAINT iga_observation_links_observation_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observation_links_relation_chk CHECK (
        relation IN ('supports', 'contradicts', 'supersedes', 'previously_supported')),
    CONSTRAINT iga_observation_links_key
        UNIQUE (workspace_id, observation_id, target_kind, target_id, relation)
);

CREATE INDEX IF NOT EXISTS idx_iga_observation_links_target
    ON public.iga_observation_links (workspace_id, target_kind, target_id);

-- iga_ownership_candidates — proposed TECHNICAL owners with the evidence that
-- proposed them. A code-review owner is not a business sponsor: no row here
-- may silently populate sponsorship, which is a separate governance action
-- that must resolve to a person.
CREATE TABLE IF NOT EXISTS public.iga_ownership_candidates (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    subject_kind   text NOT NULL,
    subject_id     uuid NOT NULL,
    candidate_kind text NOT NULL,
    candidate_ref  text NOT NULL,
    evidence_source text NOT NULL DEFAULT '',
    rank           integer NOT NULL DEFAULT 0,
    state          text NOT NULL DEFAULT 'proposed',
    decided_by     text,
    decided_at     timestamptz,
    version        bigint NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_ownership_candidates_pkey PRIMARY KEY (id),
    CONSTRAINT iga_ownership_candidates_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_ownership_candidates_kind_chk CHECK (
        candidate_kind IN ('user', 'team', 'unknown')),
    CONSTRAINT iga_ownership_candidates_state_chk CHECK (
        state IN ('proposed', 'confirmed', 'rejected')),
    CONSTRAINT iga_ownership_candidates_decided_chk CHECK (
        state = 'proposed' OR decided_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_iga_ownership_candidates_subject
    ON public.iga_ownership_candidates (workspace_id, subject_kind, subject_id, state);

-- iga_operational_issues — permission loss, staleness, truncation, API failure.
-- Kept strictly SEPARATE from agent-risk findings: "we could not read this" is
-- an operational problem for the administrator, not a security finding about
-- an agent, and mixing the two makes both untrustworthy.
CREATE TABLE IF NOT EXISTS public.iga_operational_issues (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    integration_id uuid,
    issue_kind     text NOT NULL,
    severity       text NOT NULL DEFAULT 'info',
    object_class   text NOT NULL DEFAULT '',
    scope_ref      text NOT NULL DEFAULT '',
    detail         jsonb NOT NULL DEFAULT '{}'::jsonb,
    state          text NOT NULL DEFAULT 'open',
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    CONSTRAINT iga_operational_issues_pkey PRIMARY KEY (id),
    CONSTRAINT iga_operational_issues_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_operational_issues_kind_chk CHECK (issue_kind IN (
        'permission_denied', 'stale_scan', 'tree_truncated', 'api_failure',
        'rate_limited', 'unsupported_capability', 'binding_failure')),
    CONSTRAINT iga_operational_issues_state_chk CHECK (
        state IN ('open', 'acknowledged', 'resolved'))
);

CREATE INDEX IF NOT EXISTS idx_iga_operational_issues_state
    ON public.iga_operational_issues (workspace_id, state, issue_kind);

-- iga_integration_scopes.estate_scope_id is wired up here rather than inline:
-- iga_estate_scopes is declared further down, so the reference cannot exist at
-- CREATE TABLE time. Column-list SET NULL for the same reason as above.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'iga_integration_scopes_estate_scope_fkey'
    ) THEN
        ALTER TABLE ONLY public.iga_integration_scopes
            ADD CONSTRAINT iga_integration_scopes_estate_scope_fkey
            FOREIGN KEY (workspace_id, estate_scope_id)
            REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id);
    END IF;
END $$;

-- Agentic IGA RBAC permissions -- GLOBAL (workspace_id IS NULL), same model as
-- connector:* and discovery:*. Three, matching the authorization tiers in the
-- API contract: viewer reads, admin connects/verifies/scans, reviewer decides.
-- 'review' is separate from 'admin' so a reviewer can confirm or reject a
-- candidate without also being able to rebind an installation.
INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'iga', 'read',   'Read IGA inventory, coverage and evidence', 'iga:read',   NOW()),
    (gen_random_uuid(), NULL, 'iga', 'admin',  'Manage IGA integrations and run scans',     'iga:admin',  NOW()),
    (gen_random_uuid(), NULL, 'iga', 'review', 'Decide classification and ownership candidates', 'iga:review', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

-- iga_idempotency_keys -- replay protection for POST scan and decision routes.
-- Reuse of a key with the SAME request returns the original result; reuse with
-- a different request is a conflict. request_hash is what tells them apart.
CREATE TABLE IF NOT EXISTS public.iga_idempotency_keys (
    workspace_id    uuid NOT NULL,
    idempotency_key text NOT NULL,
    route           text NOT NULL,
    request_hash    text NOT NULL,
    response_status integer NOT NULL,
    response_body   jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_idempotency_keys_pkey PRIMARY KEY (workspace_id, idempotency_key),
    CONSTRAINT iga_idempotency_keys_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE
);
