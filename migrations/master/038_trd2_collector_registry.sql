-- 038_trd2_collector_registry.sql
--
-- TRD 2 M1: collector registry, credentials, integration binding, batches,
-- snapshots and the enrollment response-recovery record.
--
-- Number 037 is reserved (migrations/contract/037_iga_access_edges_contract.sql).
-- Number 039 is reserved for the AD adapter. 040–044 are reserved for TRD 2
-- M2–M6. This file is the only 038.
--
-- The master runner is set-based, not a high-water mark. It records a success
-- row in migration_logs keyed by (version, name) and skips that pair on the
-- next boot. A later file can be recorded even when an earlier file failed
-- (the failed pair is retried because success = false does not count). In-order
-- numbering is still required: operators and later packages assume 038, then
-- 039, then 040.
--
-- The runner already wraps each file in a transaction. Do not add BEGIN/COMMIT.

-- ------------------------------------------------------------------ --
-- Parents that composite FKs need, and additive vocabulary           --
-- ------------------------------------------------------------------ --

-- id is already unique. (workspace_id, id) is required before a child can
-- reference the pair, which is what keeps a collector in workspace A from
-- pointing at workspace B's source.
CREATE UNIQUE INDEX IF NOT EXISTS discovery_sources_workspace_id_key
    ON public.discovery_sources (workspace_id, id);

ALTER TABLE public.discovery_sources DROP CONSTRAINT IF EXISTS discovery_sources_kind_chk;
ALTER TABLE public.discovery_sources
    ADD CONSTRAINT discovery_sources_kind_chk CHECK (
        kind IN (
            'k8s_webhook', 'aws', 'azure', 'gcp', 'vm_sensor', 'repo_scan',
            'linux_collector', 'k8s_collector', 'node_sensor'));

-- Evidence trust. Legacy writers do not set the column; the default labels
-- every pre-collector row unverified_legacy so it cannot be read as authenticated.
ALTER TABLE public.discovered_agents
    ADD COLUMN IF NOT EXISTS evidence_trust text NOT NULL DEFAULT 'unverified_legacy';

ALTER TABLE public.discovered_agents DROP CONSTRAINT IF EXISTS discovered_agents_evidence_trust_chk;
ALTER TABLE public.discovered_agents
    ADD CONSTRAINT discovered_agents_evidence_trust_chk CHECK (
        evidence_trust IN ('unverified_legacy', 'authenticated_collector', 'human_asserted'));

ALTER TABLE public.discovered_agent_events
    ADD COLUMN IF NOT EXISTS evidence_trust text NOT NULL DEFAULT 'unverified_legacy';

ALTER TABLE public.discovered_agent_events DROP CONSTRAINT IF EXISTS discovered_agent_events_evidence_trust_chk;
ALTER TABLE public.discovered_agent_events
    ADD CONSTRAINT discovered_agent_events_evidence_trust_chk CHECK (
        evidence_trust IN ('unverified_legacy', 'authenticated_collector', 'human_asserted'));

ALTER TABLE public.iga_observations
    ADD COLUMN IF NOT EXISTS evidence_trust text NOT NULL DEFAULT 'unverified_legacy';

ALTER TABLE public.iga_observations DROP CONSTRAINT IF EXISTS iga_observations_evidence_trust_chk;
ALTER TABLE public.iga_observations
    ADD CONSTRAINT iga_observations_evidence_trust_chk CHECK (
        evidence_trust IN ('unverified_legacy', 'authenticated_collector', 'human_asserted'));

ALTER TABLE public.iga_observations
    ADD COLUMN IF NOT EXISTS schema_version text NOT NULL DEFAULT '';

ALTER TABLE public.iga_observations
    ADD COLUMN IF NOT EXISTS received_at timestamptz;

UPDATE public.iga_observations
   SET received_at = ingested_at
 WHERE received_at IS NULL;

ALTER TABLE public.iga_observations
    ALTER COLUMN received_at SET DEFAULT now();

ALTER TABLE public.iga_observations
    ALTER COLUMN received_at SET NOT NULL;

ALTER TABLE public.iga_observations
    ADD COLUMN IF NOT EXISTS discovery_source_id uuid;

-- Nullable arm: legacy observations have no discovery source. SET NULL names
-- the column so workspace_id (NOT NULL) is not cleared with it.
ALTER TABLE public.iga_observations
    DROP CONSTRAINT IF EXISTS iga_observations_discovery_source_fkey;
ALTER TABLE public.iga_observations
    ADD CONSTRAINT iga_observations_discovery_source_fkey
    FOREIGN KEY (workspace_id, discovery_source_id)
    REFERENCES public.discovery_sources (workspace_id, id)
    ON DELETE SET NULL (discovery_source_id);

ALTER TABLE public.iga_observations DROP CONSTRAINT IF EXISTS iga_observations_mode_chk;
ALTER TABLE public.iga_observations
    ADD CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
        'platform_declared',
        'deployment_declared',
        'invocation_declared',
        'framework_dependency',
        'tool_configuration',
        'secret_reference',
        'identity_grant',
        'audit_event',
        'runtime_batch',
        'configuration_snapshot'));

ALTER TABLE public.iga_scan_runs DROP CONSTRAINT IF EXISTS iga_scan_runs_mode_chk;
ALTER TABLE public.iga_scan_runs
    ADD CONSTRAINT iga_scan_runs_mode_chk CHECK (
        mode IN ('full', 'incremental', 'targeted', 'runtime_batch', 'configuration_snapshot'));

-- iga_integrations.provider had no CHECK. The vocabulary was GitHub-only in
-- practice. linux, kubernetes and ad are additive; github stays valid. The AD
-- adapter (039) inserts provider = 'ad' and depends on this.
ALTER TABLE public.iga_integrations DROP CONSTRAINT IF EXISTS iga_integrations_provider_chk;
ALTER TABLE public.iga_integrations
    ADD CONSTRAINT iga_integrations_provider_chk CHECK (
        provider IN ('github', 'linux', 'kubernetes', 'ad'));

CREATE INDEX IF NOT EXISTS idx_discovered_agents_evidence_trust
    ON public.discovered_agents (workspace_id, evidence_trust);

-- Per-workspace kill switch for the unauthenticated /authsec/discovery ingress.
-- Absent row means the legacy routes stay open. The global env flag
-- IGA_LEGACY_INGRESS_DISABLED is applied in the handler, not here.
CREATE TABLE IF NOT EXISTS public.workspace_collector_settings (
    workspace_id uuid NOT NULL,
    legacy_discovery_ingress_disabled boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT '',
    CONSTRAINT workspace_collector_settings_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT workspace_collector_settings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

-- ------------------------------------------------------------------ --
-- Enrollment                                                          --
-- ------------------------------------------------------------------ --

CREATE TABLE IF NOT EXISTS public.collector_enrollments (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    token_hash text NOT NULL,
    kind text NOT NULL,
    estate_scope_id uuid,
    estate_scope_kind text NOT NULL,
    estate_display_name text NOT NULL DEFAULT '',
    namespace_allowlist jsonb NOT NULL DEFAULT '[]'::jsonb,
    capability_ceiling jsonb NOT NULL DEFAULT '{}'::jsonb,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '15 minutes'),
    used_at timestamptz,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_enrollments_pkey PRIMARY KEY (id),
    CONSTRAINT collector_enrollments_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_enrollments_token_hash_key UNIQUE (token_hash),
    CONSTRAINT collector_enrollments_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT collector_enrollments_estate_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id)
        ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT collector_enrollments_kind_chk CHECK (
        kind IN ('linux_collector', 'k8s_collector', 'node_sensor')),
    CONSTRAINT collector_enrollments_scope_kind_chk CHECK (
        estate_scope_kind IN ('host', 'cluster', 'node'))
);

CREATE INDEX IF NOT EXISTS idx_collector_enrollments_workspace
    ON public.collector_enrollments (workspace_id, created_at DESC);

-- Short-lived encrypted copy of the enroll response, keyed by the hash of the
-- installation public key and nonce. A retry of the same pair returns this
-- ciphertext instead of creating a second collector. The plaintext credential
-- is not stored beside the hash.
CREATE TABLE IF NOT EXISTS public.collector_enrollment_recoveries (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    enrollment_id uuid NOT NULL,
    key_hash text NOT NULL,
    ciphertext bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_enrollment_recoveries_pkey PRIMARY KEY (id),
    CONSTRAINT collector_enrollment_recoveries_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_enrollment_recoveries_pair_key UNIQUE (enrollment_id, key_hash),
    CONSTRAINT collector_enrollment_recoveries_enrollment_fkey
        FOREIGN KEY (workspace_id, enrollment_id)
        REFERENCES public.collector_enrollments (workspace_id, id) ON DELETE CASCADE
);

-- ------------------------------------------------------------------ --
-- Instances, credentials, integration binding                         --
-- ------------------------------------------------------------------ --

CREATE TABLE IF NOT EXISTS public.collector_instances (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    discovery_source_id uuid NOT NULL,
    estate_scope_id uuid NOT NULL,
    integration_id uuid NOT NULL,
    kind text NOT NULL,
    installation_key_id text NOT NULL,
    installation_public_key bytea NOT NULL,
    approved_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
    epoch uuid,
    authorized_next_epoch uuid,
    last_sequence bigint NOT NULL DEFAULT 0,
    version text NOT NULL DEFAULT '',
    row_version bigint NOT NULL DEFAULT 1,
    capability_digest text NOT NULL DEFAULT '',
    last_seen_at timestamptz,
    status text NOT NULL DEFAULT 'active',
    revoked_at timestamptz,
    revoke_reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_instances_pkey PRIMARY KEY (id),
    CONSTRAINT collector_instances_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_instances_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT collector_instances_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_instances_estate_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT collector_instances_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_instances_kind_chk CHECK (
        kind IN ('linux_collector', 'k8s_collector', 'node_sensor')),
    CONSTRAINT collector_instances_status_chk CHECK (status IN ('active', 'revoked')),
    CONSTRAINT collector_instances_revoked_chk CHECK (
        status <> 'revoked' OR revoked_at IS NOT NULL)
);

-- One active installation key per workspace. A revoked row keeps the key so
-- the audit trail survives, and a new enrollment may not reuse it while the
-- active row exists.
CREATE UNIQUE INDEX IF NOT EXISTS uq_collector_instances_active_install
    ON public.collector_instances (workspace_id, installation_key_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_collector_instances_workspace_status
    ON public.collector_instances (workspace_id, status);

CREATE TABLE IF NOT EXISTS public.collector_credentials (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    credential_hash text NOT NULL,
    scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    predecessor_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT collector_credentials_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_credentials_hash_key UNIQUE (credential_hash),
    CONSTRAINT collector_credentials_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_credentials_predecessor_fkey
        FOREIGN KEY (workspace_id, predecessor_id)
        REFERENCES public.collector_credentials (workspace_id, id)
        ON DELETE SET NULL (predecessor_id),
    CONSTRAINT collector_credentials_scopes_chk CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_collector_credentials_collector
    ON public.collector_credentials (workspace_id, collector_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS public.collector_integrations (
    workspace_id uuid NOT NULL,
    discovery_source_id uuid NOT NULL,
    integration_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_integrations_pkey PRIMARY KEY (workspace_id, discovery_source_id),
    CONSTRAINT collector_integrations_integration_key UNIQUE (workspace_id, integration_id),
    CONSTRAINT collector_integrations_collector_key UNIQUE (workspace_id, collector_id),
    CONSTRAINT collector_integrations_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_integrations_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_integrations_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE
);

-- Single-use rotation proofs. The nonce is stored only as a hash.
CREATE TABLE IF NOT EXISTS public.collector_rotation_nonces (
    workspace_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    nonce_hash text NOT NULL,
    used_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_rotation_nonces_pkey
        PRIMARY KEY (workspace_id, collector_id, nonce_hash),
    CONSTRAINT collector_rotation_nonces_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE
);

-- ------------------------------------------------------------------ --
-- Batches, snapshots, outbox (written by agent-sync; created here so --
-- 038 is the single M1 migration)                                     --
-- ------------------------------------------------------------------ --

CREATE TABLE IF NOT EXISTS public.collector_batches (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    epoch uuid NOT NULL,
    sequence bigint NOT NULL,
    batch_id uuid NOT NULL,
    payload_hash text NOT NULL,
    receipt_id uuid NOT NULL,
    receipt_state text NOT NULL,
    projection_state text NOT NULL,
    iga_scan_run_id uuid,
    graph_revision bigint NOT NULL DEFAULT 0,
    received_at timestamptz NOT NULL DEFAULT now(),
    error_code text NOT NULL DEFAULT '',
    receipt_body jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT collector_batches_pkey PRIMARY KEY (id),
    CONSTRAINT collector_batches_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_batches_receipt_key UNIQUE (workspace_id, receipt_id),
    CONSTRAINT collector_batches_sequence_key UNIQUE (workspace_id, collector_id, epoch, sequence),
    CONSTRAINT collector_batches_batch_key UNIQUE (workspace_id, collector_id, batch_id),
    CONSTRAINT collector_batches_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_batches_scan_fkey
        FOREIGN KEY (workspace_id, iga_scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id) ON DELETE SET NULL (iga_scan_run_id),
    CONSTRAINT collector_batches_sequence_chk CHECK (sequence > 0),
    CONSTRAINT collector_batches_receipt_state_chk CHECK (
        receipt_state IN ('accepted', 'projecting', 'published', 'failed')),
    CONSTRAINT collector_batches_projection_state_chk CHECK (
        projection_state IN ('queued', 'published'))
);

CREATE INDEX IF NOT EXISTS idx_collector_batches_collector_time
    ON public.collector_batches (workspace_id, collector_id, received_at DESC);

CREATE TABLE IF NOT EXISTS public.collector_snapshots (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    epoch uuid NOT NULL,
    scope_key text NOT NULL,
    object_class text NOT NULL,
    generation bigint NOT NULL,
    expected_chunks integer NOT NULL,
    received_digest text NOT NULL DEFAULT '',
    complete boolean NOT NULL DEFAULT false,
    gap_blocked boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_snapshots_pkey PRIMARY KEY (id),
    CONSTRAINT collector_snapshots_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_snapshots_identity_key
        UNIQUE (workspace_id, collector_id, snapshot_id),
    CONSTRAINT collector_snapshots_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_snapshots_chunks_chk CHECK (expected_chunks > 0)
);

CREATE TABLE IF NOT EXISTS public.collector_snapshot_chunks (
    workspace_id uuid NOT NULL,
    snapshot_row_id uuid NOT NULL,
    chunk_no integer NOT NULL,
    payload_hash text NOT NULL,
    validated boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_snapshot_chunks_pkey
        PRIMARY KEY (workspace_id, snapshot_row_id, chunk_no),
    CONSTRAINT collector_snapshot_chunks_snapshot_fkey
        FOREIGN KEY (workspace_id, snapshot_row_id)
        REFERENCES public.collector_snapshots (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_snapshot_chunks_no_chk CHECK (chunk_no > 0)
);

CREATE TABLE IF NOT EXISTS public.collector_sequence_gaps (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    epoch uuid NOT NULL,
    expected_sequence bigint NOT NULL,
    received_sequence bigint NOT NULL,
    batch_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_sequence_gaps_pkey PRIMARY KEY (id),
    CONSTRAINT collector_sequence_gaps_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_sequence_gaps_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE
);

-- Not iga_durable_jobs: that queue's worker marks an unknown job_kind dead
-- (services/iga_service.go RunWorkerOnce). A collector job placed there would
-- be destroyed by the GitHub worker. This outbox has the same lease shape and
-- is claimed only by the collector worker.
CREATE TABLE IF NOT EXISTS public.collector_outbox (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    integration_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    batch_row_id uuid NOT NULL,
    job_kind text NOT NULL,
    dedupe_key text NOT NULL,
    state text NOT NULL DEFAULT 'ready',
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    leased_until timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_outbox_pkey PRIMARY KEY (id),
    CONSTRAINT collector_outbox_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_outbox_dedupe_key UNIQUE (workspace_id, dedupe_key),
    CONSTRAINT collector_outbox_batch_fkey
        FOREIGN KEY (workspace_id, batch_row_id)
        REFERENCES public.collector_batches (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_outbox_collector_fkey
        FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_outbox_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_outbox_state_chk CHECK (
        state IN ('ready', 'leased', 'done', 'failed', 'dead'))
);

CREATE INDEX IF NOT EXISTS idx_collector_outbox_claimable
    ON public.collector_outbox (state, available_at);

-- ------------------------------------------------------------------ --
-- Permission seeds. Unused until later packages.                      --
-- ------------------------------------------------------------------ --

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'runtime_policy', 'read',    'Read runtime policy drafts and publications', 'runtime_policy:read',    NOW()),
    (gen_random_uuid(), NULL, 'runtime_policy', 'write',   'Edit runtime policy drafts',                   'runtime_policy:write',   NOW()),
    (gen_random_uuid(), NULL, 'runtime_policy', 'approve', 'Approve a runtime policy revision',            'runtime_policy:approve', NOW()),
    (gen_random_uuid(), NULL, 'runtime_policy', 'enforce', 'Publish and enforce a runtime policy',         'runtime_policy:enforce', NOW()),
    (gen_random_uuid(), NULL, 'itdr',           'triage',  'Triage an identity threat finding',            'itdr:triage',            NOW()),
    (gen_random_uuid(), NULL, 'itdr',           'respond', 'Respond to an identity threat finding',        'itdr:respond',           NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;
