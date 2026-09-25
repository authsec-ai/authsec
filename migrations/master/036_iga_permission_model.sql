-- ============================================================================
-- 036: the IGA permission model
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_policy (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    provider       text NOT NULL,
    policy_kind    text NOT NULL,     -- aws_managed | customer_managed | inline
    display_name   text NOT NULL,
    native_ref     text NOT NULL DEFAULT '',  -- ARN for managed
    source_key     text NOT NULL,
    continuity     text NOT NULL,
    immutable_key  text NOT NULL DEFAULT '',  -- PolicyId
    version_id     text NOT NULL DEFAULT '',
    document_hash  text NOT NULL DEFAULT '',
    lifecycle      text NOT NULL DEFAULT 'active',
    retired_reason text NOT NULL DEFAULT '',
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_policy_pkey PRIMARY KEY (id),
    CONSTRAINT iga_policy_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_policy_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_policy_kind_chk CHECK (policy_kind IN ('aws_managed','customer_managed','inline')),
    CONSTRAINT iga_policy_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    CONSTRAINT iga_policy_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> ''),
    CONSTRAINT iga_policy_lifecycle_chk CHECK (lifecycle IN ('active','retired')),
    CONSTRAINT iga_policy_retired_chk CHECK ((lifecycle = 'retired') = (retired_reason <> ''))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_policy_source_key
    ON public.iga_policy (workspace_id, source_key) WHERE lifecycle <> 'retired';

-- A statement is an entitlement row. Existing GitHub entitlements have
-- provider = 'github' and leave every column below at its default.
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS policy_id       uuid,
    ADD COLUMN IF NOT EXISTS statement_key   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sid             text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS statement_index integer,
    ADD COLUMN IF NOT EXISTS effect          text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS content_hash    text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS negated         boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS conditional     boolean NOT NULL DEFAULT false;
ALTER TABLE public.iga_entitlements
    ADD CONSTRAINT iga_entitlements_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_entitlements_aws_statement_chk CHECK (
        provider <> 'aws'
        OR (policy_id IS NOT NULL AND statement_key <> '' AND effect IN ('allow','deny')
            AND content_hash <> ''));
CREATE INDEX IF NOT EXISTS idx_iga_entitlements_policy
    ON public.iga_entitlements (workspace_id, policy_id) WHERE policy_id IS NOT NULL;

-- Content history for Sid-keyed statements (§2.6). One live revision each.
CREATE TABLE IF NOT EXISTS public.iga_statement_revision (
    id                 uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL,
    entitlement_id     uuid NOT NULL,
    content_hash       text NOT NULL,
    statement          jsonb NOT NULL,     -- verbatim, as AWS returned it
    policy_version_id  text NOT NULL DEFAULT '',
    valid_from         timestamptz NOT NULL,
    valid_to           timestamptz,
    first_seen_run_id  uuid NOT NULL,
    CONSTRAINT iga_statement_revision_pkey PRIMARY KEY (id),
    CONSTRAINT iga_sr_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_sr_run_fkey FOREIGN KEY (workspace_id, first_seen_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_statement_revision_live
    ON public.iga_statement_revision (workspace_id, entitlement_id) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS public.iga_entitlement_target (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    entitlement_id uuid NOT NULL,
    resource_id    uuid NOT NULL,
    target_mode    text NOT NULL,     -- resource | not_resource
    ordinal        integer NOT NULL,  -- position in the statement's list
    CONSTRAINT iga_entitlement_target_pkey PRIMARY KEY (id),
    CONSTRAINT iga_et_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_et_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_et_mode_chk CHECK (target_mode IN ('resource','not_resource')),
    CONSTRAINT iga_et_key UNIQUE (workspace_id, entitlement_id, resource_id, target_mode)
);
CREATE INDEX IF NOT EXISTS idx_iga_et_resource
    ON public.iga_entitlement_target (workspace_id, resource_id);

CREATE TABLE IF NOT EXISTS public.iga_policy_assignment (
    id                         uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id               uuid NOT NULL,
    policy_id                  uuid NOT NULL,
    holder_identity_account_id uuid NOT NULL,
    assignment_kind            text NOT NULL,   -- attached | inline | boundary
    basis             text NOT NULL DEFAULT 'declared',
    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,
    ended_reason      text NOT NULL DEFAULT '',
    source_key        text NOT NULL,
    partition_key     text NOT NULL,
    connector_id      uuid,
    CONSTRAINT iga_policy_assignment_pkey PRIMARY KEY (id),
    CONSTRAINT iga_pa_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_pa_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_pa_holder_fkey FOREIGN KEY (workspace_id, holder_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_pa_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
    CONSTRAINT iga_pa_run_fkey FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),
    CONSTRAINT iga_pa_kind_chk CHECK (assignment_kind IN ('attached','inline','boundary')),
    CONSTRAINT iga_pa_basis_chk CHECK (basis IN ('declared','asserted')),
    CONSTRAINT iga_pa_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_pa_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    CONSTRAINT iga_pa_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_pa_source_key_chk CHECK (source_key <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_policy_assignment_live
    ON public.iga_policy_assignment (workspace_id, source_key) WHERE state <> 'ended';
CREATE INDEX IF NOT EXISTS idx_iga_pa_holder
    ON public.iga_policy_assignment (workspace_id, holder_identity_account_id, state);
CREATE INDEX IF NOT EXISTS idx_iga_pa_partition
    ON public.iga_policy_assignment (workspace_id, connector_id, partition_key) WHERE state <> 'ended';

CREATE TABLE IF NOT EXISTS public.iga_assignment_evidence (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    assignment_id  uuid NOT NULL,
    observation_id uuid NOT NULL,
    relation       text NOT NULL DEFAULT 'supports',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_assignment_evidence_pkey PRIMARY KEY (id),
    CONSTRAINT iga_ae_assignment_fkey FOREIGN KEY (workspace_id, assignment_id)
        REFERENCES public.iga_policy_assignment (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_ae_obs_fkey FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_ae_relation_chk CHECK (relation IN ('supports','contradicts','supersedes','previously_supported')),
    CONSTRAINT iga_ae_key UNIQUE (workspace_id, assignment_id, observation_id, relation)
);

-- A grant is reached through exactly one assignment, and only Allow statements
-- are grants. Enforced for AWS rows; GitHub rows (provider = 'github') are exempt.
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS assignment_id uuid,
    ADD CONSTRAINT iga_access_edges_assignment_fkey FOREIGN KEY (workspace_id, assignment_id)
        REFERENCES public.iga_policy_assignment (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_aws_grant_chk CHECK (
        provider <> 'aws'
        OR (assignment_id IS NOT NULL AND entitlement_id IS NOT NULL
            AND subject_identity_account_id IS NOT NULL AND resource_id IS NULL));
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_entitlement
    ON public.iga_access_edges (workspace_id, entitlement_id) WHERE state <> 'ended';

-- Policies are nodes with multi-source support (§2.10B).
ALTER TABLE public.iga_object_support
    ADD COLUMN IF NOT EXISTS policy_id uuid,
    ADD CONSTRAINT iga_os_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE;
ALTER TABLE public.iga_object_support DROP CONSTRAINT iga_object_support_one_chk;
ALTER TABLE public.iga_object_support ADD CONSTRAINT iga_object_support_one_chk CHECK (
    (identity_account_id IS NOT NULL)::int + (workload_id    IS NOT NULL)::int
  + (resource_id         IS NOT NULL)::int + (entitlement_id IS NOT NULL)::int
  + (policy_id           IS NOT NULL)::int = 1);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_policy
    ON public.iga_object_support (workspace_id, policy_id, connector_id, partition_key)
    WHERE policy_id IS NOT NULL;

-- Durable node lifecycle history for the Changes view (§5.3). Written in the
-- projection transaction; the FK to the publication is DEFERRED because the
-- publication row is inserted at the end of the same transaction, so an event
-- can exist only together with the publication it belongs to.
CREATE TABLE IF NOT EXISTS public.iga_lifecycle_event (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    rev                 bigint NOT NULL,
    scan_run_id         uuid NOT NULL,
    occurred_at         timestamptz NOT NULL,
    event               text NOT NULL,   -- first_seen | retired | restored
    reason              text NOT NULL DEFAULT '',  -- retired: unsupported | recreated | policy_recreated
    identity_account_id uuid,
    workload_id         uuid,
    resource_id         uuid,
    entitlement_id      uuid,
    policy_id           uuid,
    CONSTRAINT iga_lifecycle_event_pkey PRIMARY KEY (id),
    CONSTRAINT iga_le_publication_fkey FOREIGN KEY (workspace_id, rev)
        REFERENCES public.iga_publication (workspace_id, rev) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT iga_le_run_fkey FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_le_identity_fkey FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_event_chk CHECK (event IN ('first_seen','retired','restored')),
    CONSTRAINT iga_le_reason_chk CHECK ((event = 'retired') = (reason <> '')),
    CONSTRAINT iga_le_one_chk CHECK (
        (identity_account_id IS NOT NULL)::int + (workload_id IS NOT NULL)::int
      + (resource_id IS NOT NULL)::int + (entitlement_id IS NOT NULL)::int
      + (policy_id IS NOT NULL)::int = 1)
);
CREATE INDEX IF NOT EXISTS idx_iga_le_identity ON public.iga_lifecycle_event (workspace_id, identity_account_id, occurred_at DESC) WHERE identity_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_le_workload ON public.iga_lifecycle_event (workspace_id, workload_id, occurred_at DESC) WHERE workload_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_le_resource ON public.iga_lifecycle_event (workspace_id, resource_id, occurred_at DESC) WHERE resource_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_le_policy   ON public.iga_lifecycle_event (workspace_id, policy_id, occurred_at DESC) WHERE policy_id IS NOT NULL;
