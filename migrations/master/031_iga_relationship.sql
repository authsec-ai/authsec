-- ============================================================================
-- 031: iga_relationship
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_relationship (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    relationship_type text NOT NULL,

    source_identity_account_id uuid,
    source_workload_id         uuid,
    -- source_external_principal_id: added by 034 (its table does not exist yet).

    target_identity_account_id uuid,

    basis             text NOT NULL DEFAULT 'declared',
    derivation_rule   text NOT NULL DEFAULT '',
    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,
    ended_reason      text NOT NULL DEFAULT '',
    source_key        text NOT NULL,
    partition_key     text NOT NULL DEFAULT '',
    connector_id      uuid,

    -- can_assume only: the trust statement that declared it, verbatim facts.
    statement_key     text  NOT NULL DEFAULT '',
    conditions        jsonb,          -- NULL = the statement had no Condition
    mechanism         text  NOT NULL DEFAULT '',  -- sts_assume_role | oidc_federation | saml_federation | eks_pod_identity

    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_relationship_pkey PRIMARY KEY (id),
    CONSTRAINT iga_relationship_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_relationship_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
    CONSTRAINT iga_rel_src_identity_fkey FOREIGN KEY (workspace_id, source_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_src_workload_fkey FOREIGN KEY (workspace_id, source_workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_identity_fkey FOREIGN KEY (workspace_id, target_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_run_fkey FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),

    CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id IS NOT NULL)::int
      + (source_workload_id         IS NOT NULL)::int = 1),
    CONSTRAINT iga_relationship_target_chk CHECK (target_identity_account_id IS NOT NULL),

    -- The legal (source, type, target) triples. ELSE false is load-bearing.
    CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as'         THEN source_workload_id IS NOT NULL
            WHEN 'task_execution_role' THEN source_workload_id IS NOT NULL
            WHEN 'member_of'           THEN source_identity_account_id IS NOT NULL
            WHEN 'can_assume'          THEN source_identity_account_id IS NOT NULL
            ELSE false
        END),

    CONSTRAINT iga_relationship_basis_chk CHECK (basis IN ('declared','observed','derived','asserted')),
    CONSTRAINT iga_relationship_derivation_chk CHECK (basis <> 'derived' OR derivation_rule <> ''),
    CONSTRAINT iga_relationship_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_relationship_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    CONSTRAINT iga_relationship_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_relationship_source_key_chk CHECK (source_key <> ''),
    CONSTRAINT iga_relationship_trust_chk CHECK (
        (relationship_type = 'can_assume') = (mechanism <> ''))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_relationship_live
    ON public.iga_relationship (workspace_id, source_key) WHERE state <> 'ended';
CREATE INDEX IF NOT EXISTS idx_iga_relationship_source
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(source_identity_account_id, source_workload_id));
CREATE INDEX IF NOT EXISTS idx_iga_relationship_target
    ON public.iga_relationship (workspace_id, relationship_type, target_identity_account_id);
CREATE INDEX IF NOT EXISTS idx_iga_relationship_partition
    ON public.iga_relationship (workspace_id, connector_id, partition_key) WHERE state <> 'ended';
