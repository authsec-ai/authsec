-- ============================================================================
-- 031: iga_relationship -- binary structural edges, typed on BOTH ends.
--
-- SPEC-iga-phase2-graph.md §2.2.
--
-- WHY A SECOND EDGE TABLE. iga_access_edges is the access-grant TRIPLE
-- (identity -> entitlement, resource denormalized). It cannot express
-- workload->identity, identity->identity or instance->workload -- there are no
-- endpoint columns for them -- and widening it to try would permit an edge
-- with no target at all. These are two genuinely different shapes and are kept
-- apart.
--
-- entitlement -> resource is NOT a relationship: it is
-- iga_entitlements.resource_id, which already exists and is already FK'd.
--
-- ORDERING NOTE, deliberate and different from a literal reading of the spec.
-- §3's 031 listing shows source_external_principal_id and its FK inline, while
-- §3's 034 says 034 adds "the table in §2.12, plus
-- iga_relationship.source_external_principal_id, its composite FK and the
-- widened can_assume arm". Both cannot be true: iga_external_principal does
-- not exist until 034, so an inline FK to it here cannot apply. 034's reading
-- is the one implemented -- this table ships with three typed sources, and 034
-- adds the fourth together with the table it points at. The spec's own reason
-- for putting external principals last holds either way: the graph is correct
-- without them, since a trust policy naming an unconnected provider simply
-- produces no edge.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_relationship (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    relationship_type text NOT NULL,

    source_identity_account_id uuid,
    source_workload_id         uuid,
    source_agent_instance_id   uuid,

    target_identity_account_id uuid,
    target_workload_id         uuid,
    target_agent_id            uuid,

    -- What KIND of claim this edge makes (§2.3). Everything Phase 2 projects
    -- is 'declared': the provider's configuration says so. Nothing produces
    -- 'observed' -- no CloudTrail collector exists -- and writing it would
    -- claim we saw something happen.
    basis             text NOT NULL DEFAULT 'declared',
    derivation_rule   text NOT NULL DEFAULT '',

    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,
    ended_reason      text NOT NULL DEFAULT '',
    source_key        text NOT NULL,

    -- Partition membership, stored not inferred. See 030's note -- a
    -- relationship written without these is invisible to reconciliation and
    -- never ends.
    partition_key     text NOT NULL DEFAULT '',
    connector_id      uuid,

    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_relationship_pkey PRIMARY KEY (id),
    CONSTRAINT iga_relationship_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_workspace_id_key UNIQUE (workspace_id, id),

    -- Every endpoint is typed AND workspace-qualified. This is the A3 rule
    -- applied on both ends at once, which is what §6.6 means by "A3 is closed
    -- on both ends".
    CONSTRAINT iga_rel_src_identity_fkey
        FOREIGN KEY (workspace_id, source_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_src_workload_fkey
        FOREIGN KEY (workspace_id, source_workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_src_instance_fkey
        FOREIGN KEY (workspace_id, source_agent_instance_id)
        REFERENCES public.iga_agent_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_identity_fkey
        FOREIGN KEY (workspace_id, target_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_workload_fkey
        FOREIGN KEY (workspace_id, target_workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_agent_fkey
        FOREIGN KEY (workspace_id, target_agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,

    -- §2.9: provenance is workspace-qualified too, not just endpoints.
    CONSTRAINT iga_relationship_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_by),
    CONSTRAINT iga_relationship_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id)
        ON DELETE SET NULL (connector_id),

    -- Exactly one source and exactly one target, always. 034 widens the source
    -- arm to four when it adds external principals.
    CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id IS NOT NULL)::int
      + (source_workload_id         IS NOT NULL)::int
      + (source_agent_instance_id   IS NOT NULL)::int = 1),
    CONSTRAINT iga_relationship_target_chk CHECK (
        (target_identity_account_id IS NOT NULL)::int
      + (target_workload_id         IS NOT NULL)::int
      + (target_agent_id            IS NOT NULL)::int = 1),

    -- The legal (source, type, target) triples, ENUMERATED.
    --
    -- The ELSE arm is load-bearing: a new relationship_type cannot be inserted
    -- until someone widens this constraint deliberately, and that widening is
    -- the review point. Without it, a typo in relationship_type would insert
    -- happily and reconcile never.
    --
    -- This is redundant with the exactly-one CHECKs above for the three
    -- current types. Keep both: the pair CHECK's ELSE false gates new types,
    -- and the exactly-one CHECKs stay correct no matter how the pair CHECK is
    -- later widened.
    CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as' THEN
                source_workload_id IS NOT NULL
                AND target_identity_account_id IS NOT NULL
            WHEN 'can_assume' THEN
                source_identity_account_id IS NOT NULL
                AND target_identity_account_id IS NOT NULL
            WHEN 'realizes' THEN
                source_agent_instance_id IS NOT NULL
                AND target_workload_id IS NOT NULL
            ELSE false
        END),

    CONSTRAINT iga_relationship_basis_chk CHECK (
        basis IN ('declared', 'observed', 'derived', 'asserted')),
    CONSTRAINT iga_relationship_derivation_chk CHECK (
        basis <> 'derived' OR derivation_rule <> ''),
    CONSTRAINT iga_relationship_state_chk CHECK (
        state IN ('current', 'stale', 'ended')),
    CONSTRAINT iga_relationship_ended_chk CHECK (
        (state = 'ended') = (valid_to IS NOT NULL)),
    CONSTRAINT iga_relationship_ended_reason_chk CHECK (
        (state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_relationship_source_key_chk CHECK (source_key <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_relationship_live
    ON public.iga_relationship (workspace_id, source_key) WHERE state <> 'ended';

CREATE INDEX IF NOT EXISTS idx_iga_relationship_source
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(source_identity_account_id, source_workload_id, source_agent_instance_id));

CREATE INDEX IF NOT EXISTS idx_iga_relationship_target
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(target_identity_account_id, target_workload_id, target_agent_id));

CREATE INDEX IF NOT EXISTS idx_iga_relationship_partition
    ON public.iga_relationship (workspace_id, connector_id, partition_key)
    WHERE state <> 'ended';

COMMENT ON TABLE public.iga_relationship IS
    'Binary structural edges with typed endpoints on BOTH ends. Three types in '
    'Phase 2: executes_as (workload -> identity, from cloud_workload.'
    'identity_id), can_assume (identity -> identity, from cloud_assume_edge), '
    'realizes (agent instance -> workload). What an edge MAY CLAIM is §2.3: '
    'executes_as means a configured execution identity, never that it ran; '
    'can_assume means trust permits assumption, never that assumption '
    'succeeds.';

COMMENT ON COLUMN public.iga_relationship.basis IS
    'declared = provider configuration says so. observed = we saw it happen, '
    'with attribution. derived = we computed it, naming the rule and its '
    'inputs. asserted = a human decided it, with authority recorded. '
    'Everything Phase 2 projects is declared.';

-- verify ---------------------------------------------------------------------
SELECT count(*) FILTER (WHERE conname = 'iga_relationship_pair_chk')   AS pair_chk,
       count(*) FILTER (WHERE conname = 'iga_relationship_source_chk') AS source_chk,
       count(*) FILTER (WHERE conname = 'iga_relationship_target_chk') AS target_chk
  FROM pg_constraint
 WHERE conrelid = 'public.iga_relationship'::regclass;
