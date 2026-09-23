-- ============================================================================
-- 032: evidence junctions, and per-source support for shared nodes.
--
-- SPEC-iga-phase2-graph.md §2.10B, §4.8.
--
-- Two things that look unrelated and are the same idea: an edge's belief has
-- to point at the observations that support it, and a node's existence has to
-- point at the sources that still support it. Both are "who says so", stored
-- rather than inferred.
-- ============================================================================

-- evidence junctions ---------------------------------------------------------
-- Both endpoints typed and FK'd, unlike iga_observation_links, which keeps its
-- polymorphic target_kind/target_id for the GitHub path. P2-1's CI check
-- forbids new writers to that table.

CREATE TABLE IF NOT EXISTS public.iga_access_edge_evidence (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    access_edge_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    relation       text NOT NULL DEFAULT 'supports',
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_access_edge_evidence_pkey PRIMARY KEY (id),
    CONSTRAINT iga_access_edge_evidence_edge_fkey
        FOREIGN KEY (workspace_id, access_edge_id)
        REFERENCES public.iga_access_edges (workspace_id, id) ON DELETE CASCADE,

    -- RESTRICT IS NOW SAFE, and was not before. 024 changed cloud_observation's
    -- subject FKs from CASCADE to SET NULL, so inventory deletion no longer
    -- cascades into the observations -- which means this constraint can no
    -- longer block reconciliation. Before 024 this exact constraint would have
    -- deadlocked it: reconciliation deletes stale inventory, the cascade
    -- deleted the observations, and RESTRICT here refused the delete.
    CONSTRAINT iga_access_edge_evidence_obs_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE RESTRICT,

    CONSTRAINT iga_access_edge_evidence_relation_chk CHECK (
        relation IN ('supports', 'contradicts', 'supersedes', 'previously_supported')),
    CONSTRAINT iga_access_edge_evidence_key
        UNIQUE (workspace_id, access_edge_id, observation_id, relation)
);

CREATE INDEX IF NOT EXISTS idx_iga_access_edge_evidence_edge
    ON public.iga_access_edge_evidence (workspace_id, access_edge_id);

CREATE TABLE IF NOT EXISTS public.iga_relationship_evidence (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    relationship_id uuid NOT NULL,
    observation_id  uuid NOT NULL,
    relation        text NOT NULL DEFAULT 'supports',
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_relationship_evidence_pkey PRIMARY KEY (id),
    CONSTRAINT iga_relationship_evidence_rel_fkey
        FOREIGN KEY (workspace_id, relationship_id)
        REFERENCES public.iga_relationship (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_evidence_obs_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_relationship_evidence_relation_chk CHECK (
        relation IN ('supports', 'contradicts', 'supersedes', 'previously_supported')),
    CONSTRAINT iga_relationship_evidence_key
        UNIQUE (workspace_id, relationship_id, observation_id, relation)
);

CREATE INDEX IF NOT EXISTS idx_iga_relationship_evidence_rel
    ON public.iga_relationship_evidence (workspace_id, relationship_id);

-- per-source support ---------------------------------------------------------
-- §2.10B. A resource, and a managed-policy entitlement, can be supported by
-- SEVERAL connectors at once: accounts A and B both attach RefundS3Access,
-- both name the same bucket. Recording one connector_id and one
-- last_confirmed_run_id ON THE NODE makes the most recent scanner its apparent
-- owner, and then:
--
--     A and B both support entitlement E
--     B scans last, so E records B as its membership
--     B detaches the policy
--     B's reconciliation retires E -- while A still holds it
--
-- Serialization does not help; that sequence is already sequential and still
-- wrong. So object identity and source support are separate rows.
--
-- Reconciliation acts on SUPPORT ROWS, never on nodes directly: B's scan ends
-- B's support and touches nothing of A's. A node's lifecycle is DERIVED, in
-- the same transaction, after support reconciliation -- active while any
-- support is current or stale, retired with retired_reason='unsupported' only
-- when EVERY support has ended.
--
-- This is why nodes carry no connector_id and edges do (030, 031): an access
-- edge's subject is an identity in one account, an executes_as joins a
-- workload and identity in one account, and a can_assume edge is evidenced by
-- exactly one trust policy. None is multiply-supported.
CREATE TABLE IF NOT EXISTS public.iga_object_support (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    -- identity | workload | resource | entitlement | agent. Deliberately a
    -- discriminator rather than five typed columns: this is a MEMBERSHIP
    -- record about who still vouches for a row, not a claim about the graph,
    -- and reconciliation reads it one object_type at a time.
    object_type   text NOT NULL,
    object_id     uuid NOT NULL,
    connector_id  uuid NOT NULL,
    partition_key text NOT NULL,

    state         text NOT NULL DEFAULT 'current',
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_run_id uuid,
    last_confirmed_at     timestamptz,
    ended_reason  text NOT NULL DEFAULT '',

    CONSTRAINT iga_object_support_pkey PRIMARY KEY (id),
    CONSTRAINT iga_object_support_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_object_support_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    -- §2.9 again: provenance is workspace-qualified even here.
    CONSTRAINT iga_object_support_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_run_id),

    CONSTRAINT iga_object_support_type_chk CHECK (
        object_type IN ('identity', 'workload', 'resource', 'entitlement', 'agent')),
    CONSTRAINT iga_object_support_state_chk CHECK (
        state IN ('current', 'stale', 'ended')),
    CONSTRAINT iga_object_support_ended_chk CHECK (
        (state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_object_support_key
        UNIQUE (workspace_id, object_type, object_id, connector_id, partition_key)
);

-- The query retireUnsupported runs: "does this object have any support left?"
CREATE INDEX IF NOT EXISTS idx_iga_object_support_object
    ON public.iga_object_support (workspace_id, object_type, object_id, state);

-- The query reconcileNodes runs: "what did this partition support?"
CREATE INDEX IF NOT EXISTS idx_iga_object_support_partition
    ON public.iga_object_support (workspace_id, object_type, connector_id, partition_key)
    WHERE state <> 'ended';

COMMENT ON TABLE public.iga_object_support IS
    'One row per (object, connector, partition). Reconciliation ends SUPPORT; '
    'a node retires only when every support of it has ended. The node-side '
    'analogue of a partition membership column, and the reason nodes cannot '
    'simply carry one.';

-- verify ---------------------------------------------------------------------
SELECT count(*) AS tables_created
  FROM information_schema.tables
 WHERE table_schema = 'public'
   AND table_name IN ('iga_access_edge_evidence', 'iga_relationship_evidence',
                      'iga_object_support');
