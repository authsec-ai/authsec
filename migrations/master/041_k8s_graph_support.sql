-- 041_k8s_graph_support.sql — Kubernetes joins the evidence and reconciliation
-- pipeline.
--
-- expand only.
--
-- WHAT 038 AND 040 LEFT UNFINISHED
-- Those two widened CHECKs so Kubernetes rows could be WRITTEN into the shared
-- iga_* graph. They did nothing about rows being RETIRED, and the projector
-- that followed writes every row 'current'/'active' and never ends anything.
-- A RoleBinding deleted in the cluster therefore stays in the graph forever,
-- and the product reports access that no longer exists. For an IGA product
-- that is the worst available failure: the one answer a reviewer acts on.
--
-- SPEC-iga-phase2-graph §2.7 already says how absence is decided, and §2.10B
-- already has the table that records it -- iga_object_support. Kubernetes could
-- not use it, for one structural reason:
--
--     connector_id uuid NOT NULL
--         REFERENCES cloud_connector (workspace_id, id)
--     last_confirmed_run_id uuid
--         REFERENCES cloud_scan_run (workspace_id, id)
--
-- Kubernetes has neither a cloud_connector nor a cloud_scan_run. It has a
-- discovery_sources row and an in-cluster agent that pushes snapshots.
--
-- So this migration does exactly what §2.1 prescribes for a new endpoint type
-- -- "one migration that adds a column and widens the constraints" -- and adds
-- the sweep record that makes a Kubernetes absence check provable.
--
-- WHY A SWEEP TABLE AND NOT A BOOLEAN ON THE SNAPSHOT
-- §2.7 condition 3 is that the partition's source surface was read BY THAT RUN,
-- "because content dedupe means the absence of a fresh observation row proves
-- nothing". The same hazard exists here and is worse: the agent reports a
-- snapshot, not a diff, and two identical snapshots are indistinguishable. A
-- durable sweep row with a generation is what lets a support row name the
-- reading that last confirmed it.

-- 1. §2.9 prerequisite -------------------------------------------------------
-- No single-column foreign key to a workspace-scoped table. discovery_sources
-- is about to be referenced, so it needs the workspace-qualified unique first.
ALTER TABLE public.discovery_sources
    DROP CONSTRAINT IF EXISTS discovery_sources_workspace_id_key;
ALTER TABLE public.discovery_sources
    ADD CONSTRAINT discovery_sources_workspace_id_key UNIQUE (workspace_id, id);

-- 2. The sweep record --------------------------------------------------------
-- The Kubernetes counterpart of cloud_scan_run. Deliberately NOT a reuse of
-- cloud_scan_run: that table is keyed to a cloud_connector and carries AWS
-- region coverage, and borrowing it would put rows in a table every AWS query
-- in the codebase reads.
CREATE TABLE IF NOT EXISTS public.iga_k8s_sweep (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    discovery_source_id uuid NOT NULL,
    cluster             text NOT NULL,

    -- Monotonic per (workspace, source, cluster). The projector fences its
    -- writes and its retirements to the generation it claimed, so a snapshot
    -- that arrives mid-projection cannot have its rows closed by the older
    -- reading that is still running (§2.8).
    generation bigint NOT NULL,

    scan_kind text NOT NULL DEFAULT 'rbac',

    -- The three facts that decide whether absence means anything (§2.7).
    --
    -- complete       -- every LIST in the sweep succeeded
    -- cluster_scoped -- ClusterRoles and ClusterRoleBindings were readable.
    --                   This is not a smaller answer than a namespaced sweep,
    --                   it is a different one: cluster-scoped bindings are
    --                   where the dangerous grants are.
    -- namespaces     -- the exact scope swept. Absence outside it proves
    --                   nothing, so it is stored, not recomputed.
    complete       boolean NOT NULL DEFAULT false,
    cluster_scoped boolean NOT NULL DEFAULT false,
    namespaces     text[]  NOT NULL DEFAULT '{}',

    sweep_started_at timestamptz NOT NULL,
    observed_at      timestamptz NOT NULL,
    received_at      timestamptz NOT NULL DEFAULT now(),

    -- received -> projected | failed. A sweep is never deleted; a failed
    -- projection leaves the previous graph standing.
    status      text NOT NULL DEFAULT 'received',
    projected_at timestamptz,
    error        text NOT NULL DEFAULT '',

    CONSTRAINT iga_k8s_sweep_pkey PRIMARY KEY (id),
    CONSTRAINT iga_k8s_sweep_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_k8s_sweep_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE,

    -- §2.9: this table is itself referenced, workspace-qualified.
    CONSTRAINT iga_k8s_sweep_workspace_id_key UNIQUE (workspace_id, id),

    CONSTRAINT iga_k8s_sweep_generation_key
        UNIQUE (workspace_id, discovery_source_id, cluster, generation),

    CONSTRAINT iga_k8s_sweep_status_chk
        CHECK (status IN ('received', 'projected', 'failed')),
    CONSTRAINT iga_k8s_sweep_cluster_chk CHECK (cluster <> ''),

    -- An incomplete sweep may never be the one that retires anything. The
    -- check keeps that from depending on a projector branch being right.
    CONSTRAINT iga_k8s_sweep_projected_chk
        CHECK ((status = 'projected') = (projected_at IS NOT NULL)),
    CONSTRAINT iga_k8s_sweep_error_chk
        CHECK ((status = 'failed') = (error <> ''))
);

CREATE INDEX IF NOT EXISTS idx_iga_k8s_sweep_latest
    ON public.iga_k8s_sweep (workspace_id, discovery_source_id, cluster, generation DESC);

-- 3. iga_object_support learns a second kind of source ------------------------
ALTER TABLE public.iga_object_support
    ALTER COLUMN connector_id DROP NOT NULL;

ALTER TABLE public.iga_object_support
    ADD COLUMN IF NOT EXISTS discovery_source_id uuid,
    ADD COLUMN IF NOT EXISTS last_confirmed_sweep_id uuid;

ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_os_discovery_source_fkey;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_os_discovery_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE;

ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_os_sweep_fkey;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_os_sweep_fkey
        FOREIGN KEY (workspace_id, last_confirmed_sweep_id)
        REFERENCES public.iga_k8s_sweep (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_sweep_id);

-- Exactly one source. A support row with neither is unattributable; a row with
-- both would be counted twice by §2.10B's multi-source support.
ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_object_support_source_chk;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_object_support_source_chk CHECK (
        (connector_id IS NOT NULL)::int + (discovery_source_id IS NOT NULL)::int = 1);

-- A confirming reading belongs to the same kind of source that supports the row.
ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_object_support_confirm_chk;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_object_support_confirm_chk CHECK (
        (last_confirmed_run_id   IS NULL OR connector_id        IS NOT NULL)
    AND (last_confirmed_sweep_id IS NULL OR discovery_source_id IS NOT NULL));

-- 4. The uniqueness that the upserts conflict on ------------------------------
-- The five indexes from 032/036 discriminate on connector_id. With it nullable
-- they would stop deduplicating Kubernetes rows entirely, because Postgres
-- treats NULLs as distinct in a unique index -- every sweep would insert a new
-- support row for the same object and the multi-source count in §2.10B would
-- climb forever.
--
-- source_ref collapses the two columns into the one that is always present.
-- STORED and generated, so no writer can set it inconsistently, and a plain
-- column so ON CONFLICT can name it without an expression.
ALTER TABLE public.iga_object_support
    ADD COLUMN IF NOT EXISTS source_ref uuid
        GENERATED ALWAYS AS (COALESCE(connector_id, discovery_source_id)) STORED;

DROP INDEX IF EXISTS public.uq_iga_os_identity;
DROP INDEX IF EXISTS public.uq_iga_os_workload;
DROP INDEX IF EXISTS public.uq_iga_os_resource;
DROP INDEX IF EXISTS public.uq_iga_os_entitlement;
DROP INDEX IF EXISTS public.uq_iga_os_policy;

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_identity
    ON public.iga_object_support (workspace_id, identity_account_id, source_ref, partition_key)
    WHERE identity_account_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_workload
    ON public.iga_object_support (workspace_id, workload_id, source_ref, partition_key)
    WHERE workload_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_resource
    ON public.iga_object_support (workspace_id, resource_id, source_ref, partition_key)
    WHERE resource_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_entitlement
    ON public.iga_object_support (workspace_id, entitlement_id, source_ref, partition_key)
    WHERE entitlement_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_policy
    ON public.iga_object_support (workspace_id, policy_id, source_ref, partition_key)
    WHERE policy_id IS NOT NULL;

-- 5. Edges learn the same second provenance -----------------------------------
-- iga_policy_assignment and iga_access_edges already carry partition_key,
-- state, valid_to and ended_reason -- everything reconciliation needs -- but
-- their provenance columns point at AWS: connector_id -> cloud_connector and
-- last_confirmed_by -> cloud_scan_run. A Kubernetes binding can set neither,
-- so today its rows carry no evidence of WHICH reading last confirmed them.
--
-- Without that column the reconciler cannot express "this sweep looked here and
-- did not see it" and would have to fall back on "no row was written this
-- time", which is the content-dedupe trap §2.7 condition 3 names explicitly.
ALTER TABLE public.iga_policy_assignment
    ADD COLUMN IF NOT EXISTS discovery_source_id uuid,
    ADD COLUMN IF NOT EXISTS last_confirmed_sweep_id uuid;

ALTER TABLE public.iga_policy_assignment
    DROP CONSTRAINT IF EXISTS iga_pa_discovery_source_fkey;
ALTER TABLE public.iga_policy_assignment
    ADD CONSTRAINT iga_pa_discovery_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE;

ALTER TABLE public.iga_policy_assignment
    DROP CONSTRAINT IF EXISTS iga_pa_sweep_fkey;
ALTER TABLE public.iga_policy_assignment
    ADD CONSTRAINT iga_pa_sweep_fkey
        FOREIGN KEY (workspace_id, last_confirmed_sweep_id)
        REFERENCES public.iga_k8s_sweep (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_sweep_id);

ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS discovery_source_id uuid,
    ADD COLUMN IF NOT EXISTS last_confirmed_sweep_id uuid;

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_discovery_source_fkey;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_discovery_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE;

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_sweep_fkey;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_sweep_fkey
        FOREIGN KEY (workspace_id, last_confirmed_sweep_id)
        REFERENCES public.iga_k8s_sweep (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_sweep_id);

-- A Kubernetes row may not claim an AWS reading confirmed it, and the reverse.
-- Not a style rule: last_confirmed_* is what every retirement query compares
-- against, so a row pointing at the wrong kind of reading is never retired.
ALTER TABLE public.iga_policy_assignment
    DROP CONSTRAINT IF EXISTS iga_pa_confirm_provider_chk;
-- iga_policy_assignment carries no provider column -- it discriminates by
-- assignment_kind, which 038 widened for Kubernetes. That is the more precise
-- test anyway: it names the two kinds a Kubernetes sweep can write.
ALTER TABLE public.iga_policy_assignment
    ADD CONSTRAINT iga_pa_confirm_provider_chk CHECK (
        assignment_kind NOT IN ('k8s_role_binding', 'k8s_cluster_role_binding')
        OR last_confirmed_by IS NULL);

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_confirm_provider_chk;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_confirm_provider_chk CHECK (
        provider <> 'k8s' OR last_confirmed_by IS NULL);

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    n integer;
BEGIN
    -- connector_id must now be optional, or no Kubernetes support row can exist.
    SELECT count(*) INTO n FROM information_schema.columns
     WHERE table_name = 'iga_object_support' AND column_name = 'connector_id'
       AND is_nullable = 'YES';
    IF n <> 1 THEN
        RAISE EXCEPTION '041: iga_object_support.connector_id is still NOT NULL';
    END IF;

    -- source_ref must be generated, not merely present: a writable column here
    -- would let the two sources disagree and silently break deduplication.
    SELECT count(*) INTO n FROM information_schema.columns
     WHERE table_name = 'iga_object_support' AND column_name = 'source_ref'
       AND is_generated = 'ALWAYS';
    IF n <> 1 THEN
        RAISE EXCEPTION '041: iga_object_support.source_ref is not a generated column';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conname IN ('iga_object_support_source_chk',
                       'iga_object_support_confirm_chk',
                       'iga_k8s_sweep_generation_key');
    IF n <> 3 THEN
        RAISE EXCEPTION '041: expected 3 new constraints, found %', n;
    END IF;

    SELECT count(*) INTO n FROM information_schema.columns
     WHERE table_name IN ('iga_policy_assignment', 'iga_access_edges')
       AND column_name = 'last_confirmed_sweep_id';
    IF n <> 2 THEN
        RAISE EXCEPTION '041: edge tables did not gain last_confirmed_sweep_id (found %)', n;
    END IF;

    SELECT count(*) INTO n FROM pg_indexes
     WHERE schemaname = 'public'
       AND indexname IN ('uq_iga_os_identity', 'uq_iga_os_workload',
                         'uq_iga_os_resource', 'uq_iga_os_entitlement',
                         'uq_iga_os_policy')
       AND indexdef LIKE '%source_ref%';
    IF n <> 5 THEN
        RAISE EXCEPTION '041: expected 5 support indexes on source_ref, found %', n;
    END IF;
END $$;
