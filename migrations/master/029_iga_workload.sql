-- ============================================================================
-- 029: iga_workload -- the runtime, missing from the canonical model.
--
-- SPEC-iga-phase2-graph.md §2.4. cloud_workload has existed since 015 and has
-- no canonical counterpart, so the graph has had nowhere to say "this Lambda
-- runs as this role". That edge is the whole point of an agent-aware model:
-- an identity nobody runs as and a runtime nobody can attribute are different
-- findings.
--
-- A WORKLOAD IS NOT AN AGENT INSTANCE. An instance may not be compute at all
-- (a published SaaS agent, a Bedrock alias), and compute is frequently not an
-- agent. Where a Bedrock agent IS the runtime, the projector writes BOTH rows
-- and links them with a `realizes` relationship (031) rather than collapsing
-- them -- collapsing would make "this agent runs on this runtime" inexpressible
-- the moment one agent has two runtimes.
--
-- New table, so source_key is NOT NULL with a non-empty CHECK from the start:
-- the DEFAULT '' allowance in 028 exists only for rows that predate the graph,
-- and nothing predates this table.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_workload (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    estate_scope_id uuid,

    -- The provider's own runtime name: lambda_function, ecs_task_definition,
    -- ec2_instance, bedrock_agent. Text, not an enum -- a new AWS compute
    -- service must not need a migration (015's rule, kept).
    runtime_kind    text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    stage           text NOT NULL DEFAULT 'unknown',
    lifecycle       text NOT NULL DEFAULT 'active',
    retired_reason  text NOT NULL DEFAULT '',

    source_key      text NOT NULL,
    continuity      text NOT NULL DEFAULT 'recognition_only',
    immutable_key   text NOT NULL DEFAULT '',
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_workload_pkey PRIMARY KEY (id),
    CONSTRAINT iga_workload_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- Column-list SET NULL: dropping a scope must clear the scope, never the
    -- workspace that scopes the row.
    CONSTRAINT iga_workload_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id)
        ON DELETE SET NULL (estate_scope_id),

    CONSTRAINT iga_workload_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_workload_lifecycle_chk CHECK (
        lifecycle IN ('active', 'retired', 'tombstoned')),
    CONSTRAINT iga_workload_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    CONSTRAINT iga_workload_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> ''),
    CONSTRAINT iga_workload_source_key_chk CHECK (source_key <> ''),
    CONSTRAINT iga_workload_retired_chk CHECK (
        (lifecycle = 'retired') = (retired_reason <> '')),

    -- NOT decoration: this is the target every composite FK in 031 and 033
    -- needs. Without it, REFERENCES iga_workload (workspace_id, id) cannot
    -- apply at all.
    CONSTRAINT iga_workload_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_workload_source_key
    ON public.iga_workload (workspace_id, source_key)
    WHERE lifecycle <> 'retired';

CREATE INDEX IF NOT EXISTS idx_iga_workload_scope
    ON public.iga_workload (workspace_id, estate_scope_id, runtime_kind);

COMMENT ON TABLE public.iga_workload IS
    'Canonical runtime, projected one-way from cloud_workload. Not an agent '
    'instance: an instance may not be compute at all. Where a Bedrock agent IS '
    'the runtime the projector writes both rows and a realizes relationship.';

COMMENT ON COLUMN public.iga_workload.continuity IS
    'Always recognition_only for the runtime kinds Phase 2 collects. No AWS '
    'compute surface the collector reads records a creation-boundary id in '
    'AWSWorkloadAttrs, so a Lambda deleted and recreated under the same name '
    'continues as ONE object -- and the console says recognition_only rather '
    'than implying we checked.';

-- Unresolved execution role (§4.7) --------------------------------------------
--
-- What we know about the role a workload acts as, WHEN THERE IS NO
-- executes_as EDGE to say it. A bare "ARN or empty" cannot distinguish the
-- four cases the Identities view has to word differently, and collapsing them
-- made a configured role silently vanish from the customer's view: both
-- "no role configured" and "role configured but its identity was not in this
-- scan" rendered as nothing at all.
ALTER TABLE public.iga_workload
    ADD COLUMN IF NOT EXISTS execution_role_state text NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS execution_role_arn   text NOT NULL DEFAULT '';

ALTER TABLE public.iga_workload
    ADD CONSTRAINT iga_workload_exec_role_state_chk CHECK (execution_role_state IN
        ('resolved',          -- an executes_as edge exists; the ARN is on the edge
         'not_in_scan',       -- configured and known; its identity absent from this run
         'not_in_inventory',  -- configured; matches no identity we hold
         'none')),            -- no role configured
    -- The ARN is present EXACTLY when it is the only place the role is
    -- recorded. resolved keeps it on the edge; none has none to keep.
    ADD CONSTRAINT iga_workload_exec_role_arn_chk CHECK (
        (execution_role_state IN ('not_in_scan','not_in_inventory')) = (execution_role_arn <> ''));

COMMENT ON COLUMN public.iga_workload.execution_role_state IS
    'Read this, never the absence of an executes_as edge: none = no role '
    'configured (a real finding); not_in_inventory = runs as <arn>, matches no '
    'identity we hold; not_in_scan = runs as <arn>, not read in the latest '
    'scan; resolved = the edge carries it.';

-- Classification (§2.14.3) ----------------------------------------------------
--
-- What a workload IS, as opposed to what it runs as. provider_native_agent is
-- derived from the provider (a Bedrock agent is one by construction) and is
-- NOT human-editable; classified_agent is a person's decision and carries a
-- decision record.
ALTER TABLE public.iga_workload
    ADD COLUMN IF NOT EXISTS classification text NOT NULL DEFAULT 'unclassified',
    -- Optimistic-concurrency token for the classify endpoint: a decision made
    -- against a stale view is rejected rather than silently overwriting a
    -- newer one.
    ADD COLUMN IF NOT EXISTS classification_version bigint NOT NULL DEFAULT 0;

ALTER TABLE public.iga_workload
    ADD CONSTRAINT iga_workload_classification_chk CHECK (
        classification IN ('unclassified', 'provider_native_agent', 'classified_agent'));

-- The decision record. Same pattern as iga_classification_candidates (004),
-- which cannot be reused directly: its subject FKs to iga_source_objects, the
-- GitHub path's entity, not to a workload.
CREATE TABLE IF NOT EXISTS public.iga_workload_classification (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    workload_id   uuid NOT NULL,
    decision      text NOT NULL,   -- classified_agent | unclassified (an undo)
    purpose       text NOT NULL DEFAULT '',
    -- The USER id, never the email: an email is a display string that can be
    -- reassigned, and a decision record has to survive that.
    decided_by    text NOT NULL,
    decided_at    timestamptz NOT NULL DEFAULT now(),
    reason        text NOT NULL DEFAULT '',

    CONSTRAINT iga_workload_classification_pkey PRIMARY KEY (id),
    CONSTRAINT iga_wc_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_wc_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wc_decision_chk CHECK (decision IN ('classified_agent', 'unclassified')),
    CONSTRAINT iga_wc_decided_by_chk CHECK (decided_by <> '')
);

CREATE INDEX IF NOT EXISTS idx_iga_workload_classification_workload
    ON public.iga_workload_classification (workspace_id, workload_id, decided_at DESC);

-- verify ---------------------------------------------------------------------
SELECT count(*) AS iga_workload_created
  FROM information_schema.tables
 WHERE table_schema = 'public' AND table_name = 'iga_workload';
