-- ============================================================================
-- 029: iga_workload, execution-role state, classification
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_workload (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    estate_scope_id uuid,
    provider        text NOT NULL DEFAULT 'aws',
    runtime_kind    text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    region          text NOT NULL DEFAULT '',
    stage           text NOT NULL DEFAULT 'unknown',
    lifecycle       text NOT NULL DEFAULT 'active',
    retired_reason  text NOT NULL DEFAULT '',
    source_key      text NOT NULL,
    continuity      text NOT NULL DEFAULT 'recognition_only',
    immutable_key   text NOT NULL DEFAULT '',
    provider_attrs  jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- What we know about the role the workload runs as, when there is no
    -- executes_as edge to say it. Written on every pass (§4.6).
    execution_role_state text NOT NULL DEFAULT 'none',
    execution_role_arn   text NOT NULL DEFAULT '',

    -- Human-owned; the projector writes provider_native_agent on insert only.
    classification         text   NOT NULL DEFAULT 'unclassified',
    classification_version bigint NOT NULL DEFAULT 0,

    CONSTRAINT iga_workload_pkey PRIMARY KEY (id),
    CONSTRAINT iga_workload_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_workload_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_workload_stage_chk CHECK (stage IN ('production','non_production','unknown')),
    CONSTRAINT iga_workload_lifecycle_chk CHECK (lifecycle IN ('active','retired','tombstoned')),
    CONSTRAINT iga_workload_retired_chk CHECK ((lifecycle = 'retired') = (retired_reason <> '')),
    CONSTRAINT iga_workload_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    CONSTRAINT iga_workload_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> ''),
    CONSTRAINT iga_workload_source_key_chk CHECK (source_key <> ''),
    CONSTRAINT iga_workload_exec_role_state_chk CHECK (execution_role_state IN
        ('resolved','not_in_scan','not_in_inventory','none')),
    CONSTRAINT iga_workload_exec_role_arn_chk CHECK (
        (execution_role_state IN ('not_in_scan','not_in_inventory')) = (execution_role_arn <> '')),
    CONSTRAINT iga_workload_classification_chk CHECK (
        classification IN ('unclassified','provider_native_agent','classified_agent')),
    CONSTRAINT iga_workload_workspace_id_key UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_workload_source_key
    ON public.iga_workload (workspace_id, source_key) WHERE lifecycle <> 'retired';
-- Default list order (§5.3) and the classification filter.
CREATE INDEX IF NOT EXISTS idx_iga_workload_list
    ON public.iga_workload (workspace_id, lifecycle, lower(display_name), id);
CREATE INDEX IF NOT EXISTS idx_iga_workload_classification
    ON public.iga_workload (workspace_id, classification, lower(display_name), id);

-- The decision record. Human decisions are never rows the projector writes.
CREATE TABLE IF NOT EXISTS public.iga_workload_classification (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    workload_id           uuid NOT NULL,
    operation_id          uuid NOT NULL,   -- client-generated, one per intent (§5.5)
    decision              text NOT NULL,   -- classified_agent | unclassified
    previous              text NOT NULL,
    purpose               text NOT NULL DEFAULT '',
    reason                text NOT NULL,
    decided_by_user_id    uuid NOT NULL,   -- stable identity; never an email
    against_version       bigint NOT NULL, -- the classification_version it was made against
    request_hash          text NOT NULL,   -- sha256(workload, actor, decision, purpose, reason, expected_version, undoes)
    result_version        bigint NOT NULL,
    undoes_decision_id    uuid,
    decided_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_workload_classification_pkey PRIMARY KEY (id),
    CONSTRAINT iga_wc_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wc_decision_chk CHECK (decision IN ('classified_agent','unclassified')),
    CONSTRAINT iga_wc_reason_chk CHECK (reason <> ''),
    CONSTRAINT iga_wc_operation_key UNIQUE (workspace_id, operation_id),
    CONSTRAINT iga_wc_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_wc_undoes_fkey FOREIGN KEY (workspace_id, undoes_decision_id)
        REFERENCES public.iga_workload_classification (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS idx_iga_wc_workload
    ON public.iga_workload_classification (workspace_id, workload_id, decided_at DESC);

-- One counter per workspace, bumped in every decision transaction. List
-- cursors that filter or sort on classification bind to it (§5.5).
CREATE TABLE IF NOT EXISTS public.iga_classification_clock (
    workspace_id uuid NOT NULL,
    seq          bigint NOT NULL DEFAULT 0,
    CONSTRAINT iga_classification_clock_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT iga_classification_clock_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE
);
