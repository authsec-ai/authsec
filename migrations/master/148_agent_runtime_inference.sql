-- ============================================================================
-- 148: agent runtime inference on AWS (SPEC-agent-runtime-visibility.md
-- §5.2, §5.3, §5.5, §10 Q1/Q2).
--
-- 1. agent_suggestion: one row per workload INCARNATION (iga_workload id) that
--    rule aws_agent_suggest_v1 proposed as a likely agent. A suggestion never
--    sets classification: Confirm runs the existing classification decision
--    (iga_workload_classification) and closes the row in the same
--    transaction; Dismiss records who, when and why, and the row stays
--    dismissed, so the incarnation is never proposed again. A workload that
--    is classified elsewhere, or whose role becomes shared (§10 Q1), is
--    superseded.
-- 2. agent_finding: risky credentials and identities of AI workloads (§5.5):
--    shared_role, human_credentials, long_lived_key, model_key_secret. One row
--    per (workspace, kind, subject key); open while the latest inference of
--    its connector sees it, resolved when it no longer does.
--
-- Evidence columns hold references (cloud_usage / cloud_observation ids) and
-- summary numbers, never a secret value, a prompt or a response.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_suggestion (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid        NOT NULL,
    -- The workload incarnation (iga_workload is one row per incarnation).
    workload_id    uuid        NOT NULL,
    -- The account whose evidence proposed it.
    connector_id   uuid        NOT NULL,
    -- The identity whose model calls are the evidence (cloud_identity).
    identity_id    uuid,
    rule           text        NOT NULL,
    rule_version   integer     NOT NULL,
    evidence       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state          text        NOT NULL DEFAULT 'pending',
    -- The deciding user (confirmed, dismissed); NULL for a superseded row,
    -- which the system closed. A user id, never an email.
    decided_by     uuid,
    decided_at     timestamptz,
    -- Dismiss: the person's reason. Confirm: the classification reason.
    -- Superseded: classified | shared_role.
    reason         text        NOT NULL DEFAULT '',
    -- Confirm: the classification decision it ran (same transaction).
    decision_id    uuid,
    operation_id   uuid,
    version        integer     NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_suggestion_pkey PRIMARY KEY (id),
    CONSTRAINT agent_suggestion_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_suggestion_workspace_id_key UNIQUE (workspace_id, id),
    -- One row per incarnation: a dismissed row is never replaced.
    CONSTRAINT agent_suggestion_workload_key UNIQUE (workspace_id, workload_id),
    CONSTRAINT agent_suggestion_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_suggestion_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_suggestion_identity_fkey FOREIGN KEY (identity_id)
        REFERENCES public.cloud_identity (id) ON DELETE SET NULL,
    CONSTRAINT agent_suggestion_decision_fkey FOREIGN KEY (workspace_id, decision_id)
        REFERENCES public.iga_workload_classification (workspace_id, id),
    CONSTRAINT agent_suggestion_state_chk
        CHECK (state IN ('pending', 'confirmed', 'dismissed', 'superseded')),
    CONSTRAINT agent_suggestion_rule_chk CHECK (rule <> '' AND rule_version > 0),
    CONSTRAINT agent_suggestion_version_chk CHECK (version > 0),
    CONSTRAINT agent_suggestion_decided_chk
        CHECK ((state = 'pending') = (decided_at IS NULL)),
    CONSTRAINT agent_suggestion_decider_chk
        CHECK (state NOT IN ('confirmed', 'dismissed') OR decided_by IS NOT NULL),
    CONSTRAINT agent_suggestion_reason_chk
        CHECK (state NOT IN ('dismissed', 'superseded') OR reason <> ''),
    CONSTRAINT agent_suggestion_confirm_chk
        CHECK (state <> 'confirmed' OR (decision_id IS NOT NULL AND operation_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_agent_suggestion_state
    ON public.agent_suggestion (workspace_id, state, created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_agent_suggestion_connector
    ON public.agent_suggestion (workspace_id, connector_id);
CREATE INDEX IF NOT EXISTS idx_agent_suggestion_identity
    ON public.agent_suggestion (identity_id) WHERE identity_id IS NOT NULL;

COMMENT ON TABLE public.agent_suggestion IS
    'Likely agents proposed from observed behaviour (rule aws_agent_suggest_v1), one per workload incarnation. Never sets classification.';

CREATE TABLE IF NOT EXISTS public.agent_finding (
    id            uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid        NOT NULL,
    connector_id  uuid        NOT NULL,
    kind          text        NOT NULL,
    -- What the finding is about, stable across scans: the identity's ARN and
    -- immutable id (shared_role, human_credentials, long_lived_key) or the
    -- secret's ARN (model_key_secret).
    subject_key   text        NOT NULL,
    -- The identity it names, when it names one (cloud_identity).
    identity_id   uuid,
    -- References and display: {arn, name, kind, workloads[], secret{}...}.
    subject       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    evidence      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state         text        NOT NULL DEFAULT 'open',
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_finding_pkey PRIMARY KEY (id),
    CONSTRAINT agent_finding_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_finding_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_finding_subject_key UNIQUE (workspace_id, kind, subject_key),
    CONSTRAINT agent_finding_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_finding_identity_fkey FOREIGN KEY (identity_id)
        REFERENCES public.cloud_identity (id) ON DELETE SET NULL,
    CONSTRAINT agent_finding_kind_chk
        CHECK (kind IN ('shared_role', 'human_credentials', 'long_lived_key', 'model_key_secret')),
    CONSTRAINT agent_finding_subject_chk CHECK (subject_key <> ''),
    CONSTRAINT agent_finding_state_chk CHECK (state IN ('open', 'resolved')),
    CONSTRAINT agent_finding_resolved_chk CHECK ((state = 'resolved') = (resolved_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_agent_finding_list
    ON public.agent_finding (workspace_id, state, kind, last_seen DESC, id);
CREATE INDEX IF NOT EXISTS idx_agent_finding_connector
    ON public.agent_finding (workspace_id, connector_id, state);
CREATE INDEX IF NOT EXISTS idx_agent_finding_identity
    ON public.agent_finding (identity_id) WHERE identity_id IS NOT NULL;

COMMENT ON TABLE public.agent_finding IS
    'Risky credentials and identities of AI workloads on AWS: shared roles, human or long-lived credentials, model-key secrets (names only).';

-- Required for every workspace table; guarded as in 139 and 146.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_suggestion');
        PERFORM public.tenancy_enable_rls('public.agent_finding');
    END IF;
END $$;
