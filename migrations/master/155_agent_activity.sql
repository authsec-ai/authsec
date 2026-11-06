-- ============================================================================
-- 155: agent runtime activity timeline (SPEC-agent-runtime-activity.md §3).
--
-- 1. agent_activity_event: one row per thing an AI workload / agent did --
--    a CloudTrail event, an AgentCore span, an OTLP span -- per workspace.
--    Idempotent by (workspace_id, source, provider_event_id). Append-only:
--    UPDATE is refused; DELETE only by the retention job
--    (authsec.activity_retention = on) or a workspace purge
--    (authsec.workspace_purge = on). attrs is sanitised: never prompts,
--    completions, messages, tool-argument values or secrets.
--    connector_id, identity_id and workload_id carry no foreign key on
--    purpose: an activity record outlives the inventory row; retention
--    removes it.
-- 2. agent_activity_setting: per-workspace retention (default 90 days).
-- 3. agent_activity_cursor: per (connector, region, stream) high-water mark
--    and coverage of the AgentCore span reader (CloudWatch Logs aws/spans).
-- 4. agent_otlp_token: per-workspace OTLP ingest tokens, stored as sha256
--    hex only; the token alone decides the workspace of an ingest call.
--
-- Not partitioned (spec §3.3).
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_activity_event (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id      uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id      uuid,
    identity_id       uuid,
    workload_id       uuid,
    source            text        NOT NULL CHECK (source IN ('cloudtrail', 'cloudtrail_data', 'agentcore_span', 'otlp', 'authsec_decision')),
    kind              text        NOT NULL CHECK (kind IN ('model_call', 'tool_call', 'agent_step', 'cloud_action', 'data_access', 'sign_in', 'decision')),
    occurred_at       timestamptz NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    action            text        NOT NULL DEFAULT '' CHECK (length(action) <= 200),
    resource_ref      text        NOT NULL DEFAULT '' CHECK (length(resource_ref) <= 512),
    outcome           text        NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    on_behalf_of      text        CHECK (on_behalf_of IS NULL OR length(on_behalf_of) <= 256),
    trace_id          text        NOT NULL DEFAULT '' CHECK (length(trace_id) <= 64),
    span_id           text        NOT NULL DEFAULT '' CHECK (length(span_id) <= 64),
    parent_span_id    text        NOT NULL DEFAULT '' CHECK (length(parent_span_id) <= 64),
    provider_event_id text        NOT NULL CHECK (provider_event_id <> '' AND length(provider_event_id) <= 300),
    attrs             jsonb       NOT NULL DEFAULT '{}'::jsonb
                                  CHECK (jsonb_typeof(attrs) = 'object' AND pg_column_size(attrs) <= 16384),
    CONSTRAINT agent_activity_event_provider_key UNIQUE (workspace_id, source, provider_event_id)
);

-- The timeline (newest first), per identity, per workload, per trace; the
-- retention purge uses the first.
CREATE INDEX IF NOT EXISTS idx_agent_activity_ws_time
    ON public.agent_activity_event (workspace_id, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_activity_ws_identity_time
    ON public.agent_activity_event (workspace_id, identity_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_activity_ws_workload_time
    ON public.agent_activity_event (workspace_id, workload_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_activity_ws_trace
    ON public.agent_activity_event (workspace_id, trace_id) WHERE trace_id <> '';

COMMENT ON TABLE public.agent_activity_event IS
    'Agent runtime activity timeline (CloudTrail, AgentCore spans, OTLP), append-only, sanitised; purged by per-workspace retention.';

CREATE OR REPLACE FUNCTION public.agent_activity_event_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND (current_setting('authsec.activity_retention', true) = 'on'
                             OR current_setting('authsec.workspace_purge', true) = 'on') THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'agent_activity_event rows are append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_agent_activity_event_immutable ON public.agent_activity_event;
CREATE TRIGGER trg_agent_activity_event_immutable
    BEFORE UPDATE OR DELETE ON public.agent_activity_event
    FOR EACH ROW EXECUTE FUNCTION public.agent_activity_event_immutable();

CREATE TABLE IF NOT EXISTS public.agent_activity_setting (
    workspace_id   uuid        PRIMARY KEY REFERENCES public.workspaces(id) ON DELETE CASCADE,
    retention_days integer     NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 1 AND 400),
    updated_by     uuid,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.agent_activity_cursor (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id uuid        NOT NULL,
    region       text        NOT NULL CHECK (region <> '' AND length(region) <= 32),
    stream       text        NOT NULL CHECK (stream IN ('aws_spans')),
    cursor_at    timestamptz,
    state        text        NOT NULL DEFAULT 'reached'
                             CHECK (state IN ('reached', 'partial', 'permission_missing', 'not_configured', 'error')),
    last_error   text        NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    error_code   text        NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    last_scan_at timestamptz NOT NULL DEFAULT now(),
    rows_written bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, connector_id, region, stream),
    -- Workspace-qualified, like every cloud_* table (027).
    CONSTRAINT agent_activity_cursor_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.agent_otlp_token (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    label        text        NOT NULL DEFAULT '' CHECK (length(label) <= 200),
    -- sha256 of the token, lower-case hex. The token is shown once.
    token_hash   text        NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    -- The first characters of the token, to tell tokens apart.
    token_prefix text        NOT NULL,
    created_by   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    UNIQUE (workspace_id, id)
);
-- The ingest's credential lookup.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_otlp_token_hash
    ON public.agent_otlp_token (token_hash);
CREATE INDEX IF NOT EXISTS idx_agent_otlp_token_ws
    ON public.agent_otlp_token (workspace_id, created_at DESC);

COMMENT ON TABLE public.agent_otlp_token IS
    'Per-workspace OTLP/HTTP ingest tokens (sha256 hash only) for POST /authsec/ingest/otlp/v1/traces.';

-- Required for every workspace table; guarded as in 146_k8s_access_policies.sql.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_activity_event');
        PERFORM public.tenancy_enable_rls('public.agent_activity_setting');
        PERFORM public.tenancy_enable_rls('public.agent_activity_cursor');
        PERFORM public.tenancy_enable_rls('public.agent_otlp_token');
    END IF;
END $$;
