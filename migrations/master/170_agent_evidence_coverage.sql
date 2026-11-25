-- ============================================================================
-- 170: agent runtime evidence store and coverage (SPEC-secops-backend-upgrade
-- W1, P8, C1).
--
-- 1. agent_evidence_event: every normalised event a source delivered, for
--    EVERY principal of a connected account (not only labelled ones). One row
--    per (workspace, provider, event id): the same CloudTrail event delivered
--    by the stream, the poller and a trail-bucket backfill is one row, and
--    `source` records the path that delivered it first. The body is the
--    redacted normalised event (agentruntime.Event: names, ARNs, request
--    facts by fixed key) -- never a request or response body, never a secret
--    value, never a prompt. raw_hash is sha256 of the record as received.
--    record_class decides retention (agent_evidence_retention); a row with
--    pin_count > 0 is never purged.
-- 2. agent_evidence_retention: per workspace and record class, how many days
--    raw evidence is kept (absent row = default 90 d / elevated 1 y /
--    regulated 7 y).
-- 3. source_heartbeat: per delivering source (kind + ref, e.g. the stream of
--    a connector, a connector's region polled, an Azure diagnostic export, a
--    cluster's audit feed): last event, last receipt, the silence threshold
--    and its state. Silent sources raise coverage alert COV-01 (agent_alert).
-- 4. agent_capability_state: per estate scope (AWS account, Azure tenant,
--    cluster, or the workspace) and capability C1..C13, the computed state
--    (on|partial|off), whether a gap is broken or declared, since when, why
--    and the fallback.
-- 5. agent_capability_declaration: a request to declare a gap (tier 3): a
--    second person with governance:approve applies it; a workspace with one
--    approver applies it alone (break-glass) with a review due in 24 h.
-- 6. agent_ingest_secret: per-connector secret for pushed collectors other
--    than the AWS stream (Azure diagnostic settings via Event Hub). Only the
--    hash is stored; the presented secret alone decides workspace and
--    connector.
-- 7. agent_trail_backfill: requested and automatic trail-bucket backfills
--    (window, state, counters).
--
-- connector_id carries no foreign key on evidence, heartbeats and backfills
-- on purpose (as agent_alert, 150): evidence is a record that outlives the
-- connector row; retention removes it.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_evidence_event (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- The event id's namespace: CloudTrail ids are unique per AWS, Azure
    -- record ids per Azure, audit ids per cluster.
    provider         text        NOT NULL CHECK (provider IN ('aws', 'azure', 'k8s', 'gateway')),
    -- The path that delivered the event first.
    source           text        NOT NULL CHECK (source IN ('aws_stream', 'cloudtrail_poll', 'trail_backfill',
                                                            'azure_diag', 'k8s_audit', 'gateway', 'other')),
    event_id         text        NOT NULL CHECK (length(event_id) BETWEEN 1 AND 256),
    connector_id     uuid,
    event_time       timestamptz NOT NULL,
    received_at      timestamptz NOT NULL DEFAULT now(),
    -- received_at - event_time, in milliseconds (a negative value is a clock
    -- ahead of ours).
    skew_ms          bigint      NOT NULL DEFAULT 0,
    -- The attributed principal (an assumed role's role ARN, an IAM user's
    -- ARN, an Entra object id, a Kubernetes user name) and its kind.
    principal        text        NOT NULL DEFAULT '' CHECK (length(principal) <= 2048),
    principal_kind   text        NOT NULL DEFAULT '' CHECK (length(principal_kind) <= 64),
    -- The caller as the record states it (an assumed-role session ARN).
    principal_detail text        NOT NULL DEFAULT '' CHECK (length(principal_detail) <= 2048),
    account_id       text        NOT NULL DEFAULT '' CHECK (length(account_id) <= 256),
    region           text        NOT NULL DEFAULT '' CHECK (length(region) <= 64),
    event_source     text        NOT NULL DEFAULT '' CHECK (length(event_source) <= 256),
    event_name       text        NOT NULL DEFAULT '' CHECK (length(event_name) <= 256),
    outcome          text        NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'denied', 'error')),
    raw_hash         text        NOT NULL CHECK (raw_hash ~ '^[0-9a-f]{64}$'),
    body             jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(body) <= 16384),
    record_class     text        NOT NULL DEFAULT 'default' CHECK (record_class IN ('default', 'elevated', 'regulated')),
    pin_count        integer     NOT NULL DEFAULT 0 CHECK (pin_count >= 0),
    UNIQUE (workspace_id, id),
    CONSTRAINT agent_evidence_event_dedupe_key UNIQUE (workspace_id, provider, event_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_evidence_event_ws_time
    ON public.agent_evidence_event (workspace_id, event_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_evidence_event_ws_principal
    ON public.agent_evidence_event (workspace_id, principal, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_agent_evidence_event_ws_source
    ON public.agent_evidence_event (workspace_id, source, event_time DESC);
-- The retention purge reads unpinned rows by class and receipt.
CREATE INDEX IF NOT EXISTS idx_agent_evidence_event_retention
    ON public.agent_evidence_event (workspace_id, record_class, received_at) WHERE pin_count = 0;

CREATE TABLE IF NOT EXISTS public.agent_evidence_retention (
    workspace_id   uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    record_class   text        NOT NULL CHECK (record_class IN ('default', 'elevated', 'regulated')),
    retention_days integer     NOT NULL CHECK (retention_days BETWEEN 30 AND 3650),
    updated_by     uuid,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, record_class)
);

CREATE TABLE IF NOT EXISTS public.source_heartbeat (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id           uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    source_kind            text        NOT NULL CHECK (source_kind IN ('aws_stream', 'cloudtrail_poll', 'trail_backfill',
                                                                       'azure_diag', 'k8s_audit', 'gateway', 'other')),
    -- e.g. "connector/<id>" (a stream), "connector/<id>/region/<r>" (a poll).
    source_ref             text        NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 300),
    connector_id           uuid,
    last_event_at          timestamptz,
    last_received_at       timestamptz,
    -- The longest gap between events expected in normal operation
    -- (informational; NULL = unknown).
    expected_floor_seconds integer     CHECK (expected_floor_seconds IS NULL OR expected_floor_seconds > 0),
    -- Silent once nothing arrived for this long; NULL = never judged silent
    -- (a source delivered only when someone runs a scan).
    silent_after_seconds   integer     CHECK (silent_after_seconds IS NULL OR silent_after_seconds > 0),
    state                  text        NOT NULL DEFAULT 'ok' CHECK (state IN ('ok', 'silent')),
    silent_since           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    CONSTRAINT source_heartbeat_source_key UNIQUE (workspace_id, source_kind, source_ref),
    CONSTRAINT source_heartbeat_silent_chk CHECK ((state = 'silent') = (silent_since IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_source_heartbeat_ws_connector
    ON public.source_heartbeat (workspace_id, connector_id);

CREATE TABLE IF NOT EXISTS public.agent_capability_state (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- An AWS account id, an Azure tenant id, a cluster (discovery source id),
    -- or 'workspace'.
    estate_scope    text        NOT NULL CHECK (length(estate_scope) BETWEEN 1 AND 256),
    scope_kind      text        NOT NULL CHECK (scope_kind IN ('account', 'tenant', 'subscription', 'cluster', 'workspace')),
    connector_id    uuid,
    capability      text        NOT NULL CHECK (capability IN ('C1','C2','C3','C4','C5','C6','C7','C8','C9','C10','C11','C12','C13')),
    state           text        NOT NULL CHECK (state IN ('on', 'partial', 'off')),
    gap_kind        text        NOT NULL DEFAULT 'none' CHECK (gap_kind IN ('none', 'declared', 'broken')),
    since           timestamptz NOT NULL DEFAULT now(),
    detail          text        NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),
    fallback        text        NOT NULL DEFAULT '' CHECK (length(fallback) <= 2000),
    declared_by     uuid,
    declared_at     timestamptz,
    declared_reason text        NOT NULL DEFAULT '' CHECK (length(declared_reason) <= 2000),
    computed_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    CONSTRAINT agent_capability_state_scope_key UNIQUE (workspace_id, estate_scope, capability),
    CONSTRAINT agent_capability_state_gap_chk CHECK ((state = 'on') = (gap_kind = 'none'))
);
CREATE INDEX IF NOT EXISTS idx_agent_capability_state_ws_cap
    ON public.agent_capability_state (workspace_id, capability);

CREATE TABLE IF NOT EXISTS public.agent_capability_declaration (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    capability_state_id uuid     NOT NULL,
    reason           text        NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 2000),
    requested_by     uuid        NOT NULL,
    requested_at     timestamptz NOT NULL DEFAULT now(),
    state            text        NOT NULL DEFAULT 'pending'
                                 CHECK (state IN ('pending', 'applied', 'rejected', 'withdrawn')),
    decided_by       uuid,
    decided_at       timestamptz,
    decision_reason  text        NOT NULL DEFAULT '' CHECK (length(decision_reason) <= 2000),
    -- Applied alone: the workspace had one approver (decision 4).
    break_glass      boolean     NOT NULL DEFAULT false,
    review_due_at    timestamptz,
    reviewed_by      uuid,
    reviewed_at      timestamptz,
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, capability_state_id)
        REFERENCES public.agent_capability_state (workspace_id, id) ON DELETE CASCADE,
    -- Separation: a second person decides, except break-glass.
    CONSTRAINT agent_capability_declaration_separation_chk
        CHECK (decided_by IS NULL OR break_glass OR decided_by <> requested_by),
    CONSTRAINT agent_capability_declaration_break_glass_chk
        CHECK (NOT break_glass OR (state = 'applied' AND review_due_at IS NOT NULL)),
    CONSTRAINT agent_capability_declaration_decided_chk
        CHECK ((state = 'pending') = (decided_at IS NULL))
);
-- One open request per capability state.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_capability_declaration_pending
    ON public.agent_capability_declaration (workspace_id, capability_state_id) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_agent_capability_declaration_ws
    ON public.agent_capability_declaration (workspace_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS public.agent_ingest_secret (
    connector_id     uuid        NOT NULL,
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    kind             text        NOT NULL CHECK (kind IN ('azure_diag')),
    secret_hash      text        NOT NULL CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    secret_prefix    text        NOT NULL,
    created_by       text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    rotated_at       timestamptz,
    revoked_at       timestamptz,
    last_received_at timestamptz,
    received_count   bigint      NOT NULL DEFAULT 0,
    rejected_count   bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, connector_id, kind),
    CONSTRAINT agent_ingest_secret_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE
);
-- The ingest's credential lookup.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_ingest_secret_hash
    ON public.agent_ingest_secret (secret_hash);

CREATE TABLE IF NOT EXISTS public.agent_trail_backfill (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id  uuid        NOT NULL,
    window_from   timestamptz NOT NULL,
    window_to     timestamptz NOT NULL,
    cause         text        NOT NULL CHECK (cause IN ('manual', 'gap')),
    -- For cause 'gap': the heartbeat whose silence it fills.
    heartbeat_id  uuid,
    state         text        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
    requested_by  uuid,
    objects_read  integer     NOT NULL DEFAULT 0,
    events_read   integer     NOT NULL DEFAULT 0,
    partial       boolean     NOT NULL DEFAULT false,
    last_error    text        NOT NULL DEFAULT '' CHECK (length(last_error) <= 2000),
    leased_until  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz,
    UNIQUE (workspace_id, id),
    CONSTRAINT agent_trail_backfill_window_chk CHECK (window_to > window_from)
);
CREATE INDEX IF NOT EXISTS idx_agent_trail_backfill_ws
    ON public.agent_trail_backfill (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_trail_backfill_due
    ON public.agent_trail_backfill (created_at) WHERE state IN ('queued', 'running');
-- One automatic backfill per heartbeat silence.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_trail_backfill_gap
    ON public.agent_trail_backfill (workspace_id, heartbeat_id, window_from) WHERE cause = 'gap';

-- Coverage alerts (COV-01) are agent_alert rows: the detection id and the
-- subject label 'source' are admitted, and a source has at most one alert
-- that is not resolved. For COV-01, identity_id holds the source_heartbeat id.
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_detection_check;
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_detection_chk;
ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_detection_chk
    CHECK (detection IN ('D1','D2','D3','D4','D5','D6','D7','D8','COV-01'));
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_subject_label_check;
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_subject_label_chk;
ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_subject_label_chk
    CHECK (subject_label IN ('ai_workload', 'suggested_agent', 'agent', 'source'));
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_alert_coverage_open
    ON public.agent_alert (workspace_id, dedupe_key) WHERE detection = 'COV-01' AND state <> 'resolved';

COMMENT ON TABLE public.agent_evidence_event IS
    'Agent runtime evidence: every normalised event of a connected account (all principals), redacted, deduplicated per provider event id; retention by record class, pinned rows kept.';
COMMENT ON TABLE public.source_heartbeat IS
    'Per delivering source: last event and receipt, silence threshold and state (COV-01 coverage alerts).';
COMMENT ON TABLE public.agent_capability_state IS
    'Coverage: capability C1..C13 per estate scope (on|partial|off), broken or declared gap, detail and fallback.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_evidence_event');
        PERFORM public.tenancy_enable_rls('public.agent_evidence_retention');
        PERFORM public.tenancy_enable_rls('public.source_heartbeat');
        PERFORM public.tenancy_enable_rls('public.agent_capability_state');
        PERFORM public.tenancy_enable_rls('public.agent_capability_declaration');
        PERFORM public.tenancy_enable_rls('public.agent_ingest_secret');
        PERFORM public.tenancy_enable_rls('public.agent_trail_backfill');
    END IF;
END $$;
