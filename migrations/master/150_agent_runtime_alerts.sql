-- ============================================================================
-- 150: agent runtime alerts (SPEC-agent-runtime-visibility.md §5.7, with
-- review 2's §10 Q3: new tables plus iga_gov_event log entries).
--
-- 1. agent_alert: one alert per (workspace, identity, detection) incident,
--    deduplicated within the workspace's window; evidence holds sanitised
--    event references only (event id, time, source, name, IP, region, error
--    code, detail) -- never request bodies or secret values.
-- 2. agent_alert_delivery: one row per channel (Slack, each SIEM endpoint)
--    per alert: attempts, status, next attempt, last error, sent time.
-- 3. agent_alert_baseline: what each identity was seen doing (models, roles
--    assumed, source IPs, regions), hourly model-call and per-minute denial
--    counters, and when AuthSec first observed it (kind 'observed').
-- 4. agent_alert_setting: per-workspace detection switches and thresholds,
--    Slack on/off, dedupe window and alert retention (default 90 days).
-- 5. agent_alert_siem_endpoint: SIEM webhook URL; the HMAC secret is in Vault
--    under the workspace's path, the row holds only its path (secret_ref).
-- 6. agent_alert_event_seen: event ids already processed per workspace, so
--    an event arriving from both the poller and the stream counts once.
-- 7. iga_gov_notification.subject_kind admits 'agent_alert' (Slack delivery
--    through the governance notification outbox).
--
-- identity_id and connector_id carry no foreign key on purpose: an alert is a
-- record that outlives the inventory row (an identity incarnation replaced,
-- a connector removed); retention removes it.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_alert (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id     uuid        NOT NULL,
    identity_id      uuid        NOT NULL,
    workload_ids     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    subject_label    text        NOT NULL CHECK (subject_label IN ('ai_workload', 'suggested_agent', 'agent')),
    subject_name     text        NOT NULL DEFAULT '',
    detection        text        NOT NULL CHECK (detection IN ('D1','D2','D3','D4','D5','D6','D7','D8')),
    severity         text        NOT NULL CHECK (severity IN ('high', 'medium')),
    title            text        NOT NULL,
    dedupe_key       text        NOT NULL,
    first_seen       timestamptz NOT NULL,
    last_seen        timestamptz NOT NULL,
    event_count      integer     NOT NULL DEFAULT 1 CHECK (event_count >= 1),
    evidence         jsonb       NOT NULL DEFAULT '[]'::jsonb,
    state            text        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'acknowledged', 'resolved')),
    state_changed_by uuid,
    state_changed_at timestamptz,
    reason           text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    CONSTRAINT agent_alert_seen_chk CHECK (last_seen >= first_seen)
);
CREATE INDEX IF NOT EXISTS idx_agent_alert_ws_created
    ON public.agent_alert (workspace_id, created_at DESC, id DESC);
-- The dedupe lookup reads only alerts that are not resolved.
CREATE INDEX IF NOT EXISTS idx_agent_alert_dedupe
    ON public.agent_alert (workspace_id, dedupe_key, last_seen) WHERE state <> 'resolved';
CREATE INDEX IF NOT EXISTS idx_agent_alert_ws_identity
    ON public.agent_alert (workspace_id, identity_id);
CREATE INDEX IF NOT EXISTS idx_agent_alert_retention
    ON public.agent_alert (workspace_id, last_seen);

CREATE TABLE IF NOT EXISTS public.agent_alert_siem_endpoint (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    url          text        NOT NULL CHECK (url LIKE 'https://%'),
    -- Vault path of the HMAC secret; '' once the endpoint is deleted.
    secret_ref   text        NOT NULL DEFAULT '',
    enabled      boolean     NOT NULL DEFAULT true,
    created_by   uuid        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    deleted_at   timestamptz,
    UNIQUE (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_alert_siem_endpoint_ws
    ON public.agent_alert_siem_endpoint (workspace_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS public.agent_alert_delivery (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    alert_id        uuid        NOT NULL,
    channel         text        NOT NULL CHECK (channel IN ('slack', 'siem')),
    endpoint_id     uuid,
    attempt         integer     NOT NULL DEFAULT 0,
    status          text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    leased_until    timestamptz,
    last_error      text        NOT NULL DEFAULT '',
    sent_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, alert_id) REFERENCES public.agent_alert (workspace_id, id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, endpoint_id) REFERENCES public.agent_alert_siem_endpoint (workspace_id, id),
    CONSTRAINT agent_alert_delivery_endpoint_chk CHECK ((channel = 'siem') = (endpoint_id IS NOT NULL)),
    CONSTRAINT agent_alert_delivery_sent_chk CHECK ((status = 'sent') = (sent_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_agent_alert_delivery_alert
    ON public.agent_alert_delivery (workspace_id, alert_id);
CREATE INDEX IF NOT EXISTS idx_agent_alert_delivery_endpoint
    ON public.agent_alert_delivery (workspace_id, endpoint_id) WHERE endpoint_id IS NOT NULL;
-- The delivery worker's scan: due SIEM rows.
CREATE INDEX IF NOT EXISTS idx_agent_alert_delivery_due
    ON public.agent_alert_delivery (next_attempt_at) WHERE status = 'pending' AND channel = 'siem';
-- One delivery per channel and endpoint per alert.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_alert_delivery_target
    ON public.agent_alert_delivery (workspace_id, alert_id, channel, COALESCE(endpoint_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE IF NOT EXISTS public.agent_alert_baseline (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    identity_id  uuid        NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('model', 'role', 'ip', 'region', 'hourly', 'denied', 'observed')),
    key          text        NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    count        bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, identity_id, kind, key)
);
-- Retention of the hourly and per-minute counters.
CREATE INDEX IF NOT EXISTS idx_agent_alert_baseline_counters
    ON public.agent_alert_baseline (workspace_id, last_seen) WHERE kind IN ('hourly', 'denied');

CREATE TABLE IF NOT EXISTS public.agent_alert_setting (
    workspace_id          uuid        PRIMARY KEY REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- {"D5": {"enabled": true, "n": 10, "minutes": 5}, "D6": {"enabled": true, "k": 5}, ...}
    detections            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    slack_enabled         boolean     NOT NULL DEFAULT true,
    dedupe_window_minutes integer     NOT NULL DEFAULT 60 CHECK (dedupe_window_minutes BETWEEN 5 AND 1440),
    retention_days        integer     NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 7 AND 3650),
    updated_by            uuid,
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.agent_alert_event_seen (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    event_id     text        NOT NULL,
    identity_id  uuid        NOT NULL,
    event_time   timestamptz NOT NULL,
    seen_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_alert_event_seen_age
    ON public.agent_alert_event_seen (workspace_id, seen_at);

COMMENT ON TABLE public.agent_alert IS
    'Agent runtime alerts (D1-D8) on AI workloads and agents; opened and resolved are also logged in iga_gov_event.';

DO $$
BEGIN
    IF to_regclass('public.iga_gov_notification') IS NOT NULL THEN
        ALTER TABLE public.iga_gov_notification DROP CONSTRAINT IF EXISTS iga_gov_notification_subject_kind_check;
        ALTER TABLE public.iga_gov_notification ADD CONSTRAINT iga_gov_notification_subject_kind_check
            CHECK (subject_kind IN ('owner_review','approval_request','deployment','drift','canary_gate','finding_digest',
                                    'temporary_grant','session_revocation','time_bound','agent_alert'));
    END IF;
    -- Required for every workspace table; guarded as in 139 and 146.
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_alert');
        PERFORM public.tenancy_enable_rls('public.agent_alert_siem_endpoint');
        PERFORM public.tenancy_enable_rls('public.agent_alert_delivery');
        PERFORM public.tenancy_enable_rls('public.agent_alert_baseline');
        PERFORM public.tenancy_enable_rls('public.agent_alert_setting');
        PERFORM public.tenancy_enable_rls('public.agent_alert_event_seen');
    END IF;
END $$;
