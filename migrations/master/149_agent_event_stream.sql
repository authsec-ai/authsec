-- ============================================================================
-- 149: agent runtime event stream (SPEC-agent-runtime-visibility.md §5.6).
--
-- agent_event_stream: one row per AWS connector whose account streams its
-- CloudTrail events to POST /authsec/ingest/aws/events through an EventBridge
-- API destination. The row holds the HASH of the connector's event secret
-- (sha256 hex, as discovery ingest tokens), never the secret: the ingest
-- resolves workspace and connector from the presented secret's hash and from
-- nothing in the body. Rotating replaces the hash; revoking stamps revoked_at.
-- The counters and last_received_at say whether the stream is alive; the
-- connector reads as "stream silent since ..." once nothing arrived for
-- silent_after.
--
-- agent_event_seen: the CloudTrail eventIDs already accepted, per workspace,
-- so an event EventBridge retries (or delivers twice) is handed to the sinks
-- once. Kept 14 days, purged per workspace by the ingest.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_event_stream (
    connector_id     uuid        PRIMARY KEY,
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- sha256 of the secret, lower-case hex. The secret is shown once.
    secret_hash      text        NOT NULL,
    -- The first characters of the secret, to tell secrets apart.
    secret_prefix    text        NOT NULL,
    created_by       text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    rotated_at       timestamptz,
    revoked_at       timestamptz,
    -- When an accepted event last arrived, and the newest eventTime seen.
    last_received_at timestamptz,
    last_event_time  timestamptz,
    -- Events accepted (new and duplicate) and refused (wrong account,
    -- unparseable, oversize).
    received_count   bigint      NOT NULL DEFAULT 0,
    rejected_count   bigint      NOT NULL DEFAULT 0,
    silent_after     interval    NOT NULL DEFAULT interval '6 hours',
    CONSTRAINT agent_event_stream_hash_chk
        CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_event_stream_silent_after_chk
        CHECK (silent_after BETWEEN interval '15 minutes' AND interval '7 days'),
    CONSTRAINT agent_event_stream_workspace_id_key
        UNIQUE (workspace_id, connector_id),
    -- Workspace-qualified, like every cloud_* table (027): a stream cannot
    -- name another workspace's connector.
    CONSTRAINT agent_event_stream_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE
);

-- The ingest's credential lookup.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_event_stream_secret_hash
    ON public.agent_event_stream (secret_hash);

COMMENT ON TABLE public.agent_event_stream IS
    'Per-connector CloudTrail event stream (EventBridge API destination): the event secret hash and the stream health.';

CREATE TABLE IF NOT EXISTS public.agent_event_seen (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id uuid        NOT NULL,
    -- CloudTrail eventID.
    event_id     text        NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_event_seen_event_id_chk
        CHECK (event_id <> '' AND length(event_id) <= 128),
    CONSTRAINT agent_event_seen_workspace_event_key
        UNIQUE (workspace_id, event_id),
    CONSTRAINT agent_event_seen_stream_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.agent_event_stream (workspace_id, connector_id) ON DELETE CASCADE
);

-- The purge (per workspace, by age) and the FK.
CREATE INDEX IF NOT EXISTS idx_agent_event_seen_received
    ON public.agent_event_seen (workspace_id, received_at);
CREATE INDEX IF NOT EXISTS idx_agent_event_seen_connector
    ON public.agent_event_seen (workspace_id, connector_id);

COMMENT ON TABLE public.agent_event_seen IS
    'CloudTrail eventIDs the event stream already accepted (idempotency), kept 14 days.';

-- Required for every workspace table; guarded as in 139_cloud_scan_schedule.sql.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_event_stream');
        PERFORM public.tenancy_enable_rls('public.agent_event_seen');
    END IF;
END $$;
