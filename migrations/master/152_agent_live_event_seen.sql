-- ============================================================================
-- 152: live model-call evidence (agent_live_event_seen).
--
-- The "agent_runtime_live" event sink (services/agent_runtime_live.go)
-- records model calls seen on the event stream (or a poll's dispatch) as live
-- evidence in cloud_usage attrs (live_calls, live_denied, live_models,
-- live_last_call_at, live_regions), so a new AI workload shows before the next
-- scan. agent_live_event_seen holds the event ids it counted, per workspace,
-- so an event arriving from both the poller and the stream counts once.
-- Purged after 8 days by the sink (workspace by workspace).
--
-- identity_id and connector_id carry no foreign key on purpose, as in 150:
-- the row is an idempotency key that outlives the inventory row; the purge
-- removes it.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_live_event_seen (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    event_id     text        NOT NULL CHECK (event_id <> '' AND length(event_id) <= 128),
    connector_id uuid        NOT NULL,
    identity_id  uuid        NOT NULL,
    event_time   timestamptz NOT NULL,
    seen_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_live_event_seen_pkey PRIMARY KEY (workspace_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_live_event_seen_age
    ON public.agent_live_event_seen (workspace_id, seen_at);

COMMENT ON TABLE public.agent_live_event_seen IS
    'CloudTrail event ids the live model-call sink counted, per workspace (idempotency across the poller and the event stream).';

DO $$
BEGIN
    -- Required for every workspace table; guarded as in 139 and 146.
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_live_event_seen');
    END IF;
END $$;
