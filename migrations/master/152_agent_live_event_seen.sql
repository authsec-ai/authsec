-- ============================================================================
-- 152: live model-call evidence (agent_live_event_seen) and the AI-workload
-- evidence finding kinds.
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
-- agent_finding_kind_chk admits 'ai_config_hint' (a workload whose
-- configuration names a model provider: a possible AI workload) and
-- 'ai_network_traffic' (DNS lookups of model endpoints, written by the
-- network evidence path, migration 153 on its branch). Both are added here
-- and there, keeping every earlier kind, so either merge order works.
-- agent_alert.subject_label admits 'possible_ai_workload' (detections run on
-- possible AI workloads too).
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

DO $$
BEGIN
    IF to_regclass('public.agent_finding') IS NOT NULL THEN
        ALTER TABLE public.agent_finding DROP CONSTRAINT IF EXISTS agent_finding_kind_chk;
        ALTER TABLE public.agent_finding ADD CONSTRAINT agent_finding_kind_chk
            CHECK (kind IN ('shared_role', 'human_credentials', 'long_lived_key', 'model_key_secret',
                            'ai_config_hint', 'ai_network_traffic'));
    END IF;
    IF to_regclass('public.agent_alert') IS NOT NULL THEN
        ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_subject_label_check;
        ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_subject_label_check
            CHECK (subject_label IN ('ai_workload', 'suggested_agent', 'agent', 'possible_ai_workload'));
    END IF;
END $$;
