-- 243_usage_reconciliation.sql
--
-- W6 (SPEC-secops-backend-upgrade.md P15): the usage reconciliation.
--
-- 1. model_usage_reconciliation: one label per provider key and minute
--    (key_ref '' when the key is unknown: estate traffic with no provider
--    usage to tie it to):
--      observed     the gateway's decision log has calls with the key in the minute;
--      bypass       an estate workload looked the provider up or sent it
--                   traffic in the minute, and the gateway saw no call;
--      outside_use  the provider reports usage of the key in the minute and
--                   neither the gateway nor any estate lookup or flow explains it.
--    evidence holds references (table and id) to the rows behind the label.
-- 2. agent_alert admits detections USAGE-02 (outside use) and USAGE-03
--    (bypass), subject label 'provider_key', and keeps one open alert per
--    dedupe key for them.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.model_usage_reconciliation (
    id                uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    provider          text        NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,63}$'),
    -- The provider's key id; 'agw:<uuid>' for an AuthSec-held key not tied
    -- to one; '' unknown.
    key_ref           text        NOT NULL DEFAULT '' CHECK (length(key_ref) <= 200),
    connection_id     uuid,
    minute            timestamptz NOT NULL,
    label             text        NOT NULL CHECK (label IN ('observed', 'bypass', 'outside_use')),
    gateway_calls     integer     NOT NULL DEFAULT 0 CHECK (gateway_calls >= 0),
    provider_requests bigint,
    input_tokens      bigint      NOT NULL DEFAULT 0,
    output_tokens     bigint      NOT NULL DEFAULT 0,
    dns_lookups       bigint      NOT NULL DEFAULT 0,
    flow_bytes        bigint      NOT NULL DEFAULT 0,
    workload_ids      jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(workload_ids) = 'array'),
    evidence          jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence) = 'array'),
    alert_id          uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT model_usage_reconciliation_pkey PRIMARY KEY (id),
    CONSTRAINT model_usage_reconciliation_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT model_usage_reconciliation_key UNIQUE (workspace_id, provider, key_ref, minute)
);
CREATE INDEX IF NOT EXISTS idx_model_usage_reconciliation_ws
    ON public.model_usage_reconciliation (workspace_id, minute DESC);
CREATE INDEX IF NOT EXISTS idx_model_usage_reconciliation_label
    ON public.model_usage_reconciliation (workspace_id, label, minute DESC) WHERE label <> 'observed';

COMMENT ON TABLE public.model_usage_reconciliation IS
    'Per provider key and minute: observed (gateway), bypass (estate traffic, no gateway call) or outside use (provider usage nobody explains), with evidence refs.';

ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_detection_check;
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_detection_chk;
ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_detection_chk
    CHECK (detection IN ('D1','D2','D3','D4','D5','D6','D7','D8','COV-01','USAGE-02','USAGE-03'));
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_subject_label_check;
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_subject_label_chk;
ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_subject_label_chk
    CHECK (subject_label IN ('ai_workload', 'suggested_agent', 'agent', 'source', 'provider_key'));
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_alert_usage_open
    ON public.agent_alert (workspace_id, dedupe_key) WHERE detection IN ('USAGE-02', 'USAGE-03') AND state <> 'resolved';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.model_usage_reconciliation');
    END IF;
END $$;
