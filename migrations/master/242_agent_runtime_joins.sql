-- 242_agent_runtime_joins.sql
--
-- W6 (SPEC-secops-backend-upgrade.md C3-C5, P15): the rows the usage
-- reconciliation joins.
--
-- 1. agent_dns_lookup: per minute, a source's lookups of a model provider
--    host or a workspace egress host (never any other name): where from
--    (address, interface, instance, VPC), the workload holding the address
--    (resolved holder), the name, the first answer address, the source
--    (route53 Resolver query logs; coredns and azure are admitted for the
--    Kubernetes and Azure readers).
-- 2. agent_flow_summary: per minute, a source's traffic to an address a
--    provider or egress host resolved to (VPC / VNet flow logs): bytes out,
--    packets, the host the address was resolved from.
-- 3. model_provider_usage_minute: a connected organisation's usage per key,
--    project and model at the finest resolution the provider reports
--    (1m for OpenAI and Anthropic usage; cost is daily, 1d), with cost where
--    the provider reports it.
-- 4. model_provider_connection.usage_minute_cursor / cost_cursor: how far
--    the per-minute usage and the daily cost were read.
-- 5. agent_join_setting: per workspace, the egress hosts (beyond the model
--    provider list) whose lookups and flows are kept, and the flow-log log
--    groups to read per AWS connector and region.
--
-- Counts only: no DNS answer other than the first address of a listed
-- host, no payload, no prompt.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.agent_dns_lookup (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id       uuid        NOT NULL,
    source             text        NOT NULL CHECK (source IN ('route53', 'coredns', 'azure')),
    region             text        NOT NULL DEFAULT '',
    -- Start of the minute the lookups were made in.
    observed_at        timestamptz NOT NULL,
    src_ip             text        NOT NULL DEFAULT '',
    src_eni            text        NOT NULL DEFAULT '',
    src_instance       text        NOT NULL DEFAULT '',
    vpc_id             text        NOT NULL DEFAULT '',
    -- The workload holding the source (cloud_workload id), when resolved.
    holder_workload_id uuid,
    holder_ref         text        NOT NULL DEFAULT '' CHECK (length(holder_ref) <= 512),
    query_name         text        NOT NULL CHECK (query_name <> '' AND length(query_name) <= 253),
    host_kind          text        NOT NULL CHECK (host_kind IN ('provider', 'egress')),
    -- The model provider key of the host's list entry; '' for egress hosts.
    provider           text        NOT NULL DEFAULT '',
    answer_ip          text        NOT NULL DEFAULT '',
    queries            bigint      NOT NULL DEFAULT 1 CHECK (queries >= 1),
    log_group_arn      text        NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_dns_lookup_pkey PRIMARY KEY (id),
    CONSTRAINT agent_dns_lookup_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_dns_lookup_key UNIQUE (workspace_id, connector_id, source, observed_at, src_ip, src_instance,
                                            vpc_id, query_name, answer_ip)
);
CREATE INDEX IF NOT EXISTS idx_agent_dns_lookup_ws_time
    ON public.agent_dns_lookup (workspace_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_agent_dns_lookup_provider
    ON public.agent_dns_lookup (workspace_id, provider, observed_at) WHERE provider <> '';
CREATE INDEX IF NOT EXISTS idx_agent_dns_lookup_answer
    ON public.agent_dns_lookup (workspace_id, answer_ip) WHERE answer_ip <> '';

CREATE TABLE IF NOT EXISTS public.agent_flow_summary (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id       uuid        NOT NULL,
    source             text        NOT NULL CHECK (source IN ('vpc', 'vnet')),
    region             text        NOT NULL DEFAULT '',
    minute             timestamptz NOT NULL,
    src_ip             text        NOT NULL DEFAULT '',
    src_eni            text        NOT NULL DEFAULT '',
    holder_workload_id uuid,
    holder_ref         text        NOT NULL DEFAULT '' CHECK (length(holder_ref) <= 512),
    dst_ip             text        NOT NULL CHECK (dst_ip <> ''),
    dst_host           text        NOT NULL DEFAULT '',
    provider           text        NOT NULL DEFAULT '',
    bytes_out          bigint      NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    packets            bigint      NOT NULL DEFAULT 0 CHECK (packets >= 0),
    log_group_arn      text        NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_flow_summary_pkey PRIMARY KEY (id),
    CONSTRAINT agent_flow_summary_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_flow_summary_key UNIQUE (workspace_id, connector_id, source, minute, src_ip, src_eni, dst_ip)
);
CREATE INDEX IF NOT EXISTS idx_agent_flow_summary_ws_time
    ON public.agent_flow_summary (workspace_id, minute);
CREATE INDEX IF NOT EXISTS idx_agent_flow_summary_provider
    ON public.agent_flow_summary (workspace_id, provider, minute) WHERE provider <> '';

CREATE TABLE IF NOT EXISTS public.model_provider_usage_minute (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL,
    connection_id       uuid        NOT NULL,
    provider            text        NOT NULL CHECK (provider IN ('openai', 'anthropic')),
    -- '' for usage or cost the provider ties to no key.
    provider_key_id     text        NOT NULL DEFAULT '',
    key_hint            text        NOT NULL DEFAULT '',
    project_id          text        NOT NULL DEFAULT '',
    model               text        NOT NULL DEFAULT '',
    bucket_start        timestamptz NOT NULL,
    -- 1m for usage; 1h when a provider reports only hourly; 1d for cost.
    resolution          text        NOT NULL CHECK (resolution IN ('1m', '1h', '1d')),
    requests            bigint,
    input_tokens        bigint      NOT NULL DEFAULT 0,
    cached_input_tokens bigint      NOT NULL DEFAULT 0,
    output_tokens       bigint      NOT NULL DEFAULT 0,
    -- USD, when the provider reports cost at this resolution (cost rows).
    cost_usd            numeric(20, 6),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT model_provider_usage_minute_pkey PRIMARY KEY (id),
    CONSTRAINT model_provider_usage_minute_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT model_provider_usage_minute_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT model_provider_usage_minute_connection_fkey FOREIGN KEY (workspace_id, connection_id)
        REFERENCES public.model_provider_connection (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT model_provider_usage_minute_bucket_key
        UNIQUE (workspace_id, connection_id, resolution, provider_key_id, project_id, model, bucket_start),
    CONSTRAINT model_provider_usage_minute_counts_chk
        CHECK ((requests IS NULL OR requests >= 0) AND input_tokens >= 0 AND cached_input_tokens >= 0
               AND output_tokens >= 0 AND (cost_usd IS NULL OR cost_usd >= 0))
);
CREATE INDEX IF NOT EXISTS idx_model_provider_usage_minute_bucket
    ON public.model_provider_usage_minute (workspace_id, resolution, bucket_start);

ALTER TABLE public.model_provider_connection ADD COLUMN IF NOT EXISTS usage_minute_cursor timestamptz;
ALTER TABLE public.model_provider_connection ADD COLUMN IF NOT EXISTS cost_cursor timestamptz;

-- The flow-log read keeps its cursors beside the DNS ones (stream 'flow').
ALTER TABLE public.cloud_dns_cursor DROP CONSTRAINT IF EXISTS cloud_dns_cursor_stream_chk;
ALTER TABLE public.cloud_dns_cursor ADD CONSTRAINT cloud_dns_cursor_stream_chk CHECK (stream IN ('dns', 'flow'));

CREATE TABLE IF NOT EXISTS public.agent_join_setting (
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- ["api.example.com", "*.example.net"]
    egress_hosts    jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(egress_hosts) = 'array'),
    -- [{"connector_id": "...", "region": "us-east-1", "log_group": "arn:aws:logs:..."}]
    flow_log_groups jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(flow_log_groups) = 'array'),
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    version         integer     NOT NULL DEFAULT 1,
    CONSTRAINT agent_join_setting_pkey PRIMARY KEY (workspace_id)
);

COMMENT ON TABLE public.agent_dns_lookup IS
    'Per-minute lookups of model provider and egress hosts (route53 / coredns / azure), with the resolved holder; counts only.';
COMMENT ON TABLE public.agent_flow_summary IS
    'Per-minute flow-log traffic to addresses provider / egress hosts resolved to: bytes out, packets; counts only.';
COMMENT ON TABLE public.model_provider_usage_minute IS
    'Provider usage per key at the finest resolution reported (1m; cost 1d); token and request counts only.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_dns_lookup');
        PERFORM public.tenancy_enable_rls('public.agent_flow_summary');
        PERFORM public.tenancy_enable_rls('public.model_provider_usage_minute');
        PERFORM public.tenancy_enable_rls('public.agent_join_setting');
    END IF;
END $$;
