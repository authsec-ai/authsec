-- ============================================================================
-- 153: DNS-based detection of direct model-provider calls
-- (SPEC-agent-runtime-visibility.md §11).
--
-- 1. agent_finding.kind admits 'ai_network_traffic' (a workload, identity or
--    VPC seen looking up a model provider's API host in Route 53 Resolver
--    query logs) and 'ai_config_hint' (written by 152 on another branch; both
--    migrations widen the CHECK to the same list, so either merge order
--    leaves it whole). Every existing kind is kept.
-- 2. cloud_dns_cursor: how far each Resolver query-log group was read, per
--    (connector, region, log group), like cloud_trail_cursor (147) with the
--    log group in the key. stream is 'dns'.
--
-- COVERAGE IS NEVER CLAIMED FOR WHAT WAS NOT READ. A read covers [window_from,
-- read_to). covered_from is where the CONTIGUOUS fully read interval ending at
-- read_to begins: it carries over from the previous read when this one began
-- exactly at the previous read_to and was whole, restarts at window_from after
-- a gap (a log group unread for longer than the per-read cap, so only its last
-- seven days were read), and is read_to itself when the read was truncated by
-- the query's row limit (nothing in it is known whole). A finding is resolved
-- only when every log group it was seen in has been read without a gap for 30
-- days after its last lookup.
--
-- A failed read does not move the cursor; it records last_error and
-- last_attempt_at on an existing row and nothing else.
--
-- No DNS data is stored here: counts and bytes only. The findings hold only
-- lookups of the model-endpoint list.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
BEGIN
    IF to_regclass('public.agent_finding') IS NOT NULL THEN
        ALTER TABLE public.agent_finding DROP CONSTRAINT IF EXISTS agent_finding_kind_chk;
        ALTER TABLE public.agent_finding ADD CONSTRAINT agent_finding_kind_chk
            CHECK (kind IN ('shared_role', 'human_credentials', 'long_lived_key', 'model_key_secret',
                            'ai_config_hint', 'ai_network_traffic'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.cloud_dns_cursor (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id    uuid        NOT NULL,
    region          text        NOT NULL,
    stream          text        NOT NULL DEFAULT 'dns',
    -- The CloudWatch Logs log group a Resolver query logging configuration
    -- writes to (its ARN, without ":*").
    log_group_arn   text        NOT NULL,
    window_from     timestamptz NOT NULL,
    covered_from    timestamptz NOT NULL,
    -- The high-water mark the next read starts from (exclusive end).
    read_to         timestamptz NOT NULL,
    partial         boolean     NOT NULL DEFAULT false,
    -- truncated | lapsed | truncated,lapsed; '' when whole.
    partial_reason  text        NOT NULL DEFAULT '',
    -- Logs Insights statistics of the last read: what the customer paid for.
    records_scanned bigint      NOT NULL DEFAULT 0,
    bytes_scanned   bigint      NOT NULL DEFAULT 0,
    -- Groups (source, VPC, model host) the last read returned.
    groups          integer     NOT NULL DEFAULT 0,
    last_error      text        NOT NULL DEFAULT '',
    last_attempt_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_dns_cursor_stream_chk CHECK (stream IN ('dns')),
    CONSTRAINT cloud_dns_cursor_region_chk CHECK (region <> ''),
    CONSTRAINT cloud_dns_cursor_log_group_chk CHECK (log_group_arn <> ''),
    CONSTRAINT cloud_dns_cursor_window_chk
        CHECK (window_from <= read_to AND covered_from <= read_to),
    CONSTRAINT cloud_dns_cursor_counts_chk
        CHECK (records_scanned >= 0 AND bytes_scanned >= 0 AND groups >= 0),
    CONSTRAINT cloud_dns_cursor_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    -- One cursor per log group per region per connector. Leads with
    -- workspace_id, so it is also the table's workspace index.
    CONSTRAINT uq_cloud_dns_cursor
        UNIQUE (workspace_id, connector_id, region, stream, log_group_arn)
);

COMMENT ON TABLE public.cloud_dns_cursor IS
    'How far each Route 53 Resolver query-log group (CloudWatch Logs) was read for model-endpoint lookups, per connector and region; counts only, no DNS data.';

-- Required for every workspace table; guarded as in 139 and 146.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.cloud_dns_cursor');
    END IF;
END $$;
