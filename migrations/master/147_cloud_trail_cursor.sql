-- ============================================================================
-- 147: CloudTrail read cursors for model-call evidence
-- (SPEC-agent-runtime-visibility.md §5.1, P1a).
--
-- Until now every scan read a fixed 48 hours of CloudTrail per region. A weekly
-- connector therefore never saw five of its seven days, and a model call made
-- six days ago was "not seen". This table records, per (connector, region,
-- stream), how far the last successful read covered, so the next scan reads
-- from there -- bounded by AWS's 90-day LookupEvents limit; the first read
-- covers the full 90 days up to its page cap.
--
-- STREAMS. 'general' is the unfiltered LookupEvents pass the scan always made;
-- 'bedrock' is the focused pass (LookupAttributes EventSource =
-- bedrock.amazonaws.com) with its own page cap. Each has its own cursor: model
-- calls are counted only inside the bedrock window, other services only
-- inside the general window, so no event is counted twice across scans.
--
-- COVERAGE IS NEVER CLAIMED FOR WHAT WAS NOT READ. LookupEvents returns the
-- newest events first, so a read that hits its page cap has covered
-- [covered_from, read_to] and not [window_from, covered_from). Such a read is
-- partial = true and covered_from says how far back it reached; the gap is
-- not re-read (the next read starts at read_to), and it is never reported as
-- "no calls seen". A cursor older than the 90-day limit is partial for the
-- same reason (window_from is then the limit, not the old read_to).
--
-- read_to lags the scan by CloudTrail's delivery delay: events newer than it
-- are read (and recorded as evidence) but not counted until a later scan
-- settles them.
--
-- A failed read does not move the cursor; it records last_error and
-- last_attempt_at on an existing row and nothing else.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_trail_cursor (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id    uuid        NOT NULL,
    region          text        NOT NULL,
    stream          text        NOT NULL,
    -- The window the last successful read was asked to settle: from the
    -- previous read_to (or the 90-day limit) ...
    window_from     timestamptz NOT NULL,
    -- ... how far back it actually reached (= window_from unless a cap was
    -- hit) ...
    covered_from    timestamptz NOT NULL,
    -- ... and the high-water mark the next read starts from.
    read_to         timestamptz NOT NULL,
    partial         boolean     NOT NULL DEFAULT false,
    pages           integer     NOT NULL DEFAULT 0,
    events          integer     NOT NULL DEFAULT 0,
    -- The last failed attempt, '' after a successful one.
    last_error      text        NOT NULL DEFAULT '',
    last_attempt_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_trail_cursor_stream_chk CHECK (stream IN ('general', 'bedrock')),
    CONSTRAINT cloud_trail_cursor_region_chk CHECK (region <> ''),
    CONSTRAINT cloud_trail_cursor_window_chk
        CHECK (window_from <= covered_from AND covered_from <= read_to),
    CONSTRAINT cloud_trail_cursor_counts_chk CHECK (pages >= 0 AND events >= 0),
    -- Workspace-qualified, like every cloud_* table (027): a cursor cannot
    -- name another workspace's connector.
    CONSTRAINT cloud_trail_cursor_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    -- One cursor per stream per region per connector. Leads with
    -- workspace_id, so it is also the table's workspace index.
    CONSTRAINT uq_cloud_trail_cursor
        UNIQUE (workspace_id, connector_id, region, stream)
);

COMMENT ON TABLE public.cloud_trail_cursor IS
    'How far CloudTrail LookupEvents was read per connector, region and stream (general | bedrock); partial = a page cap left [window_from, covered_from) unread.';

-- Required for every workspace table; guarded as in 139_cloud_scan_schedule.sql.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.cloud_trail_cursor');
    END IF;
END $$;
