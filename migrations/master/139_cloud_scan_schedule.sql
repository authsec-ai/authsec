-- ============================================================================
-- 139: per-connector schedule for automatic AWS rescans.
--
-- Until now an AWS connector was scanned only when a person pressed "Scan now".
-- This table says WHEN a connector should rescan itself. It holds the schedule
-- and nothing else: the scans it causes are ordinary cloud_scan_run rows
-- (trigger = 'scheduled'), run by the existing scan worker.
--
-- WHY A TABLE AND NOT COLUMNS ON cloud_connector. That table is a shared
-- contract with the Azure and GCP connectors, and attrs is the AWS onboarding
-- blob the region PATCH rewrites. A separate table touches neither.
--
-- NO FAILURE COUNTER. Whether a schedule should pause is derived from the last
-- runs' own outcomes, so it cannot drift from the run history.
--
-- A missing row means "never scheduled", the same as enabled = false.
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_scan_schedule (
    connector_id     uuid        PRIMARY KEY,
    workspace_id     uuid        NOT NULL,
    enabled          boolean     NOT NULL DEFAULT false,
    -- 6 hours .. 7 days. Hourly is deliberately not offered (API cost and
    -- throttling for little gain until events exist).
    interval_minutes integer     NOT NULL DEFAULT 1440,
    next_due_at      timestamptz,
    last_enqueued_at timestamptz,
    -- Scheduled runs older than this do not count toward the pause decision.
    -- Set when the schedule is turned on or resumed, so a resumed schedule is
    -- not paused again by the failures that paused it.
    streak_since     timestamptz,
    -- '' = not paused. Otherwise a short code and the last error.
    paused_reason    text        NOT NULL DEFAULT '',
    updated_by       text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_scan_schedule_interval_chk
        CHECK (interval_minutes BETWEEN 360 AND 10080),
    -- Workspace-qualified, like every cloud_* table (027): a schedule cannot
    -- name another workspace's connector.
    CONSTRAINT cloud_scan_schedule_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE
);

-- The scheduler's due-scan query reads only schedules that are on and not paused.
CREATE INDEX IF NOT EXISTS idx_cloud_scan_schedule_due
    ON public.cloud_scan_schedule (next_due_at)
    WHERE enabled AND paused_reason = '';

COMMENT ON TABLE public.cloud_scan_schedule IS
    'When an AWS connector rescans itself. The scans it causes are cloud_scan_run rows with trigger = scheduled.';

-- Required for every workspace table; guarded as in 137_access_policies.sql.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.cloud_scan_schedule');
    END IF;
END $$;
