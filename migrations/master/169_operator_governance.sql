-- ============================================================================
-- 169: operator governance (SPEC-secops-backend-upgrade.md P18 / W5, AS-177).
--
-- operator_activity_hour: per workspace, operator (audit_events.user_id) and
-- hour, the console writes, the elevated (tier 2/3) writes and the exports
-- the operator made, counted from audit_events by the hourly baseline job.
-- Reads are not counted: audit_events records writes only.
--
-- operator_alert: an hour in which an operator's count exceeded their
-- baseline (max(10, 3 x the trailing 14-day p95 of their hourly counts)).
--
-- operator_suspension: an operator suspended in a workspace (governance:
-- emergency). The suspension sets the membership to 'suspended' (or, for a
-- user with no membership row, deactivates the user of that home workspace);
-- AuthMiddleware re-checks on every request, so the next request fails.
-- Lifting it is a tier-3 change (audit_governance_change, kind
-- operator_unsuspend).
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.operator_activity_hour (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    user_id      text        NOT NULL,
    hour         timestamptz NOT NULL,
    writes       integer     NOT NULL DEFAULT 0,
    elevated     integer     NOT NULL DEFAULT 0,
    exports      integer     NOT NULL DEFAULT 0,
    computed_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operator_activity_hour_counts_chk CHECK (writes >= 0 AND elevated >= 0 AND exports >= 0),
    CONSTRAINT operator_activity_hour_pkey PRIMARY KEY (workspace_id, user_id, hour)
);

CREATE TABLE IF NOT EXISTS public.operator_alert (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    user_id      text        NOT NULL,
    hour         timestamptz NOT NULL,
    metric       text        NOT NULL,
    observed     integer     NOT NULL,
    baseline_p95 numeric     NOT NULL,
    threshold    integer     NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operator_alert_metric_chk CHECK (metric IN ('writes', 'elevated', 'exports')),
    CONSTRAINT uq_operator_alert UNIQUE (workspace_id, user_id, hour, metric)
);
CREATE INDEX IF NOT EXISTS idx_operator_alert_ws_time
    ON public.operator_alert (workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.operator_suspension (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    user_id        uuid        NOT NULL,
    mechanism      text        NOT NULL,
    membership_id  uuid,
    reason         text        NOT NULL,
    suspended_by   uuid        NOT NULL,
    suspended_at   timestamptz NOT NULL DEFAULT now(),
    lifted_at      timestamptz,
    lifted_by      uuid,
    lift_change_id uuid,
    CONSTRAINT operator_suspension_mechanism_chk CHECK (mechanism IN ('membership', 'user')),
    CONSTRAINT operator_suspension_reason_chk CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
    CONSTRAINT operator_suspension_self_chk CHECK (suspended_by <> user_id),
    CONSTRAINT uq_operator_suspension_ws_id UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_operator_suspension_live
    ON public.operator_suspension (workspace_id, user_id) WHERE lifted_at IS NULL;

COMMENT ON TABLE public.operator_activity_hour IS
    'Hourly console writes, elevated (tier 2/3) writes and exports per operator, from audit_events.';
COMMENT ON TABLE public.operator_alert IS
    'Hours in which an operator exceeded their baseline (max(10, 3 x trailing 14-day p95)).';
COMMENT ON TABLE public.operator_suspension IS
    'Operators suspended in a workspace (governance:emergency); lifted by a second person.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.operator_activity_hour');
        PERFORM public.tenancy_enable_rls('public.operator_alert');
        PERFORM public.tenancy_enable_rls('public.operator_suspension');
    END IF;
END $$;
