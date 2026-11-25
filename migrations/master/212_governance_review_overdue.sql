-- ============================================================================
-- 212: overdue break-glass reviews (SPEC-secops-backend-upgrade.md P3,
-- decision 4; W5, services/governance_approvals.go).
--
-- 1. governance_review_overdue: one row per break-glass change (of any of
--    the seven second-person kinds) whose review passed its due time
--    unreviewed. The worker inserts it in the same transaction as the
--    governance.review_overdue event, so each item raises exactly one event,
--    whatever the number of replicas.
-- 2. operator_alert (169) admits metric review_overdue: the operator who
--    applied a change alone is listed among operator alerts once its review
--    is overdue (one row per operator and hour of the due time).
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.governance_review_overdue (
    workspace_id  uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    kind          text        NOT NULL CHECK (kind ~ '^[a-z_]{1,64}$'),
    item_id       uuid        NOT NULL,
    requested_by  uuid,
    review_due_at timestamptz NOT NULL,
    raised_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT governance_review_overdue_pkey PRIMARY KEY (workspace_id, kind, item_id)
);
CREATE INDEX IF NOT EXISTS idx_governance_review_overdue_ws_raised
    ON public.governance_review_overdue (workspace_id, raised_at DESC);

ALTER TABLE public.operator_alert DROP CONSTRAINT IF EXISTS operator_alert_metric_chk;
ALTER TABLE public.operator_alert ADD CONSTRAINT operator_alert_metric_chk
    CHECK (metric IN ('writes', 'elevated', 'exports', 'review_overdue'));

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.governance_review_overdue');
    END IF;
END $$;
