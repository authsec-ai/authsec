-- ============================================================================
-- 168: audit retention per workspace and record class, legal holds, and the
-- second-person changes of audit governance (SPEC-secops-backend-upgrade.md
-- F7, DECISIONS 4 and 5, AS-177).
--
-- audit_retention_policy: how long a workspace keeps each record class of
-- audit_events (admin_change, auth, access_decision, export, default). A
-- missing row means the built-in default (services.DefaultAuditRetentionDays).
-- 7 days to 7 years.
--
-- audit_legal_hold: a window of audit_events (by timestamp) the retention job
-- must not delete while the hold is live. Placing a hold is immediate;
-- releasing one is a tier-3 change.
--
-- audit_governance_change: a tier-3 (loosening) change waiting for a second
-- person: shortening a retention, releasing a legal hold, lifting an
-- operator suspension. The approver must hold governance:approve and must not
-- be the requester (checked by the service and by the CHECK below). A
-- workspace with no other governance:approve holder may apply it alone
-- (break_glass), which records a review due within 24 hours.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.audit_retention_policy (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    record_class text        NOT NULL,
    retain_days  integer     NOT NULL,
    updated_by   uuid,
    change_id    uuid,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_retention_policy_class_chk
        CHECK (record_class IN ('admin_change', 'auth', 'access_decision', 'export', 'default')),
    CONSTRAINT audit_retention_policy_days_chk CHECK (retain_days BETWEEN 7 AND 2557),
    CONSTRAINT audit_retention_policy_pkey PRIMARY KEY (workspace_id, record_class)
);

CREATE TABLE IF NOT EXISTS public.audit_legal_hold (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id      uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    from_ts           timestamptz NOT NULL,
    to_ts             timestamptz NOT NULL,
    reason            text        NOT NULL,
    created_by        uuid        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    released_at       timestamptz,
    released_by       uuid,
    release_change_id uuid,
    CONSTRAINT audit_legal_hold_window_chk CHECK (to_ts > from_ts),
    CONSTRAINT audit_legal_hold_reason_chk CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
    CONSTRAINT uq_audit_legal_hold_ws_id UNIQUE (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS idx_audit_legal_hold_live
    ON public.audit_legal_hold (workspace_id, from_ts, to_ts) WHERE released_at IS NULL;

CREATE TABLE IF NOT EXISTS public.audit_governance_change (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    kind            text        NOT NULL,
    target          text        NOT NULL,
    payload         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    reason          text        NOT NULL,
    status          text        NOT NULL DEFAULT 'pending',
    requested_by    uuid        NOT NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    decided_by      uuid,
    decided_at      timestamptz,
    decision_reason text,
    break_glass     boolean     NOT NULL DEFAULT false,
    review_due_at   timestamptz,
    reviewed_by     uuid,
    reviewed_at     timestamptz,
    CONSTRAINT audit_governance_change_kind_chk
        CHECK (kind IN ('retention_shorten', 'legal_hold_release', 'operator_unsuspend')),
    CONSTRAINT audit_governance_change_status_chk
        CHECK (status IN ('pending', 'applied', 'rejected', 'withdrawn', 'expired')),
    CONSTRAINT audit_governance_change_reason_chk CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
    -- Separation of duties: nobody approves or rejects their own request;
    -- only break-glass applies alone, and then someone else reviews it.
    CONSTRAINT audit_governance_change_second_person_chk
        CHECK (decided_by IS NULL OR break_glass OR status = 'withdrawn' OR decided_by <> requested_by),
    CONSTRAINT audit_governance_change_break_glass_chk CHECK (NOT break_glass OR review_due_at IS NOT NULL),
    CONSTRAINT audit_governance_change_reviewer_chk CHECK (reviewed_by IS NULL OR reviewed_by <> requested_by),
    CONSTRAINT uq_audit_governance_change_ws_id UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_governance_change_pending
    ON public.audit_governance_change (workspace_id, kind, target) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_audit_governance_change_ws_status
    ON public.audit_governance_change (workspace_id, status, requested_at);

COMMENT ON TABLE public.audit_retention_policy IS
    'Audit retention per workspace and record class (days); missing rows use the built-in defaults.';
COMMENT ON TABLE public.audit_legal_hold IS
    'Windows of audit_events the retention job must keep while the hold is live.';
COMMENT ON TABLE public.audit_governance_change IS
    'Tier-3 audit governance changes (shorter retention, hold release, unsuspend) awaiting or applied by a second person.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.audit_retention_policy');
        PERFORM public.tenancy_enable_rls('public.audit_legal_hold');
        PERFORM public.tenancy_enable_rls('public.audit_governance_change');
    END IF;
END $$;
