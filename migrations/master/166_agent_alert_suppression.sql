-- ============================================================================
-- 166: agent alert suppressions (SecOps P6, AS-179/AS-180 follow-on).
--
-- A suppression keeps the alerts of one agent identity and one detection
-- (optionally one instance digest) from being delivered to Slack and SIEM
-- for at most 90 days. The alerts are still stored, with suppressed_by set.
--
--   proposed  requested; a second person holding governance:approve
--             approves (tier 3; approved_by <> requested_by)
--   active    in force between starts_at and ends_at
--   rejected  turned down
--   ended     ended early by a member, or replaced by its approved renewal
--   expired   reached ends_at
--
-- A suppression never silences an alert recording a succeeded harmful
-- outcome (services/agent_runtime_alert_suppression.go): it cannot name
-- D1-D4 or D7, which fire only on a call that succeeded.
-- renewals counts the earlier suppressions of the same identity and
-- detection that came into force (per agent x rule, however requested).
-- break_glass marks one the workspace's only governance:approve holder
-- applied alone; it is due a review within 24 hours.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_alert_suppression (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    identity_id     uuid        NOT NULL,
    detection       text        NOT NULL CHECK (detection IN ('D1','D2','D3','D4','D5','D6','D7','D8')),
    instance_digest text        NOT NULL DEFAULT '' CHECK (length(instance_digest) <= 200),
    reason          text        NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    duration_days   integer     NOT NULL CHECK (duration_days BETWEEN 1 AND 90),
    state           text        NOT NULL CHECK (state IN ('proposed', 'active', 'rejected', 'ended', 'expired')),
    renewal_of      uuid,
    renewals        integer     NOT NULL DEFAULT 0 CHECK (renewals >= 0),
    requested_by    uuid        NOT NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    approved_by     uuid,
    approved_at     timestamptz,
    rejected_by     uuid,
    rejected_at     timestamptz,
    starts_at       timestamptz,
    ends_at         timestamptz,
    ended_by        uuid,
    ended_at        timestamptz,
    end_reason      text        NOT NULL DEFAULT '' CHECK (length(end_reason) <= 1000),
    break_glass     boolean     NOT NULL DEFAULT false,
    review_due_at   timestamptz,
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, renewal_of) REFERENCES public.agent_alert_suppression (workspace_id, id),
    CONSTRAINT agent_alert_suppression_sod_chk CHECK (approved_by IS NULL OR approved_by <> requested_by),
    -- In force means a window, never longer than 90 days.
    CONSTRAINT agent_alert_suppression_window_chk CHECK (
        (starts_at IS NULL) = (ends_at IS NULL)
        AND (ends_at IS NULL OR (ends_at > starts_at AND ends_at <= starts_at + interval '90 days'))),
    CONSTRAINT agent_alert_suppression_active_chk CHECK (state NOT IN ('active', 'expired') OR starts_at IS NOT NULL),
    CONSTRAINT agent_alert_suppression_break_glass_chk CHECK (NOT break_glass OR review_due_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_agent_alert_suppression_ws
    ON public.agent_alert_suppression (workspace_id, requested_at DESC, id DESC);
-- The sink's lookup: active suppressions of an identity and detection.
CREATE INDEX IF NOT EXISTS idx_agent_alert_suppression_match
    ON public.agent_alert_suppression (workspace_id, identity_id, detection) WHERE state = 'active';
-- One request waiting and one suppression in force per scope.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_alert_suppression_proposed
    ON public.agent_alert_suppression (workspace_id, identity_id, detection, instance_digest) WHERE state = 'proposed';
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_alert_suppression_active
    ON public.agent_alert_suppression (workspace_id, identity_id, detection, instance_digest) WHERE state = 'active';

-- The suppression that kept an alert from being delivered.
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS suppressed_by uuid;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_alert_suppressed_by_fkey'
                      AND conrelid = 'public.agent_alert'::regclass) THEN
        ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_suppressed_by_fkey
            FOREIGN KEY (workspace_id, suppressed_by) REFERENCES public.agent_alert_suppression (workspace_id, id);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_agent_alert_suppressed_by
    ON public.agent_alert (workspace_id, suppressed_by) WHERE suppressed_by IS NOT NULL;

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_alert_suppression');
    END IF;
END $$;
