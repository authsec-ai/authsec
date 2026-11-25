-- ============================================================================
-- 165: agent alert lifecycle (SecOps F8, AS-180).
--
-- 1. agent_alert.state admits 'reopened' (a resolved alert reopened with a
--    reason); severity admits 'low'.
-- 2. Per-transition actors on the alert: acknowledged_by/at, resolved_by/at
--    and the resolution's outcome code (true_positive | benign |
--    false_positive | duplicate), reopened_by/at and reopen_count.
--    Resolving no longer overwrites who acknowledged. state_changed_by/at
--    stay: the latest transition.
-- 3. agent_alert_transition: every acknowledge / resolve / reopen, with its
--    actor, outcome and reason, in order. Rows are only inserted; they go
--    with their alert (retention). The summary columns of (2) show the
--    latest cycle; this table keeps every cycle.
--
-- Existing acknowledged and resolved alerts get their summary columns from
-- state_changed_by/at; their outcome stays NULL (it was never recorded).
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_state_check;
ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_state_check
    CHECK (state IN ('open', 'acknowledged', 'resolved', 'reopened'));
ALTER TABLE public.agent_alert DROP CONSTRAINT IF EXISTS agent_alert_severity_check;
ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_severity_check
    CHECK (severity IN ('high', 'medium', 'low'));

ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS acknowledged_by uuid;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS resolved_by     uuid;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS resolved_at     timestamptz;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS outcome         text;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS reopened_by     uuid;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS reopened_at     timestamptz;
ALTER TABLE public.agent_alert ADD COLUMN IF NOT EXISTS reopen_count    integer NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_alert_outcome_check'
                      AND conrelid = 'public.agent_alert'::regclass) THEN
        ALTER TABLE public.agent_alert ADD CONSTRAINT agent_alert_outcome_check
            CHECK (outcome IS NULL OR outcome IN ('true_positive', 'benign', 'false_positive', 'duplicate'));
    END IF;
END $$;

UPDATE public.agent_alert SET acknowledged_by = state_changed_by, acknowledged_at = state_changed_at
 WHERE state = 'acknowledged' AND acknowledged_at IS NULL AND state_changed_at IS NOT NULL;
UPDATE public.agent_alert SET resolved_by = state_changed_by, resolved_at = state_changed_at
 WHERE state = 'resolved' AND resolved_at IS NULL AND state_changed_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.agent_alert_transition (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    alert_id     uuid        NOT NULL,
    from_state   text        NOT NULL,
    to_state     text        NOT NULL CHECK (to_state IN ('acknowledged', 'resolved', 'reopened')),
    actor_id     uuid        NOT NULL,
    outcome      text        CHECK (outcome IS NULL OR outcome IN ('true_positive', 'benign', 'false_positive', 'duplicate')),
    reason       text        NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
    at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, alert_id) REFERENCES public.agent_alert (workspace_id, id) ON DELETE CASCADE,
    -- A resolution always carries its outcome; nothing else does.
    CONSTRAINT agent_alert_transition_outcome_chk CHECK ((to_state = 'resolved') = (outcome IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_agent_alert_transition_alert
    ON public.agent_alert_transition (workspace_id, alert_id, at);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_alert_transition');
    END IF;
END $$;
