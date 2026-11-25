-- ============================================================================
-- 164: versioned detection rules (SecOps F6, AS-179).
--
-- agent_alert_setting was one row per workspace, overwritten in place, and
-- its audit row carried only the new value. Every change is now a row of
-- agent_detection_rule_version:
--
--   proposed    a loosening change (a detection disabled, a threshold raised,
--               a severity lowered, Slack off, a longer dedupe window, a
--               shorter retention) waiting for a second person holding
--               governance:approve (tier 3; approved_by <> proposed_by)
--   active      the version the detections read (at most one per workspace)
--   rejected    a proposal turned down
--   superseded  a version that was active, or a proposal overtaken by a newer
--               active version
--
-- A tightening change is active at once. break_glass marks a loosening that
-- the workspace's only governance:approve holder applied alone; it is due a
-- review within 24 hours (review_due_at).
--
-- Every existing agent_alert_setting row becomes the workspace's version 1,
-- active. agent_alert_setting stays (it mirrors the active version) until a
-- contract migration retires it.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.agent_detection_rule_version (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id          uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    version_no            integer     NOT NULL CHECK (version_no >= 1),
    -- The version this one was proposed against (NULL for the first).
    base_version_no       integer,
    -- Same shape as agent_alert_setting.detections:
    -- {"D5": {"enabled": true, "n": 10, "minutes": 5, "severity": ""}, ...}
    detections            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    slack_enabled         boolean     NOT NULL DEFAULT true,
    dedupe_window_minutes integer     NOT NULL DEFAULT 60 CHECK (dedupe_window_minutes BETWEEN 5 AND 1440),
    retention_days        integer     NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 7 AND 3650),
    -- The loosening changes this version makes over its base ([] = none).
    loosening             jsonb       NOT NULL DEFAULT '[]'::jsonb,
    state                 text        NOT NULL CHECK (state IN ('proposed', 'active', 'rejected', 'superseded')),
    proposed_by           uuid,
    proposed_at           timestamptz NOT NULL DEFAULT now(),
    approved_by           uuid,
    approved_at           timestamptz,
    rejected_by           uuid,
    rejected_at           timestamptz,
    activated_at          timestamptz,
    superseded_at         timestamptz,
    reason                text        NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
    break_glass           boolean     NOT NULL DEFAULT false,
    review_due_at         timestamptz,
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, version_no),
    -- Separation of duties: nobody approves their own proposal.
    CONSTRAINT agent_detection_rule_version_sod_chk
        CHECK (approved_by IS NULL OR proposed_by IS NULL OR approved_by <> proposed_by),
    CONSTRAINT agent_detection_rule_version_approved_chk
        CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT agent_detection_rule_version_break_glass_chk
        CHECK (NOT break_glass OR review_due_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_agent_detection_rule_version_ws
    ON public.agent_detection_rule_version (workspace_id, version_no DESC);
-- One active version, and at most one open proposal, per workspace.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_detection_rule_version_active
    ON public.agent_detection_rule_version (workspace_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_detection_rule_version_proposed
    ON public.agent_detection_rule_version (workspace_id) WHERE state = 'proposed';

-- Existing settings become version 1, active.
INSERT INTO public.agent_detection_rule_version (workspace_id, version_no, detections, slack_enabled, dedupe_window_minutes,
                                                 retention_days, state, proposed_by, proposed_at, activated_at, reason)
SELECT s.workspace_id, 1, s.detections, s.slack_enabled, s.dedupe_window_minutes, s.retention_days, 'active',
       s.updated_by, s.updated_at, s.updated_at, 'migrated from agent_alert_setting'
  FROM public.agent_alert_setting s
 WHERE NOT EXISTS (SELECT 1 FROM public.agent_detection_rule_version v WHERE v.workspace_id = s.workspace_id);

COMMENT ON TABLE public.agent_detection_rule_version IS
    'Versioned agent runtime detection rules: loosening changes need a second person (tier 3); every change is an iga_gov_event.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_detection_rule_version');
    END IF;
END $$;
