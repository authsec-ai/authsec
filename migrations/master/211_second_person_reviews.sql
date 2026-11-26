-- ============================================================================
-- 211: one second-person rule for every tier-3 mechanism
-- (SPEC-secops-backend-upgrade.md P3, decision 4; W5, services/second_person.go).
--
-- 1. Break-glass reviews. pending_change (163), agent_detection_rule_version
--    (164) and agent_alert_suppression (166) recorded break_glass and
--    review_due_at but had nowhere to record the review, so a break-glass
--    change stayed due forever. They get reviewed_by / reviewed_at, like
--    agent_capability_declaration (170), audit_governance_change (168) and
--    iga_history_approval (201); the reviewer is never the requester.
-- 2. agent_pending_change (177) had no break-glass at all: a workspace with
--    one admin could never lower a risk class or a classification. It gets
--    break_glass, review_due_at, reviewed_by, reviewed_at; the second-person
--    CHECK admits exactly one exception, a break-glass row applied by its
--    requester.
--
-- No data is migrated: every new column is NULL or false on existing rows.
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

ALTER TABLE public.pending_change ADD COLUMN IF NOT EXISTS reviewed_by uuid REFERENCES public.users(id);
ALTER TABLE public.pending_change ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE public.pending_change DROP CONSTRAINT IF EXISTS pending_change_review_chk;
ALTER TABLE public.pending_change ADD CONSTRAINT pending_change_review_chk
    CHECK ((reviewed_at IS NULL) = (reviewed_by IS NULL) AND (reviewed_by IS NULL OR reviewed_by <> requested_by));

ALTER TABLE public.agent_detection_rule_version ADD COLUMN IF NOT EXISTS reviewed_by uuid;
ALTER TABLE public.agent_detection_rule_version ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE public.agent_detection_rule_version DROP CONSTRAINT IF EXISTS agent_detection_rule_version_review_chk;
ALTER TABLE public.agent_detection_rule_version ADD CONSTRAINT agent_detection_rule_version_review_chk
    CHECK ((reviewed_at IS NULL) = (reviewed_by IS NULL)
           AND (reviewed_by IS NULL OR proposed_by IS NULL OR reviewed_by <> proposed_by));

ALTER TABLE public.agent_alert_suppression ADD COLUMN IF NOT EXISTS reviewed_by uuid;
ALTER TABLE public.agent_alert_suppression ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE public.agent_alert_suppression DROP CONSTRAINT IF EXISTS agent_alert_suppression_review_chk;
ALTER TABLE public.agent_alert_suppression ADD CONSTRAINT agent_alert_suppression_review_chk
    CHECK ((reviewed_at IS NULL) = (reviewed_by IS NULL) AND (reviewed_by IS NULL OR reviewed_by <> requested_by));

ALTER TABLE public.agent_pending_change ADD COLUMN IF NOT EXISTS break_glass boolean NOT NULL DEFAULT false;
ALTER TABLE public.agent_pending_change ADD COLUMN IF NOT EXISTS review_due_at timestamptz;
ALTER TABLE public.agent_pending_change ADD COLUMN IF NOT EXISTS reviewed_by uuid;
ALTER TABLE public.agent_pending_change ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE public.agent_pending_change DROP CONSTRAINT IF EXISTS agent_pending_change_second_person_chk;
ALTER TABLE public.agent_pending_change ADD CONSTRAINT agent_pending_change_second_person_chk
    CHECK (state NOT IN ('applied', 'rejected') OR decided_by <> requested_by OR (break_glass AND state = 'applied'));
ALTER TABLE public.agent_pending_change DROP CONSTRAINT IF EXISTS agent_pending_change_break_glass_chk;
ALTER TABLE public.agent_pending_change ADD CONSTRAINT agent_pending_change_break_glass_chk
    CHECK (NOT break_glass OR (state = 'applied' AND review_due_at IS NOT NULL));
ALTER TABLE public.agent_pending_change DROP CONSTRAINT IF EXISTS agent_pending_change_review_chk;
ALTER TABLE public.agent_pending_change ADD CONSTRAINT agent_pending_change_review_chk
    CHECK ((reviewed_at IS NULL) = (reviewed_by IS NULL) AND (reviewed_by IS NULL OR reviewed_by <> requested_by));
