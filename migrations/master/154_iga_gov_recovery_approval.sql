-- 154_iga_gov_recovery_approval.sql — recovery-plan approval, accepted drift, author notices.
--
-- expand only. Idempotent: safe to run again.
--
-- WHY
-- §8.9: a blocked undo (artifact_consumers_changed) offers a role-only recovery
-- plan whose hash is not in the original approval, "so it needs its own
-- approval (or governance:emergency)". Until now the only way to give it one
-- was the emergency path: uq_iga_gov_approval_live allows ONE live approve row
-- per version, and the deployment's foreign key (workspace_id, approval_id,
-- version_id) requires an iga_gov_approval row of that version, so a second
-- approval of the same version could not be stored.
--
-- A recovery approval is a row of the same table, scoped to one plan:
--
--   scope = 'version'   the approval of a proposal (every row so far)
--   scope = 'recovery'  the approval of ONE side plan (recovery_plan_id), with
--                       plan_hashes = {that plan's hash}; it never marks the
--                       version approved and never counts as its live approval
--
-- uq_iga_gov_approval_live now applies to scope = 'version' only; a recovery
-- plan has at most one live approval of its own (uq_iga_gov_approval_recovery).
-- Readers of "the version's approval" filter scope = 'version'.

ALTER TABLE iga_gov_approval ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'version';
ALTER TABLE iga_gov_approval ADD COLUMN IF NOT EXISTS recovery_plan_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_gov_approval_scope_chk' AND conrelid = 'iga_gov_approval'::regclass) THEN
    ALTER TABLE iga_gov_approval ADD CONSTRAINT iga_gov_approval_scope_chk CHECK (
      scope IN ('version','recovery')
      AND ((scope = 'recovery') = (recovery_plan_id IS NOT NULL))
      AND (scope = 'version' OR decision = 'approve'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_gov_approval_recovery_plan_fkey' AND conrelid = 'iga_gov_approval'::regclass) THEN
    ALTER TABLE iga_gov_approval ADD CONSTRAINT iga_gov_approval_recovery_plan_fkey
      FOREIGN KEY (workspace_id, recovery_plan_id, version_id) REFERENCES iga_gov_plan (workspace_id, id, version_id);
  END IF;
END $$;

DROP INDEX IF EXISTS uq_iga_gov_approval_live;
CREATE UNIQUE INDEX uq_iga_gov_approval_live
  ON iga_gov_approval (version_id) WHERE decision = 'approve' AND revoked_at IS NULL AND scope = 'version';
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_approval_recovery
  ON iga_gov_approval (recovery_plan_id) WHERE scope = 'recovery' AND decision = 'approve' AND revoked_at IS NULL;

-- ACCEPTED DRIFT (§8.8)
-- "Accept drift" closes a drifted deployment: the deployment stays `drifted`
-- (it still describes what AuthSec applied, which AWS no longer matches) and
-- records who accepted it, when and why, so the console stops offering the
-- choice and the event log keeps the decision. The actor is an audit
-- reference like emergency_by: NO ACTION, so the user survives their record.
ALTER TABLE iga_gov_deployment ADD COLUMN IF NOT EXISTS drift_accepted_at timestamptz;
ALTER TABLE iga_gov_deployment ADD COLUMN IF NOT EXISTS drift_accepted_by uuid REFERENCES users(id);
ALTER TABLE iga_gov_deployment ADD COLUMN IF NOT EXISTS drift_accepted_reason text NOT NULL DEFAULT '';

-- AUTHOR NOTICE (§9.3 S4)
-- "Keep a service" and "This will break something" create a version or block
-- one, "and tell the author". The notice is its own subject kind, review_response,
-- one row per (review, channel, recipient), resent on each new response.
ALTER TABLE iga_gov_notification DROP CONSTRAINT IF EXISTS iga_gov_notification_subject_kind_check;
ALTER TABLE iga_gov_notification ADD CONSTRAINT iga_gov_notification_subject_kind_check
  CHECK (subject_kind IN ('owner_review','approval_request','deployment','drift','canary_gate','finding_digest','temporary_grant','session_revocation','time_bound','agent_alert','review_response'));
