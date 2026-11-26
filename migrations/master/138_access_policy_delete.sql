-- 138_access_policy_delete.sql
--
-- Deleting an ended access policy hides it from the list and the detail page;
-- its versions, deployments and history stay for the audit trail. The policy's
-- name is freed (the handler renames it) so a new policy can reuse it.
--
-- Expand only: one nullable column. Idempotent: safe to run again.

ALTER TABLE iga_gov_policy ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_iga_gov_policy_not_deleted
  ON iga_gov_policy (workspace_id, family) WHERE deleted_at IS NULL;
