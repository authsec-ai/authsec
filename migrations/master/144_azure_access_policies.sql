-- 144_azure_access_policies.sql
--
-- Access policies on Azure resources. An access policy (137) names roles and a
-- resource; on Azure its deployment is not an IAM policy document but role
-- assignments:
--   allow  AuthSec creates one role assignment (a built-in role for the access
--          level) for the principal on the resource, and deletes it at the end;
--   block  AuthSec removes the principal's own role assignments on the resource
--          that grant the access, records each exactly, and restores them at
--          the end (Azure RBAC has no customer deny).
--
-- 1. iga_gov_azure_access: one row per principal per access-policy version,
--    run by the azure_access job.
-- 2. iga_gov_job_kind_check admits 'azure_access'.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS iga_gov_azure_access (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id           uuid NOT NULL,
  version_id          uuid NOT NULL,
  connector_id        uuid NOT NULL,
  identity_account_id uuid NOT NULL,
  tenant_id           text NOT NULL,
  subscription_id     text NOT NULL,
  principal_id        text NOT NULL,
  principal_type      text NOT NULL DEFAULT 'ServicePrincipal',
  principal_name      text NOT NULL DEFAULT '',
  scope               text NOT NULL CHECK (scope LIKE '/subscriptions/%'),
  effect              text NOT NULL CHECK (effect IN ('allow','deny')),
  access              jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- allow: the role AuthSec assigns and the assignment's fixed name.
  role_definition_id  text NOT NULL DEFAULT '',
  assignment_name     text NOT NULL DEFAULT '',
  -- block: the assignments removed, each as it was (azure.RoleAssignmentSpec).
  revoked             jsonb NOT NULL DEFAULT '[]'::jsonb,
  state               text NOT NULL DEFAULT 'approved' CHECK (state IN ('approved','deploying','active','expiring','expired','revoked','failed')),
  state_reason        text NOT NULL DEFAULT '',
  end_reason          text NOT NULL DEFAULT '',
  drift               text NOT NULL DEFAULT '',
  starts_at           timestamptz,
  expires_at          timestamptz NOT NULL,
  deployed_at         timestamptz,
  verified_at         timestamptz,
  last_readback_at    timestamptz,
  ended_at            timestamptz,
  created_by          uuid NOT NULL REFERENCES users(id),
  ops                 jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, version_id, policy_id) REFERENCES iga_gov_access_policy_version (workspace_id, id, policy_id),
  CONSTRAINT iga_gov_aa_window_chk CHECK (expires_at > created_at AND (starts_at IS NULL OR starts_at < expires_at))
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_azure_access_policy ON iga_gov_azure_access (workspace_id, policy_id, version_id);
CREATE INDEX IF NOT EXISTS idx_iga_gov_azure_access_live ON iga_gov_azure_access (state)
  WHERE state IN ('approved','deploying','active','expiring');

DO $$
BEGIN
    IF to_regclass('public.iga_gov_job') IS NOT NULL THEN
        ALTER TABLE public.iga_gov_job DROP CONSTRAINT IF EXISTS iga_gov_job_kind_check;
        ALTER TABLE public.iga_gov_job ADD CONSTRAINT iga_gov_job_kind_check
            CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                            'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync',
                            'prune_evidence','metrics_rollup','resolve_unknown',
                            'temp_grant','session_revoke','time_bound','azure_access'));
    END IF;
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_gov_azure_access');
    END IF;
END $$;
