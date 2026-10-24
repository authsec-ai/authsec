-- 146_k8s_access_policies.sql
--
-- Access policies on Kubernetes (block only in this release). A block names a
-- Role or ClusterRole and ServiceAccounts: AuthSec removes each ServiceAccount
-- from every binding of that role (through the in-cluster agent), records the
-- binding as it was, and puts the subject back at the end.
--
-- 1. iga_gov_k8s_access: one row per (ServiceAccount, binding) per
--    access-policy version, run by the k8s_access job.
-- 2. iga_gov_job_kind_check admits 'k8s_access'.
-- 3. provisioning_instructions_kind_chk admits 'remove_binding_subject' and
--    'restore_binding_subject'.
-- 4. discovery_sources.enforcement_bindings: the agent reports it may change
--    bindings (its chart's enforcement.bindings switch), as it reports evict.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS iga_gov_k8s_access (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id           uuid NOT NULL,
  version_id          uuid NOT NULL,
  -- The discovery source (in-cluster agent) that saw the binding and acts on it.
  connector_id        uuid NOT NULL,
  identity_account_id uuid NOT NULL,
  cluster             text NOT NULL CHECK (cluster <> ''),
  binding_kind        text NOT NULL CHECK (binding_kind IN ('RoleBinding','ClusterRoleBinding')),
  binding_namespace   text NOT NULL DEFAULT '',
  binding_name        text NOT NULL CHECK (binding_name <> ''),
  role_kind           text NOT NULL CHECK (role_kind IN ('Role','ClusterRole')),
  role_name           text NOT NULL,
  -- The subject removed: {kind, name, namespace}.
  subject             jsonb NOT NULL,
  effect              text NOT NULL CHECK (effect IN ('deny')),
  access              jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- What the agent reported removing: the binding's uid and the subject's
  -- position, so the restore re-adds it to the same object only.
  removed             jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- The open instruction the row waits on (provisioning_instructions.id).
  instruction_id      uuid,
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
  CONSTRAINT iga_gov_ka_window_chk CHECK (expires_at > created_at AND (starts_at IS NULL OR starts_at < expires_at)),
  CONSTRAINT iga_gov_ka_namespace_chk CHECK ((binding_kind = 'RoleBinding') = (binding_namespace <> ''))
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_k8s_access_policy ON iga_gov_k8s_access (workspace_id, policy_id, version_id);
CREATE INDEX IF NOT EXISTS idx_iga_gov_k8s_access_live ON iga_gov_k8s_access (state)
  WHERE state IN ('approved','deploying','active','expiring');

ALTER TABLE public.discovery_sources ADD COLUMN IF NOT EXISTS enforcement_bindings boolean NOT NULL DEFAULT false;

DO $$
BEGIN
    IF to_regclass('public.iga_gov_job') IS NOT NULL THEN
        ALTER TABLE public.iga_gov_job DROP CONSTRAINT IF EXISTS iga_gov_job_kind_check;
        ALTER TABLE public.iga_gov_job ADD CONSTRAINT iga_gov_job_kind_check
            CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                            'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync',
                            'prune_evidence','metrics_rollup','resolve_unknown',
                            'temp_grant','session_revoke','time_bound','azure_access','k8s_access'));
    END IF;
    IF to_regclass('public.provisioning_instructions') IS NOT NULL THEN
        ALTER TABLE public.provisioning_instructions DROP CONSTRAINT IF EXISTS provisioning_instructions_kind_chk;
        ALTER TABLE public.provisioning_instructions ADD CONSTRAINT provisioning_instructions_kind_chk
            CHECK (kind IN ('quarantine', 'unquarantine', 'verify_uptake',
                            'evict_pods', 'delete_workload', 'force_delete_pods',
                            'remove_binding_subject', 'restore_binding_subject'));
    END IF;
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_gov_k8s_access');
    END IF;
END $$;
