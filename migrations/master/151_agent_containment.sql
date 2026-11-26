-- 151_agent_containment.sql
--
-- Agent containment on AWS (SPEC-agent-runtime-visibility.md §5.8, §10;
-- phase P3): contain an AWS identity of the workspace at the workload,
-- model or identity level, verify it, and release it to the exact recorded
-- before-state.
--
-- 1. agent_containment: one containment of one identity (cloud_identity)
--    at one level, its blast-radius preview as shown when it was requested,
--    its state (previewed -> containing -> contained | partially_contained |
--    failed -> releasing -> released) and its behavioural verification. One
--    LIVE containment per (workspace, identity, level).
-- 2. agent_containment_step: one change per row (Lambda concurrency, ECS
--    desired count, ECS auto scaling, AuthSec IAM policy, session revocation,
--    access key), written BEFORE its AWS write with the exact before-state,
--    so release restores exactly what was there.
-- 3. iga_gov_job_kind_check admits 'agent_contain' (the policy job worker
--    runs containments), keeping every existing kind.
--
-- identity_id and connector_id are deliberately not foreign keys: a
-- containment is a record that outlives a role deleted from AWS (and its
-- cloud_identity row) or a disconnected account.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS agent_containment (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id         uuid NOT NULL,
  identity_id          uuid NOT NULL,
  identity_kind        text NOT NULL CHECK (identity_kind IN ('iam_role','iam_user')),
  identity_arn         text NOT NULL CHECK (identity_arn <> ''),
  -- The identity's AWS unique id (AROA... / AIDA...) at request time: a
  -- role recreated under the same name is not this identity.
  unique_id            text NOT NULL DEFAULT '',
  workload_ids         uuid[] NOT NULL DEFAULT '{}',
  level                text NOT NULL CHECK (level IN ('workload','identity','model')),
  state                text NOT NULL DEFAULT 'previewed'
                       CHECK (state IN ('previewed','containing','contained','partially_contained','failed','releasing','released')),
  state_reason         text NOT NULL DEFAULT '',
  reason               text NOT NULL CHECK (btrim(reason) <> ''),
  release_reason       text NOT NULL DEFAULT '',
  -- Behavioural verification: NULL until decided; false with the late
  -- events in verification when a successful call followed containment.
  effective            boolean,
  verification         jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by           uuid NOT NULL REFERENCES users(id),
  contained_at         timestamptz,
  verified_at          timestamptz,
  release_requested_at timestamptz,
  released_at          timestamptz,
  released_by          uuid REFERENCES users(id),
  -- A deferred restore (the session revocation) is due at this time.
  pending_restore_at   timestamptz,
  preview              jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT agent_containment_workload_ids_chk CHECK (level = 'workload' OR cardinality(workload_ids) = 0),
  CONSTRAINT agent_containment_released_chk CHECK ((state = 'released') = (released_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_containment_live ON agent_containment (workspace_id, identity_id, level)
  WHERE state IN ('previewed','containing','contained','partially_contained','releasing');
CREATE INDEX IF NOT EXISTS idx_agent_containment_ws_state ON agent_containment (workspace_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_containment_identity ON agent_containment (workspace_id, identity_id);
CREATE INDEX IF NOT EXISTS idx_agent_containment_open ON agent_containment (state)
  WHERE state IN ('previewed','containing','contained','partially_contained','releasing') OR pending_restore_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS agent_containment_step (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  containment_id uuid NOT NULL,
  seq            integer NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('lambda_concurrency','ecs_desired','ecs_autoscaling','iam_policy','session_revoke','access_key')),
  target         text NOT NULL CHECK (target <> ''),
  region         text NOT NULL DEFAULT '',
  before         jsonb NOT NULL DEFAULT '{}'::jsonb,
  after          jsonb NOT NULL DEFAULT '{}'::jsonb,
  state          text NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending','applied','skipped','failed','restoring','restored','restore_failed')),
  error          text NOT NULL DEFAULT '',
  restore_after  timestamptz,
  applied_at     timestamptz,
  restored_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, containment_id, kind, target),
  FOREIGN KEY (workspace_id, containment_id) REFERENCES agent_containment (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_containment_step_seq ON agent_containment_step (workspace_id, containment_id, seq);

DO $$
BEGIN
    IF to_regclass('public.iga_gov_job') IS NOT NULL THEN
        ALTER TABLE public.iga_gov_job DROP CONSTRAINT IF EXISTS iga_gov_job_kind_check;
        ALTER TABLE public.iga_gov_job ADD CONSTRAINT iga_gov_job_kind_check
            CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                            'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync',
                            'prune_evidence','metrics_rollup','resolve_unknown',
                            'temp_grant','session_revoke','time_bound','azure_access','k8s_access',
                            'agent_contain'));
    END IF;
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_containment');
        PERFORM public.tenancy_enable_rls('public.agent_containment_step');
    END IF;
END $$;
