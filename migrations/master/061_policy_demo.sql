-- 061_policy_demo.sql — storage for the Policy UI demo (/api/policy-demo/v1).
--
-- expand only. Idempotent: safe to run again.
--
-- A demo of the policy authoring flow: a policy names an agent, the identity it
-- acts as, one S3 bucket (optionally one prefix), the access it may have and a
-- time window. The routes store and list these and show the AWS documents such
-- a policy WOULD produce. Nothing here is deployed to AWS, evaluated or enforced,
-- and nothing reads these rows but the demo routes. Independent of the iga_gov_*
-- tables.

CREATE TABLE IF NOT EXISTS policy_demo_policies (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name          text NOT NULL,
  description   text NOT NULL DEFAULT '',
  agent         text NOT NULL DEFAULT '',
  identity      text NOT NULL DEFAULT '',
  resource_type text NOT NULL DEFAULT 's3' CHECK (resource_type IN ('s3')),
  resource      text NOT NULL,
  prefix        text NOT NULL DEFAULT '',
  actions       text[] NOT NULL,
  protect_bucket boolean NOT NULL DEFAULT true,
  require_tls   boolean NOT NULL DEFAULT true,
  start_time    timestamptz,
  end_time      timestamptz,
  paused        boolean NOT NULL DEFAULT false,
  created_by    uuid,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT policy_demo_window_chk CHECK (start_time IS NULL OR end_time IS NULL OR end_time > start_time)
);
CREATE INDEX IF NOT EXISTS idx_policy_demo_policies_workspace
  ON policy_demo_policies (workspace_id, created_at DESC);
