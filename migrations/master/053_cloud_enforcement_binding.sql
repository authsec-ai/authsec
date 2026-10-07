-- 053_cloud_enforcement_binding.sql
--
-- Phase 3 delivery setup: the per-account enforcement binding (J3), and the
-- IaC sources and changes (J2) (sections 1.1, 3.6, 8.11).
--
-- New tables: cloud_enforcement_binding, iga_gov_iac_source,
-- iga_gov_iac_change.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 053_cloud_enforcement_binding.sql, verbatim; section 6.3 lists the probes
-- that prove it (tests/igagovschema). 001_bootstrap.sql carries the same
-- objects.

CREATE TABLE IF NOT EXISTS cloud_enforcement_binding (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id     uuid NOT NULL,
  account_id       text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  role_arn         text NOT NULL DEFAULT '',
  selftest_role_arn text NOT NULL DEFAULT '',
  auth_ref         text NOT NULL DEFAULT '',
  template_version text NOT NULL DEFAULT '',
  state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','verifying','verified','partial','error','revoked')),
  capabilities     jsonb NOT NULL DEFAULT '{}',
  last_error       text NOT NULL DEFAULT '',
  last_error_code  text NOT NULL DEFAULT '',
  consented_by     uuid NOT NULL REFERENCES users(id),
  verified_at      timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, connector_id) REFERENCES cloud_connector (workspace_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_enforcement_binding_live
  ON cloud_enforcement_binding (workspace_id, connector_id) WHERE state <> 'revoked';

CREATE TABLE IF NOT EXISTS iga_gov_iac_source (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id        uuid NOT NULL,
  format              text NOT NULL CHECK (format IN ('terraform','cloudformation')),
  discovery_source_id uuid NOT NULL,
  repository          text NOT NULL CHECK (repository ~ '^[^/]+/[^/]+$'),
  base_branch         text NOT NULL DEFAULT 'main',
  directory           text NOT NULL,
  role_match          jsonb NOT NULL DEFAULT '{}',
  created_by          uuid NOT NULL REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, connector_id) REFERENCES cloud_connector (workspace_id, id) ON DELETE CASCADE,
  -- the GitHub organisation's discovery source (041 made (workspace_id, id) unique there)
  FOREIGN KEY (workspace_id, discovery_source_id) REFERENCES discovery_sources (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS iga_gov_iac_change (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  deployment_id  uuid NOT NULL,
  source_id      uuid NOT NULL,
  branch         text NOT NULL,
  pr_number      int,
  pr_url         text NOT NULL DEFAULT '',
  proposed_sha   text NOT NULL DEFAULT '',
  reviewed_sha   text NOT NULL DEFAULT '',
  merged_sha     text NOT NULL DEFAULT '',
  merged_at      timestamptz,
  apply_run_ref  text NOT NULL DEFAULT '',
  state          text NOT NULL DEFAULT 'opening' CHECK (state IN
                   ('opening','open','changed_after_review','merged','applied','closed','failed')),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (deployment_id),
  CONSTRAINT iga_gov_ic_merged_chk CHECK ((state IN ('merged','applied')) = (merged_at IS NOT NULL AND merged_sha <> '')),
  FOREIGN KEY (workspace_id, deployment_id) REFERENCES iga_gov_deployment (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, source_id) REFERENCES iga_gov_iac_source (workspace_id, id)
);
