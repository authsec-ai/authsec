-- 047_iga_gov_ownership.sql
--
-- Phase 3 ownership: the accountable and technical owners of workloads and
-- identities, and the tag rules that assign them (SPEC-iga-phase3-policy.md
-- section 2.9).
--
-- New tables: iga_gov_owner_rule, iga_gov_owner.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 047_iga_gov_ownership.sql, verbatim; section 6.3 lists the probes that
-- prove it (tests/igagovschema). 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS iga_gov_owner_rule (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  tag_key      text NOT NULL CHECK (tag_key <> ''),
  applies_to   text NOT NULL DEFAULT 'both' CHECK (applies_to IN ('workload','identity_account','both')),
  role         text NOT NULL DEFAULT 'accountable' CHECK (role IN ('accountable','technical')),
  enabled      boolean NOT NULL DEFAULT true,
  created_by   uuid NOT NULL REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, tag_key, applies_to, role)
);

CREATE TABLE IF NOT EXISTS iga_gov_owner (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  object_kind         text NOT NULL CHECK (object_kind IN ('workload','identity_account')),
  workload_id         uuid,
  identity_account_id uuid,
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role                text NOT NULL DEFAULT 'accountable' CHECK (role IN ('accountable','technical')),
  source              text NOT NULL CHECK (source IN ('manual','tag_rule')),
  rule_id             uuid,
  review_due_at       timestamptz,
  created_by          uuid REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT iga_gov_owner_one_chk CHECK (
    (object_kind = 'workload' AND workload_id IS NOT NULL AND identity_account_id IS NULL) OR
    (object_kind = 'identity_account' AND identity_account_id IS NOT NULL AND workload_id IS NULL)),
  CONSTRAINT iga_gov_owner_rule_chk CHECK ((source = 'tag_rule') = (rule_id IS NOT NULL)),
  FOREIGN KEY (workspace_id, workload_id) REFERENCES iga_workload (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, identity_account_id) REFERENCES iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, rule_id) REFERENCES iga_gov_owner_rule (workspace_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_owner
  ON iga_gov_owner (workspace_id, object_kind, coalesce(workload_id, identity_account_id), user_id, role);
