-- 049_iga_gov_policy.sql
--
-- Phase 3 policy model: policies, immutable versions, the content-addressed
-- boundary-document archive, role controls (one live control per role; the
-- epoch of its posture) and version targets (sections 2.1-2.7).
--
-- New tables: iga_gov_policy, iga_gov_policy_version, iga_gov_document,
-- iga_gov_control, iga_gov_target.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading 049_iga_gov_policy.sql,
-- verbatim; section 6.3 lists the probes that prove it (tests/igagovschema).
-- 001_bootstrap.sql carries the same objects.

-- The AuthSec governance policy: customer intent and its lifecycle. It is
-- independent of the legacy agent_policies table, which Phase 3 does not read
-- or alter (PLAN-existing-policy-code-disposition.md).
CREATE TABLE IF NOT EXISTS iga_gov_policy (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name               text NOT NULL CHECK (name <> ''),
  purpose            text NOT NULL DEFAULT '',
  family             text NOT NULL CHECK (family IN ('governance','cloud_access','time_bound','runtime')),
  provider           text NOT NULL CHECK (provider IN ('aws')),          -- R1k adds 'k8s'
  lifecycle          text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','paused','archived')),
  owner_user_id      uuid REFERENCES users(id) ON DELETE SET NULL,
  current_version_id uuid,
  created_by         uuid NOT NULL REFERENCES users(id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS iga_gov_policy_version (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id       uuid NOT NULL,
  version_no      int  NOT NULL CHECK (version_no > 0),
  intent          jsonb NOT NULL,
  intent_hash     text NOT NULL,
  catalog_version int  NOT NULL,
  evidence_rev    bigint NOT NULL,
  status          text NOT NULL DEFAULT 'draft' CHECK (status IN
                    ('draft','in_review','approved','superseded','withdrawn','rejected')),
  created_by      uuid NOT NULL REFERENCES users(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  status_changed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, policy_id),
  UNIQUE (policy_id, version_no),
  FOREIGN KEY (workspace_id, policy_id) REFERENCES iga_gov_policy (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, evidence_rev) REFERENCES iga_publication (workspace_id, rev)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_policy_version_one_approved
  ON iga_gov_policy_version (policy_id) WHERE status = 'approved';

CREATE OR REPLACE FUNCTION iga_gov_policy_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.intent IS DISTINCT FROM OLD.intent OR NEW.intent_hash IS DISTINCT FROM OLD.intent_hash
     OR NEW.catalog_version IS DISTINCT FROM OLD.catalog_version OR NEW.evidence_rev IS DISTINCT FROM OLD.evidence_rev
     OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.version_no IS DISTINCT FROM OLD.version_no THEN
    RAISE EXCEPTION 'iga_gov_policy_version % is immutable; create a new version', OLD.id;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_policy_version_immutable ON iga_gov_policy_version;
CREATE TRIGGER iga_gov_policy_version_immutable BEFORE UPDATE ON iga_gov_policy_version
  FOR EACH ROW EXECUTE FUNCTION iga_gov_policy_version_immutable();

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_gov_policy_current_version_fk') THEN
    ALTER TABLE iga_gov_policy ADD CONSTRAINT iga_gov_policy_current_version_fk
      FOREIGN KEY (workspace_id, current_version_id, id)
      REFERENCES iga_gov_policy_version (workspace_id, id, policy_id) DEFERRABLE INITIALLY DEFERRED;
  END IF;
END $$;

-- Content-addressed documents are insert-once: the hash must be the sha256 of
-- the canonical (RFC 8785) text, the jsonb must equal that text, and a row can
-- never be updated. A duplicate insert of the same hash is the same content.
CREATE OR REPLACE FUNCTION authsec_document_insert_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.document_hash <> 'sha256:' || encode(sha256(convert_to(NEW.canonical, 'UTF8')), 'hex') THEN
    RAISE EXCEPTION '%: document_hash does not match the canonical content', TG_TABLE_NAME;
  END IF;
  IF NEW.document IS DISTINCT FROM NEW.canonical::jsonb THEN
    RAISE EXCEPTION '%: document does not equal its canonical text', TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION authsec_row_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END $$;

-- Content-addressed archive of every boundary document AuthSec read or wrote,
-- so undo never depends on IAM's five-version limit.
CREATE TABLE IF NOT EXISTS iga_gov_document (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  document_hash text NOT NULL,
  canonical     text NOT NULL,
  document      jsonb NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, document_hash)
);
DROP TRIGGER IF EXISTS iga_gov_document_insert ON iga_gov_document;
CREATE TRIGGER iga_gov_document_insert BEFORE INSERT ON iga_gov_document
  FOR EACH ROW EXECUTE FUNCTION authsec_document_insert_check();
DROP TRIGGER IF EXISTS iga_gov_document_immutable ON iga_gov_document;
CREATE TRIGGER iga_gov_document_immutable BEFORE UPDATE ON iga_gov_document
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();

-- The physical AWS subject. One live control per role, owned by exactly one
-- policy: every deployment, lock and conflict check keys on this row, never on
-- a version-specific target. The baseline is the role's boundary state before
-- AuthSec's first change; removing control restores it.
CREATE TABLE IF NOT EXISTS iga_gov_control (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id        uuid NOT NULL,
  account_id          text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  role_id             text NOT NULL CHECK (role_id <> ''),
  role_arn            text NOT NULL,
  identity_account_id uuid NOT NULL,
  policy_id           uuid NOT NULL,
  boundary_policy_arn text NOT NULL,
  baseline_captured_at   timestamptz,
  baseline_boundary_arn  text,
  baseline_document_hash text,
  -- Orders every observation of what is enforced on this role (readback,
  -- verification, undo, supersession). Writers compare-and-swap it.
  enforcement_seq        bigint NOT NULL DEFAULT 0 CHECK (enforcement_seq >= 0),
  state               text NOT NULL DEFAULT 'planned' CHECK (state IN ('planned','active','removing','removed')),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, policy_id),
  FOREIGN KEY (workspace_id, connector_id) REFERENCES cloud_connector (workspace_id, id),
  FOREIGN KEY (workspace_id, identity_account_id) REFERENCES iga_identity_accounts (workspace_id, id),
  CONSTRAINT iga_gov_rc_baseline_chk CHECK (
    (baseline_boundary_arn IS NULL) = (baseline_document_hash IS NULL)
    AND (baseline_captured_at IS NOT NULL OR baseline_boundary_arn IS NULL)
    AND (state IN ('planned','removed') OR baseline_captured_at IS NOT NULL)),
  FOREIGN KEY (workspace_id, policy_id) REFERENCES iga_gov_policy (workspace_id, id),
  FOREIGN KEY (workspace_id, baseline_document_hash) REFERENCES iga_gov_document (workspace_id, document_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_control_live
  ON iga_gov_control (workspace_id, account_id, role_id) WHERE state <> 'removed';

-- A retired control is fenced: its sequence can advance in the same statement
-- that retires it (the removal's final observation), never afterwards. Workers
-- still holding the old control therefore always lose their compare-and-swap.
CREATE OR REPLACE FUNCTION iga_gov_control_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state = 'removed' AND NEW.enforcement_seq <> OLD.enforcement_seq THEN
    RAISE EXCEPTION 'control % is retired; its enforcement sequence cannot advance', OLD.id;
  END IF;
  IF OLD.state = 'removed' AND NEW.state <> 'removed' THEN
    RAISE EXCEPTION 'control % is retired and cannot be reactivated; create a new control', OLD.id;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_control_fence ON iga_gov_control;
CREATE TRIGGER iga_gov_control_fence BEFORE UPDATE ON iga_gov_control
  FOR EACH ROW EXECUTE FUNCTION iga_gov_control_fence();

CREATE TABLE IF NOT EXISTS iga_gov_target (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version_id          uuid NOT NULL,
  policy_id           uuid NOT NULL,
  control_id          uuid NOT NULL,
  provider            text NOT NULL DEFAULT 'aws' CHECK (provider = 'aws'),
  is_canary           boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, version_id),
  UNIQUE (workspace_id, id, version_id, control_id),
  UNIQUE (version_id, control_id),
  FOREIGN KEY (workspace_id, version_id, policy_id) REFERENCES iga_gov_policy_version (workspace_id, id, policy_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, control_id, policy_id) REFERENCES iga_gov_control (workspace_id, id, policy_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_target_one_canary
  ON iga_gov_target (version_id) WHERE is_canary;
