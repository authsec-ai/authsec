-- 050_iga_gov_plans_reviews.sql
--
-- Phase 3 evidence bundles, compiled plans, owner review, approvals and
-- revalidations (sections 2.8, 2.11).
--
-- New tables: iga_gov_evidence_bundle, iga_gov_plan, iga_gov_owner_review,
-- iga_gov_owner_response, iga_gov_approval, iga_gov_revalidation.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 050_iga_gov_plans_reviews.sql, verbatim; section 6.3 lists the probes that
-- prove it (tests/igagovschema). 001_bootstrap.sql carries the same objects.

-- The immutable evidence a proposal was compiled from: per-source references
-- (publication, connector run, sweep, scan) with trust and freshness, plus the
-- copied facts the plan relies on. Insert-once, hash-verified, never updated.
CREATE TABLE IF NOT EXISTS iga_gov_evidence_bundle (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider     text NOT NULL CHECK (provider IN ('aws')),          -- R1k adds 'k8s'
  trust        text NOT NULL CHECK (trust IN ('trusted','partial','untrusted')),
  bundle_hash  text NOT NULL,
  canonical    text NOT NULL,
  facts        jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, bundle_hash)
);
CREATE OR REPLACE FUNCTION iga_gov_bundle_insert_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.bundle_hash <> 'sha256:' || encode(sha256(convert_to(NEW.canonical, 'UTF8')), 'hex') THEN
    RAISE EXCEPTION 'evidence bundle hash does not match its canonical facts';
  END IF;
  IF NEW.facts IS DISTINCT FROM NEW.canonical::jsonb THEN
    RAISE EXCEPTION 'evidence bundle facts do not equal their canonical text';
  END IF;
  IF jsonb_typeof(NEW.facts -> 'sources') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.facts -> 'sources') = 0 THEN
    RAISE EXCEPTION 'evidence bundle must name at least one source';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_bundle_insert ON iga_gov_evidence_bundle;
CREATE TRIGGER iga_gov_bundle_insert BEFORE INSERT ON iga_gov_evidence_bundle
  FOR EACH ROW EXECUTE FUNCTION iga_gov_bundle_insert_check();
DROP TRIGGER IF EXISTS iga_gov_bundle_immutable ON iga_gov_evidence_bundle;
CREATE TRIGGER iga_gov_bundle_immutable BEFORE UPDATE ON iga_gov_evidence_bundle
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();

CREATE TABLE IF NOT EXISTS iga_gov_plan (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version_id            uuid NOT NULL,
  target_id             uuid NOT NULL,
  control_id            uuid NOT NULL,
  kind                  text NOT NULL CHECK (kind IN ('apply','undo','remove_control','split','split_revert')),
  delivery              text NOT NULL CHECK (delivery IN ('direct','iac_pr','export')),
  eligibility           text NOT NULL CHECK (eligibility IN ('eligible','iac_only','ineligible')),
  ineligible_reason     text NOT NULL DEFAULT '',
  basis                 text NOT NULL CHECK (basis IN ('live_read','graph_rev')),
  basis_read_at         timestamptz NOT NULL,
  precondition          jsonb NOT NULL,
  precondition_hash     text NOT NULL,
  before_document_hash  text,
  desired_attachment    text NOT NULL CHECK (desired_attachment IN ('present','absent','unchanged')),
  desired_boundary_arn  text,
  desired_document_hash text,
  -- The policy this plan detaches from or replaces on the role, named
  -- explicitly (never inferred from whether the role had a boundary before an
  -- earlier apply), and what happens to it: keep (not detached or replaced),
  -- delete (nobody else uses it), or retain_shared (others use it; detach from
  -- this role only). An undo of a split copy names the copy here.
  replaced_boundary_arn text,
  artifact_disposition  text NOT NULL DEFAULT 'keep' CHECK (artifact_disposition IN ('keep','delete','retain_shared')),
  -- The exact evidence: graph revision and the role connector's scan whose
  -- immutable resource-policy observations the compiler read.
  evidence_bundle_id    uuid NOT NULL,
  evidence_rev          bigint NOT NULL,
  resource_policy_scan_run_id uuid,
  -- none -> present: the first boundary this role will ever have under AuthSec.
  first_attachment      boolean NOT NULL DEFAULT false,
  -- Policy-bearing resource forms the proof could not analyse; approval must accept each.
  unanalysed            jsonb NOT NULL DEFAULT '[]',
  impact                jsonb NOT NULL,
  impact_hash           text NOT NULL,
  operations            jsonb NOT NULL,
  diff                  jsonb NOT NULL,
  plan_hash             text NOT NULL,
  -- What an approver decided on, without the evidence identifiers: control,
  -- kind, delivery, attachment, desired and replaced ARNs, document, disposition,
  -- precondition, ops, impact, first attachment, unanalysed items and evidence
  -- gaps. An unchanged rescan reproduces it (§2.8 Revalidation).
  material_hash         text NOT NULL,
  superseded_at         timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, version_id),
  UNIQUE (workspace_id, id, version_id, control_id, kind, delivery),
  UNIQUE (workspace_id, id, material_hash),
  CONSTRAINT iga_gov_plan_ineligible_chk CHECK ((eligibility = 'ineligible') = (ineligible_reason <> '')),
  -- present: a named boundary with a document; absent/unchanged: neither.
  CONSTRAINT iga_gov_plan_attachment_chk CHECK (
    eligibility = 'ineligible' OR CASE desired_attachment
      WHEN 'present' THEN desired_boundary_arn IS NOT NULL AND desired_document_hash IS NOT NULL
      ELSE desired_boundary_arn IS NULL AND desired_document_hash IS NULL
    END),
  CONSTRAINT iga_gov_plan_kind_chk CHECK (
    (kind IN ('split','split_revert')) = (desired_attachment = 'unchanged')
    AND (kind <> 'apply' OR desired_attachment = 'present')
    AND (kind NOT IN ('split','split_revert') OR delivery IN ('iac_pr','export'))),
  CONSTRAINT iga_gov_plan_disposition_chk CHECK (
    (desired_attachment <> 'absent' OR artifact_disposition IN ('delete','retain_shared'))
    AND (kind IN ('undo','remove_control') OR artifact_disposition = 'keep')
    AND (artifact_disposition = 'keep'
         OR (replaced_boundary_arn IS NOT NULL AND replaced_boundary_arn IS DISTINCT FROM desired_boundary_arn))),
  CONSTRAINT iga_gov_plan_first_attachment_chk CHECK (
    NOT first_attachment
    OR (desired_attachment = 'present' AND resource_policy_scan_run_id IS NOT NULL)),
  FOREIGN KEY (workspace_id, evidence_bundle_id) REFERENCES iga_gov_evidence_bundle (workspace_id, id),
  FOREIGN KEY (workspace_id, evidence_rev) REFERENCES iga_publication (workspace_id, rev),
  FOREIGN KEY (workspace_id, resource_policy_scan_run_id) REFERENCES cloud_scan_run (workspace_id, id),
  FOREIGN KEY (workspace_id, target_id, version_id, control_id)
    REFERENCES iga_gov_target (workspace_id, id, version_id, control_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, before_document_hash) REFERENCES iga_gov_document (workspace_id, document_hash),
  FOREIGN KEY (workspace_id, desired_document_hash) REFERENCES iga_gov_document (workspace_id, document_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_plan_current
  ON iga_gov_plan (target_id, kind) WHERE superseded_at IS NULL;

CREATE TABLE IF NOT EXISTS iga_gov_owner_review (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version_id       uuid NOT NULL,
  impact_hashes    text[] NOT NULL,
  status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open','complete','excepted','cancelled','reopened')),
  deadline_at      timestamptz NOT NULL,
  exception_by     uuid REFERENCES users(id),
  exception_reason text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  closed_at        timestamptz,
  UNIQUE (workspace_id, id),
  UNIQUE (version_id),
  CONSTRAINT iga_gov_owner_review_exception_chk CHECK (
    (status = 'excepted') = (exception_by IS NOT NULL AND exception_reason <> '')),
  FOREIGN KEY (workspace_id, version_id) REFERENCES iga_gov_policy_version (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iga_gov_owner_response (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id      uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  review_id         uuid NOT NULL,
  user_id           uuid NOT NULL REFERENCES users(id),
  owner_of          jsonb NOT NULL,
  delivery          text NOT NULL DEFAULT 'pending' CHECK (delivery IN ('pending','delivered','failed')),
  delivery_channels text[] NOT NULL DEFAULT '{}',
  response          text CHECK (response IN ('acknowledge','retain','object')),
  retain_items      jsonb NOT NULL DEFAULT '[]',
  age_confirmations jsonb NOT NULL DEFAULT '[]',
  -- Per removed service with a resource-policy route (or unanalysed forms):
  -- the owner's statement that the role does not rely on that route.
  route_confirmations jsonb NOT NULL DEFAULT '[]',
  comment           text NOT NULL DEFAULT '',
  responded_at      timestamptz,
  responded_via     text CHECK (responded_via IN ('ui','slack','email_link')),
  UNIQUE (workspace_id, id),
  UNIQUE (review_id, user_id),
  CONSTRAINT iga_gov_orr_response_chk CHECK ((response IS NULL) = (responded_at IS NULL)),
  FOREIGN KEY (workspace_id, review_id) REFERENCES iga_gov_owner_review (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iga_gov_approval (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version_id     uuid NOT NULL,
  decision       text NOT NULL CHECK (decision IN ('approve','reject')),
  decided_by     uuid NOT NULL REFERENCES users(id),
  channel        text NOT NULL CHECK (channel IN ('ui','slack')),
  intent_hash    text NOT NULL,
  impact_hashes  text[] NOT NULL,
  plan_hashes    text[] NOT NULL,
  -- Revalidation compares against these (§2.8); accepted items are rows of
  -- iga_gov_acceptance, never a list on this row.
  material_hashes text[] NOT NULL,
  evidence_rev   bigint NOT NULL,
  reason         text NOT NULL DEFAULT '',
  expires_at     timestamptz NOT NULL,
  revoked_at     timestamptz,
  revoked_reason text NOT NULL DEFAULT '',
  decided_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, version_id),
  CONSTRAINT iga_gov_approval_reject_reason_chk CHECK (decision = 'approve' OR reason <> ''),
  FOREIGN KEY (workspace_id, version_id) REFERENCES iga_gov_policy_version (workspace_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_approval_live
  ON iga_gov_approval (version_id) WHERE decision = 'approve' AND revoked_at IS NULL;

-- A later evidence check of an approved plan. It never rewrites the plan or
-- its bundle: the approved evidence stays as approved, and each check is its
-- own insert-once row. Only an 'unchanged' check lets a deployment proceed.
CREATE TABLE IF NOT EXISTS iga_gov_revalidation (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id           uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  plan_id                uuid NOT NULL,
  approved_material_hash text NOT NULL,
  evidence_bundle_id     uuid NOT NULL,
  evidence_rev           bigint NOT NULL,
  resource_policy_scan_run_id uuid,
  basis_read_at          timestamptz NOT NULL,
  material_hash          text,
  result                 text NOT NULL CHECK (result IN ('unchanged','material_change','blocked')),
  changes                jsonb NOT NULL DEFAULT '[]',
  blocked_reason         text NOT NULL DEFAULT '',
  created_at             timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, plan_id, result),
  -- IS TRUE: a branch that evaluates to NULL (e.g. a NULL material_hash) must
  -- fail, not pass, because 'unchanged' authorizes proceeding without approval.
  CONSTRAINT iga_gov_rv_result_chk CHECK ((CASE result
    WHEN 'unchanged' THEN material_hash IS NOT NULL AND material_hash = approved_material_hash
                          AND changes = '[]'::jsonb AND blocked_reason = ''
    WHEN 'material_change' THEN material_hash IS NOT NULL AND material_hash <> approved_material_hash
                                AND jsonb_array_length(changes) > 0 AND blocked_reason = ''
    ELSE material_hash IS NULL AND blocked_reason <> '' END) IS TRUE),
  FOREIGN KEY (workspace_id, plan_id, approved_material_hash) REFERENCES iga_gov_plan (workspace_id, id, material_hash),
  FOREIGN KEY (workspace_id, evidence_bundle_id) REFERENCES iga_gov_evidence_bundle (workspace_id, id),
  FOREIGN KEY (workspace_id, evidence_rev) REFERENCES iga_publication (workspace_id, rev),
  FOREIGN KEY (workspace_id, resource_policy_scan_run_id) REFERENCES cloud_scan_run (workspace_id, id)
);
DROP TRIGGER IF EXISTS iga_gov_revalidation_immutable ON iga_gov_revalidation;
CREATE TRIGGER iga_gov_revalidation_immutable BEFORE UPDATE ON iga_gov_revalidation
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();
