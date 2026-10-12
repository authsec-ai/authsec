-- 048_iga_gov_findings.sql
--
-- Phase 3 findings: one evaluation per published revision, the activity
-- evidence it copied out of cloud_usage, findings, and each finding's frozen
-- per-revision result (sections 2.5, 2.6).
--
-- New tables: iga_gov_evaluation, iga_gov_activity_evidence, iga_gov_finding,
-- iga_gov_finding_result, iga_gov_finding_rule.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading 048_iga_gov_findings.sql,
-- verbatim; section 6.3 lists the probes that prove it (tests/igagovschema).
-- 001_bootstrap.sql carries the same objects.

-- One row per revision the evaluator processed. Evaluation runs inside the
-- projection job, under the pipeline barrier, so the cloud_* rows it reads are
-- still the published run's. Facts it relied on are copied into
-- iga_gov_activity_evidence and never re-read from the mutable cloud_usage later.
CREATE TABLE IF NOT EXISTS iga_gov_evaluation (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  rev          bigint NOT NULL,
  status       text NOT NULL CHECK (status IN ('running','complete','failed','superseded')),
  attempts     int  NOT NULL DEFAULT 1 CHECK (attempts > 0),
  started_at   timestamptz NOT NULL DEFAULT now(),
  finished_at  timestamptz,
  error        text NOT NULL DEFAULT '',
  PRIMARY KEY (workspace_id, rev),
  FOREIGN KEY (workspace_id, rev) REFERENCES iga_publication (workspace_id, rev)
);

-- running -> complete | failed | superseded; failed -> running (retry, attempts+1)
-- | superseded. complete and superseded are terminal, so a replay of a
-- completed evaluation can change nothing.
CREATE OR REPLACE FUNCTION iga_gov_evaluation_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = OLD.status AND NEW.attempts = OLD.attempts THEN
    RETURN NEW;
  END IF;
  IF NOT ((OLD.status = 'running' AND NEW.status IN ('complete','failed','superseded') AND NEW.attempts = OLD.attempts)
       OR (OLD.status = 'failed'  AND NEW.status = 'running' AND NEW.attempts = OLD.attempts + 1)
       OR (OLD.status = 'failed'  AND NEW.status = 'superseded' AND NEW.attempts = OLD.attempts)) THEN
    RAISE EXCEPTION 'iga_gov_evaluation rev %: % (attempt %) -> % (attempt %) is not allowed',
      OLD.rev, OLD.status, OLD.attempts, NEW.status, NEW.attempts;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_evaluation_transition ON iga_gov_evaluation;
CREATE TRIGGER iga_gov_evaluation_transition BEFORE UPDATE ON iga_gov_evaluation
  FOR EACH ROW EXECUTE FUNCTION iga_gov_evaluation_transition();

CREATE TABLE IF NOT EXISTS iga_gov_activity_evidence (
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  rev                   bigint NOT NULL,
  identity_account_id   uuid NOT NULL,
  role_id               text NOT NULL,
  service               text NOT NULL,
  state                 text NOT NULL CHECK (state IN ('collected','not_collected')),
  reason                text NOT NULL DEFAULT '',
  last_authenticated_at timestamptz,
  report_generated_at   timestamptz,
  grant_observed_since  timestamptz,
  grant_age_basis       text NOT NULL CHECK (grant_age_basis IN ('observed_since_change','predates_observation','unknown')),
  tracking_from         timestamptz,
  -- The run of the role's own connector partition in rev's manifest: the
  -- activity report and resource-policy observations this row was built from.
  scan_run_id           uuid,
  route_usage           text NOT NULL DEFAULT 'confirm_required' CHECK (route_usage IN ('none_observed','confirm_required')),
  PRIMARY KEY (workspace_id, rev, identity_account_id, service),
  CONSTRAINT iga_gov_ae_scan_chk CHECK (state = 'not_collected' OR scan_run_id IS NOT NULL),
  CONSTRAINT iga_gov_ae_route_chk CHECK (route_usage = 'confirm_required' OR scan_run_id IS NOT NULL),
  FOREIGN KEY (workspace_id, scan_run_id) REFERENCES cloud_scan_run (workspace_id, id),
  FOREIGN KEY (workspace_id, rev) REFERENCES iga_gov_evaluation (workspace_id, rev) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, identity_account_id) REFERENCES iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
  CONSTRAINT iga_gov_ae_collected_chk CHECK (state = 'not_collected' OR report_generated_at IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS iga_gov_finding (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  fingerprint         text NOT NULL,
  kind                text NOT NULL CHECK (kind IN ('unused_service','broad_grant','shared_role',
                        'missing_owner','missing_review_date','activity_not_read')),
  family              text NOT NULL CHECK (family IN ('governance','cloud_access')),
  severity            text NOT NULL CHECK (severity IN ('high','medium','low','info')),
  confidence          text NOT NULL DEFAULT 'not_applicable'
                        CHECK (confidence IN ('qualified','age_unverified','not_applicable')),
  identity_account_id uuid,
  workload_id         uuid,
  role_id             text,
  connector_id        uuid,
  detail_key          text NOT NULL DEFAULT '',
  detail              jsonb NOT NULL DEFAULT '{}',
  status              text NOT NULL DEFAULT 'open' CHECK (status IN
                        ('open','under_review','excepted','mitigated','resolved','cleared','superseded','reopened')),
  excepted_until      timestamptz,
  exception_reason    text NOT NULL DEFAULT '',
  first_seen_rev      bigint NOT NULL,
  last_evaluated_rev  bigint NOT NULL,
  resolved_by_deployment_id uuid,
  first_seen_at       timestamptz NOT NULL DEFAULT now(),
  last_evaluated_at   timestamptz NOT NULL DEFAULT now(),
  status_changed_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, fingerprint),
  CONSTRAINT iga_gov_finding_exception_chk CHECK ((status = 'excepted') = (excepted_until IS NOT NULL)),
  CONSTRAINT iga_gov_finding_rev_order_chk CHECK (first_seen_rev <= last_evaluated_rev),
  FOREIGN KEY (workspace_id, last_evaluated_rev) REFERENCES iga_publication (workspace_id, rev),
  FOREIGN KEY (workspace_id, identity_account_id) REFERENCES iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, workload_id) REFERENCES iga_workload (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_finding_open ON iga_gov_finding (workspace_id, status, severity)
  WHERE status IN ('open','reopened','under_review');
CREATE INDEX IF NOT EXISTS idx_iga_gov_finding_identity ON iga_gov_finding (workspace_id, identity_account_id);

-- An older revision's evaluation can never overwrite a newer one.
CREATE OR REPLACE FUNCTION iga_gov_finding_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.last_evaluated_rev < OLD.last_evaluated_rev THEN
    RAISE EXCEPTION 'iga_gov_finding % evaluated at rev % cannot be overwritten by rev %',
      OLD.id, OLD.last_evaluated_rev, NEW.last_evaluated_rev;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_finding_monotonic ON iga_gov_finding;
CREATE TRIGGER iga_gov_finding_monotonic BEFORE UPDATE OF last_evaluated_rev ON iga_gov_finding
  FOR EACH ROW EXECUTE FUNCTION iga_gov_finding_monotonic();

-- The condition of each finding AT a revision. Written in the same transaction
-- that marks the evaluation complete; frozen afterwards, so a read at rev N is
-- reproducible after later revisions change iga_gov_finding.
CREATE TABLE IF NOT EXISTS iga_gov_finding_result (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  rev          bigint NOT NULL,
  finding_id   uuid NOT NULL,
  severity     text NOT NULL CHECK (severity IN ('high','medium','low','info')),
  confidence   text NOT NULL CHECK (confidence IN ('qualified','age_unverified','not_applicable')),
  detail       jsonb NOT NULL DEFAULT '{}',
  evidence_scan_run_id uuid,   -- the role connector's run in rev's manifest (null for governance kinds)
  PRIMARY KEY (workspace_id, rev, finding_id),
  FOREIGN KEY (workspace_id, evidence_scan_run_id) REFERENCES cloud_scan_run (workspace_id, id),
  FOREIGN KEY (workspace_id, rev) REFERENCES iga_gov_evaluation (workspace_id, rev) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, finding_id) REFERENCES iga_gov_finding (workspace_id, id) ON DELETE CASCADE
);

-- Evidence and results can be written only while their evaluation is running.
CREATE OR REPLACE FUNCTION iga_gov_evaluation_rows_frozen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM iga_gov_evaluation e
                 WHERE e.workspace_id = NEW.workspace_id AND e.rev = NEW.rev AND e.status = 'running') THEN
    RAISE EXCEPTION '% rows for rev % are frozen: evaluation is not running', TG_TABLE_NAME, NEW.rev;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_activity_evidence_frozen ON iga_gov_activity_evidence;
CREATE TRIGGER iga_gov_activity_evidence_frozen BEFORE INSERT OR UPDATE ON iga_gov_activity_evidence
  FOR EACH ROW EXECUTE FUNCTION iga_gov_evaluation_rows_frozen();
DROP TRIGGER IF EXISTS iga_gov_finding_result_frozen ON iga_gov_finding_result;
CREATE TRIGGER iga_gov_finding_result_frozen BEFORE INSERT OR UPDATE ON iga_gov_finding_result
  FOR EACH ROW EXECUTE FUNCTION iga_gov_evaluation_rows_frozen();

CREATE TABLE IF NOT EXISTS iga_gov_finding_rule (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind         text NOT NULL CHECK (kind IN ('require_review_date','unused_window')),
  scope        jsonb NOT NULL DEFAULT '{}',
  params       jsonb NOT NULL DEFAULT '{}',
  enabled      boolean NOT NULL DEFAULT true,
  created_by   uuid NOT NULL REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id)
);
