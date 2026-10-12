-- 056_cloud_resource_policy.sql
--
-- Phase 3 resource-policy collection: immutable per-scan observations, their
-- per-(form, region) coverage, and the content-addressed policy documents
-- they reference (section 3.9).
--
-- New tables: cloud_policy_document, cloud_resource_policy_coverage,
-- cloud_resource_policy_observation.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 056_cloud_resource_policy.sql, verbatim; section 6.3 lists the probes that
-- prove it (tests/igagovschema). 001_bootstrap.sql carries the same objects.

-- Resource policies collected by enumeration, as IMMUTABLE observations per
-- scan, so a later compilation reads exactly the evidence of the scan it names.
-- A rescan adds rows; it never rewrites or removes another scan's rows.
CREATE TABLE IF NOT EXISTS cloud_policy_document (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  document_hash text NOT NULL,
  canonical     text NOT NULL,
  document      jsonb NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, document_hash)
);
DROP TRIGGER IF EXISTS cloud_policy_document_insert ON cloud_policy_document;
CREATE TRIGGER cloud_policy_document_insert BEFORE INSERT ON cloud_policy_document
  FOR EACH ROW EXECUTE FUNCTION authsec_document_insert_check();
DROP TRIGGER IF EXISTS cloud_policy_document_immutable ON cloud_policy_document;
CREATE TRIGGER cloud_policy_document_immutable BEFORE UPDATE ON cloud_policy_document
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();

CREATE TABLE IF NOT EXISTS cloud_resource_policy_coverage (
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id   uuid NOT NULL,
  scan_run_id    uuid NOT NULL,
  resource_form  text NOT NULL CHECK (resource_form IN (
                   's3_bucket','s3_directory_bucket','s3_access_point','s3_multi_region_access_point',
                   's3_object_lambda_access_point','kms_key','sqs_queue','sns_topic','lambda_function',
                   'lambda_function_version','lambda_alias','lambda_layer_version','secretsmanager_secret')),
  region         text NOT NULL,
  state          text NOT NULL CHECK (state IN ('complete','partial','denied','not_collected')),
  enumerated     int  NOT NULL DEFAULT 0 CHECK (enumerated >= 0),
  read_ok        int  NOT NULL DEFAULT 0 CHECK (read_ok >= 0),
  read_failed    int  NOT NULL DEFAULT 0 CHECK (read_failed >= 0),
  reason         text NOT NULL DEFAULT '',
  collected_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, scan_run_id, resource_form, region),
  CONSTRAINT cloud_rpc_complete_chk CHECK (
    state <> 'complete' OR (read_failed = 0 AND read_ok = enumerated)),
  CONSTRAINT cloud_rpc_reason_chk CHECK (state = 'complete' OR reason <> ''),
  FOREIGN KEY (workspace_id, connector_id) REFERENCES cloud_connector (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, scan_run_id) REFERENCES cloud_scan_run (workspace_id, id) ON DELETE CASCADE
);

-- One row per resource read in a scan, including "no policy". Its coverage row
-- must exist, so an observation always belongs to a stated (form, region) set.
CREATE TABLE IF NOT EXISTS cloud_resource_policy_observation (
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_run_id    uuid NOT NULL,
  resource_form  text NOT NULL,
  region         text NOT NULL,
  resource_arn   text NOT NULL CHECK (resource_arn LIKE 'arn:%'),
  policy_present boolean NOT NULL,
  document_hash  text,
  parse_state    text NOT NULL DEFAULT 'parsed' CHECK (parse_state IN ('parsed','unparseable')),
  read_at        timestamptz NOT NULL,
  PRIMARY KEY (workspace_id, scan_run_id, resource_arn),
  CONSTRAINT cloud_rpo_document_chk CHECK (policy_present = (document_hash IS NOT NULL)),
  FOREIGN KEY (workspace_id, scan_run_id, resource_form, region)
    REFERENCES cloud_resource_policy_coverage (workspace_id, scan_run_id, resource_form, region) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, document_hash) REFERENCES cloud_policy_document (workspace_id, document_hash)
);
CREATE INDEX IF NOT EXISTS idx_cloud_rpo_scan_form ON cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form);

-- Observations and coverage are immutable. Rows are removed only by deleting
-- the scan's evidence (retention pruning, workspace purge), never by a rescan.
-- A document cannot be deleted while an observation references it (FK).
DROP TRIGGER IF EXISTS cloud_rpo_immutable ON cloud_resource_policy_observation;
CREATE TRIGGER cloud_rpo_immutable BEFORE UPDATE ON cloud_resource_policy_observation
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();
DROP TRIGGER IF EXISTS cloud_rpc_immutable ON cloud_resource_policy_coverage;
CREATE TRIGGER cloud_rpc_immutable BEFORE UPDATE ON cloud_resource_policy_coverage
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();
