-- 052_iga_gov_jobs_events.sql
--
-- Phase 3 durable jobs, the append-only event log behind Logs, and hourly
-- metrics (sections 8.1, 8.12).
--
-- New tables: iga_gov_job, iga_gov_event, iga_gov_metrics_hourly.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 052_iga_gov_jobs_events.sql, verbatim; section 6.3 lists the probes that
-- prove it (tests/igagovschema). 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS iga_gov_job (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind             text NOT NULL CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                     'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync','prune_evidence','metrics_rollup')),
  subject_id       uuid,
  rev              bigint,
  dedupe_key       text NOT NULL,
  status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','complete','failed','abandoned')),
  run_after        timestamptz NOT NULL DEFAULT now(),
  lease_owner      text NOT NULL DEFAULT '',
  lease_expires_at timestamptz,
  lease_version    bigint NOT NULL DEFAULT 0,
  attempts         int NOT NULL DEFAULT 0,
  max_attempts     int NOT NULL DEFAULT 5,
  last_error       text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  completed_at     timestamptz,
  UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_job_open
  ON iga_gov_job (workspace_id, kind, dedupe_key) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS idx_iga_gov_job_claim ON iga_gov_job (status, run_after) WHERE status = 'queued';

CREATE TABLE IF NOT EXISTS iga_gov_event (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  event         text NOT NULL,
  actor_kind    text NOT NULL CHECK (actor_kind IN ('user','system','slack_user','aws')),
  actor_id      text NOT NULL DEFAULT '',
  policy_id     uuid,
  version_id    uuid,
  deployment_id uuid,
  finding_id    uuid,
  payload       jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_event_policy ON iga_gov_event (workspace_id, policy_id, occurred_at);
CREATE OR REPLACE FUNCTION iga_gov_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('authsec.workspace_purge', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'iga_gov_event is append-only';
END $$;
DROP TRIGGER IF EXISTS iga_gov_event_no_update ON iga_gov_event;
CREATE TRIGGER iga_gov_event_no_update BEFORE UPDATE OR DELETE ON iga_gov_event
  FOR EACH ROW EXECUTE FUNCTION iga_gov_event_immutable();

CREATE TABLE IF NOT EXISTS iga_gov_metrics_hourly (
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  hour                  timestamptz NOT NULL CHECK (date_trunc('hour', hour) = hour),
  -- Current posture at the end of the hour: (role incarnation, service) pairs by outcome.
  posture_removed                 int NOT NULL DEFAULT 0,
  posture_excluded_routes_remain  int NOT NULL DEFAULT 0,
  posture_excluded_routes_unknown int NOT NULL DEFAULT 0,
  posture_pending                 int NOT NULL DEFAULT 0,
  -- Changes during the hour, from deployment history: each pair counted once per change.
  changes_newly_excluded          int NOT NULL DEFAULT 0,
  changes_newly_unexcluded        int NOT NULL DEFAULT 0,
  roles_right_sized     int NOT NULL DEFAULT 0,
  roles_eligible        int NOT NULL DEFAULT 0,
  approval_p50_seconds  int,
  approval_p95_seconds  int,
  approvals_pending     int NOT NULL DEFAULT 0,
  apply_to_verified_p95_seconds int,
  unexpected_failures   int NOT NULL DEFAULT 0,
  undos                 int NOT NULL DEFAULT 0,
  computed_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, hour)
);
