-- 051_iga_gov_rollout.sql
--
-- Phase 3 rollout and execution: acceptances, deployments, the write-ahead
-- attempt record, verification, per-deployment service history, current
-- service posture, the artifact ledger, workload migrations, health reports
-- and validations (sections 2.8, 8, 11).
--
-- New tables: iga_gov_rollout, iga_gov_acceptance, iga_gov_deployment,
-- iga_gov_attempt, iga_gov_verification, iga_gov_service_outcome,
-- iga_gov_service_posture, iga_gov_artifact, iga_gov_workload_migration,
-- iga_gov_health_report, iga_gov_validation, iga_gov_validation_item.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading 051_iga_gov_rollout.sql,
-- verbatim; section 6.3 lists the probes that prove it (tests/igagovschema).
-- 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS iga_gov_rollout (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id      uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version_id        uuid NOT NULL,
  stage             text NOT NULL CHECK (stage IN ('observe','awaiting_approval','canary','expand',
                      'complete','partial','paused','undone')),
  observe_until     timestamptz,
  observe_evidence_required_after timestamptz,
  canary_started_at timestamptz,
  canary_min_until  timestamptz,
  gate_results      jsonb NOT NULL DEFAULT '{}',
  paused_reason     text NOT NULL DEFAULT '',
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (version_id),
  FOREIGN KEY (workspace_id, version_id) REFERENCES iga_gov_policy_version (workspace_id, id) ON DELETE CASCADE
);

-- Each uncertainty a person explicitly accepted, one row per item: an evidence
-- gap of a partial bundle or an unanalysed resource-policy form (bound to the
-- approval, the plan and the bundle), or a canary gate that could not be
-- evaluated (bound to the rollout, stage and evidence window). Insert-once.
CREATE TABLE IF NOT EXISTS iga_gov_acceptance (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind               text NOT NULL CHECK (kind IN ('evidence_gap','unanalysed_form','gate_not_available')),
  item_key           text NOT NULL CHECK (item_key <> ''),
  item_hash          text NOT NULL,
  version_id         uuid NOT NULL,
  approval_id        uuid,
  plan_id            uuid,
  evidence_bundle_id uuid,
  rollout_id         uuid,
  stage              text,
  window_start       timestamptz,
  window_end         timestamptz,
  reason             text NOT NULL CHECK (reason <> ''),
  accepted_by        uuid NOT NULL REFERENCES users(id),
  accepted_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT iga_gov_acc_subject_chk CHECK ((CASE kind
    WHEN 'gate_not_available' THEN rollout_id IS NOT NULL AND stage IS NOT NULL AND stage IN ('canary','expand')
      AND window_start IS NOT NULL AND window_end IS NOT NULL AND window_end > window_start
      AND approval_id IS NULL AND plan_id IS NULL
    ELSE approval_id IS NOT NULL AND plan_id IS NOT NULL AND evidence_bundle_id IS NOT NULL AND rollout_id IS NULL
      AND stage IS NULL AND window_start IS NULL AND window_end IS NULL END) IS TRUE),
  FOREIGN KEY (workspace_id, approval_id, version_id) REFERENCES iga_gov_approval (workspace_id, id, version_id),
  FOREIGN KEY (workspace_id, plan_id, version_id) REFERENCES iga_gov_plan (workspace_id, id, version_id),
  FOREIGN KEY (workspace_id, evidence_bundle_id) REFERENCES iga_gov_evidence_bundle (workspace_id, id),
  FOREIGN KEY (workspace_id, rollout_id) REFERENCES iga_gov_rollout (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_acceptance_item
  ON iga_gov_acceptance (approval_id, plan_id, kind, item_key) WHERE approval_id IS NOT NULL;
DROP TRIGGER IF EXISTS iga_gov_acceptance_immutable ON iga_gov_acceptance;
CREATE TRIGGER iga_gov_acceptance_immutable BEFORE UPDATE ON iga_gov_acceptance
  FOR EACH ROW EXECUTE FUNCTION authsec_row_immutable();

CREATE TABLE IF NOT EXISTS iga_gov_deployment (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  version_id         uuid NOT NULL,
  plan_id            uuid NOT NULL,
  control_id         uuid NOT NULL,
  approval_id        uuid,
  emergency_by       uuid REFERENCES users(id),
  emergency_reason   text NOT NULL DEFAULT '',
  kind               text NOT NULL CHECK (kind IN ('apply','undo','remove_control','split','split_revert')),
  delivery           text NOT NULL CHECK (delivery IN ('direct','iac_pr','export')),
  state              text NOT NULL DEFAULT 'queued' CHECK (state IN
                       ('queued','blocked','applying','outcome_unknown','outcome_unresolved','recovered',
                        'awaiting_merge','awaiting_apply','applied_unverified','verified','failed','drifted',
                        'superseded','undone')),
  state_reason       text NOT NULL DEFAULT '',
  completed_ops      jsonb NOT NULL DEFAULT '[]',
  attempts           int  NOT NULL DEFAULT 0,
  applied_at         timestamptz,
  verified_at        timestamptz,
  verify_deadline_at timestamptz,
  apply_deadline_at  timestamptz,
  -- A mutation whose AWS outcome could not be established (§8.1): no
  -- conflicting operation on the control may start before settle_after.
  outcome_unknown_op text NOT NULL DEFAULT '',
  settle_after       timestamptz,
  -- Operator recovery (§8.1): the unresolved deployment and the deployment that
  -- takes over the role point at each other, written in one transaction.
  recovered_by_deployment_id uuid,
  recovers_deployment_id     uuid,
  -- The 'unchanged' revalidation this deployment proceeded on, if the
  -- approved plan's evidence was no longer fresh (§2.8).
  revalidation_id     uuid,
  revalidation_result text CHECK (revalidation_result = 'unchanged'),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, control_id, recovers_deployment_id),
  CONSTRAINT iga_gov_pd_unknown_chk CHECK (
    state NOT IN ('outcome_unknown','outcome_unresolved','recovered')
    OR (settle_after IS NOT NULL AND outcome_unknown_op <> '')),
  CONSTRAINT iga_gov_pd_recovered_chk CHECK ((state = 'recovered') = (recovered_by_deployment_id IS NOT NULL)),
  CONSTRAINT iga_gov_pd_revalidation_chk CHECK ((revalidation_id IS NULL) = (revalidation_result IS NULL)),
  CONSTRAINT iga_gov_pd_delivery_state_chk CHECK (
    (state NOT IN ('applying','outcome_unknown','outcome_unresolved','recovered') OR delivery = 'direct')
    AND (state <> 'awaiting_merge' OR delivery = 'iac_pr')
    AND (state <> 'awaiting_apply' OR delivery IN ('iac_pr','export'))),
  CONSTRAINT iga_gov_pd_authority_chk CHECK (
    approval_id IS NOT NULL OR (kind IN ('undo','remove_control','split_revert') AND emergency_by IS NOT NULL AND emergency_reason <> '')),
  -- The plan fixes the control, kind and delivery: the role locked below is the
  -- role the approved plan was compiled for.
  FOREIGN KEY (workspace_id, plan_id, version_id, control_id, kind, delivery)
    REFERENCES iga_gov_plan (workspace_id, id, version_id, control_id, kind, delivery),
  FOREIGN KEY (workspace_id, approval_id, version_id) REFERENCES iga_gov_approval (workspace_id, id, version_id),
  FOREIGN KEY (workspace_id, control_id) REFERENCES iga_gov_control (workspace_id, id),
  FOREIGN KEY (workspace_id, revalidation_id, plan_id, revalidation_result)
    REFERENCES iga_gov_revalidation (workspace_id, id, plan_id, result),
  -- The successor must exist, be on the same role, and name this deployment
  -- as the one it recovers; checked at commit so both rows land together.
  CONSTRAINT iga_gov_pd_recovered_by_fk FOREIGN KEY (workspace_id, recovered_by_deployment_id, control_id, id)
    REFERENCES iga_gov_deployment (workspace_id, id, control_id, recovers_deployment_id)
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT iga_gov_pd_recovers_fk FOREIGN KEY (workspace_id, recovers_deployment_id)
    REFERENCES iga_gov_deployment (workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);
-- One in-flight change per physical role, whichever policy or version asks. A
-- deployment whose outcome is unknown or unresolved stays in flight, so nothing
-- conflicting (including an ordinary undo) can start on the role. Only the
-- atomic handoff to 'recovered' (with its successor inserted in the same
-- transaction) releases it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_deployment_inflight
  ON iga_gov_deployment (control_id)
  WHERE state IN ('queued','applying','outcome_unknown','outcome_unresolved','awaiting_merge','awaiting_apply');

-- WRITE-AHEAD record of every AWS mutation (§8.1). 'prepared' is committed
-- with the exact request before anything is sent; 'dispatched' is committed,
-- with the signing time, immediately before the SDK call (automatic SDK retries
-- off); the response makes it 'completed', and no response makes it 'unknown'.
-- A prepared attempt was never sent; a dispatched one may have been.
CREATE TABLE IF NOT EXISTS iga_gov_attempt (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL,
  op_seq        int  NOT NULL CHECK (op_seq >= 0),
  attempt_no    int  NOT NULL CHECK (attempt_no >= 1),
  lease_version bigint NOT NULL,
  operation     text NOT NULL,
  request_hash  text NOT NULL,          -- sha256 of the canonical request parameters
  document_hash text,                   -- the policy document the request carries, if any
  status        text NOT NULL CHECK (status IN ('prepared','dispatched','completed','unknown','abandoned')),
  prepared_at   timestamptz NOT NULL DEFAULT now(),
  signed_at     timestamptz,
  dispatched_at timestamptz,
  completed_at  timestamptz,
  request_id    text NOT NULL DEFAULT '',
  outcome       text CHECK (outcome IN ('ok','retryable','terminal','recognised_done','not_needed')),
  error_code    text NOT NULL DEFAULT '',
  error_message text NOT NULL DEFAULT '',
  -- an unknown attempt is later resolved from readback and CloudTrail
  resolved_as   text CHECK (resolved_as IN ('applied','not_applied')),
  resolved_at   timestamptz,
  UNIQUE (workspace_id, id),
  UNIQUE (deployment_id, op_seq, attempt_no),
  CONSTRAINT iga_gov_at_status_chk CHECK ((CASE status
    WHEN 'prepared'   THEN signed_at IS NULL AND dispatched_at IS NULL AND completed_at IS NULL AND outcome IS NULL
    WHEN 'abandoned'  THEN dispatched_at IS NULL AND completed_at IS NOT NULL AND outcome IS NULL
    WHEN 'dispatched' THEN signed_at IS NOT NULL AND dispatched_at IS NOT NULL AND completed_at IS NULL AND outcome IS NULL
    WHEN 'completed'  THEN signed_at IS NOT NULL AND dispatched_at IS NOT NULL AND completed_at IS NOT NULL AND outcome IS NOT NULL
    WHEN 'unknown'    THEN signed_at IS NOT NULL AND dispatched_at IS NOT NULL AND outcome IS NULL
  END) IS TRUE),
  CONSTRAINT iga_gov_at_resolved_chk CHECK (
    (resolved_as IS NULL OR status = 'unknown') AND ((resolved_as IS NULL) = (resolved_at IS NULL))),
  FOREIGN KEY (workspace_id, deployment_id) REFERENCES iga_gov_deployment (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, document_hash) REFERENCES iga_gov_document (workspace_id, document_hash)
);
-- At most one attempt per deployment is open: prepared, dispatched, or unknown
-- and not yet resolved.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_attempt_open ON iga_gov_attempt (deployment_id)
  WHERE status IN ('prepared','dispatched') OR (status = 'unknown' AND resolved_as IS NULL);
CREATE OR REPLACE FUNCTION iga_gov_attempt_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'prepared' THEN
      RAISE EXCEPTION 'an attempt is recorded as prepared before it is dispatched';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.deployment_id, NEW.op_seq, NEW.attempt_no, NEW.lease_version, NEW.operation, NEW.request_hash, NEW.document_hash)
     IS DISTINCT FROM
     (OLD.deployment_id, OLD.op_seq, OLD.attempt_no, OLD.lease_version, OLD.operation, OLD.request_hash, OLD.document_hash) THEN
    RAISE EXCEPTION 'the prepared request of an attempt is immutable';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'prepared'   AND NEW.status IN ('dispatched','abandoned'))
    OR (OLD.status = 'dispatched' AND NEW.status IN ('completed','unknown'))) THEN
    RAISE EXCEPTION 'attempt % -> % is not allowed', OLD.status, NEW.status;
  END IF;
  IF OLD.resolved_as IS NOT NULL AND NEW.resolved_as IS DISTINCT FROM OLD.resolved_as THEN
    RAISE EXCEPTION 'a resolved attempt stays resolved';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_attempt_transition ON iga_gov_attempt;
CREATE TRIGGER iga_gov_attempt_transition BEFORE INSERT OR UPDATE ON iga_gov_attempt
  FOR EACH ROW EXECUTE FUNCTION iga_gov_attempt_transition();

CREATE TABLE IF NOT EXISTS iga_gov_verification (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL,
  dimension     text NOT NULL CHECK (dimension IN ('artifact','graph','application_health','restriction')),
  outcome       text NOT NULL CHECK (outcome IN ('passed','failed','awaiting_evidence','overdue','not_available','not_applicable')),
  attribution   text NOT NULL DEFAULT 'not_applicable'
                  CHECK (attribution IN ('not_applicable','boundary_attributed','cause_unknown','validation_request')),
  evidence      jsonb NOT NULL DEFAULT '{}',
  checked_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (deployment_id, dimension),
  FOREIGN KEY (workspace_id, deployment_id) REFERENCES iga_gov_deployment (workspace_id, id) ON DELETE CASCADE
);

-- HISTORY: what one deployment established for each service it changed, at
-- its verification. `change` is relative to the boundary it replaced, so
-- successive deployments never count the same exclusion twice. Current state
-- is iga_gov_service_posture, not this table.
CREATE TABLE IF NOT EXISTS iga_gov_service_outcome (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL,
  service       text NOT NULL CHECK (service ~ '^[a-z0-9-]+$'),
  change        text NOT NULL CHECK (change IN ('newly_excluded','already_excluded','newly_unexcluded')),
  exclusion     text NOT NULL DEFAULT 'pending' CHECK (exclusion IN ('pending','applied','failed','reverted')),
  route_state   text NOT NULL CHECK (route_state IN ('none_observed','bypass_known','effect_unknown','not_analysed')),
  routes        jsonb NOT NULL DEFAULT '[]',
  restriction   text NOT NULL DEFAULT 'not_observed' CHECK (restriction IN ('not_observed','observed','contradicted')),
  outcome       text NOT NULL DEFAULT 'pending' CHECK (outcome IN
                  ('pending','removed','excluded_routes_remain','excluded_routes_unknown','not_removed')),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, deployment_id, service),
  CONSTRAINT iga_gov_so_routes_chk CHECK ((route_state = 'none_observed') = (jsonb_array_length(routes) = 0)),
  CONSTRAINT iga_gov_so_outcome_chk CHECK (
    CASE outcome
      WHEN 'removed' THEN exclusion = 'applied' AND route_state = 'none_observed' AND restriction <> 'contradicted'
      WHEN 'excluded_routes_remain' THEN exclusion = 'applied' AND route_state = 'bypass_known' AND restriction <> 'contradicted'
      WHEN 'excluded_routes_unknown' THEN exclusion = 'applied' AND route_state IN ('effect_unknown','not_analysed') AND restriction <> 'contradicted'
      WHEN 'not_removed' THEN exclusion IN ('failed','reverted') OR restriction = 'contradicted'
      ELSE exclusion = 'pending'
    END),
  FOREIGN KEY (workspace_id, deployment_id) REFERENCES iga_gov_deployment (workspace_id, id) ON DELETE CASCADE
);

-- CURRENT POSTURE, one row per (role incarnation, service) AuthSec has ever
-- excluded. Two independent sets of facts, each with its own ordering:
--   route facts       (route_state, routes, evidence_scan_run_id) ordered by evidence_rev,
--                     written only by publication evaluation;
--   enforcement facts (exclusion, current_deployment_id, boundary_document_hash,
--                     restriction) ordered by the control's enforcement_seq, written
--                     only by readback / verification / undo / supersession writers
--                     that compare-and-swap iga_gov_control.enforcement_seq.
-- The outcome is GENERATED from the row's current facts, so no writer can
-- store an outcome derived from a stale snapshot of the other set.
CREATE TABLE IF NOT EXISTS iga_gov_service_posture (
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  account_id           text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  role_id              text NOT NULL CHECK (role_id <> ''),
  service              text NOT NULL CHECK (service ~ '^[a-z0-9-]+$'),
  control_id           uuid NOT NULL,
  -- enforcement facts
  current_deployment_id uuid,
  boundary_document_hash text,
  exclusion            text NOT NULL CHECK (exclusion IN ('pending','applied','not_applied')),
  restriction          text NOT NULL DEFAULT 'not_observed' CHECK (restriction IN ('not_observed','observed','contradicted')),
  enforcement_seq      bigint NOT NULL,
  enforcement_observed_at timestamptz NOT NULL,
  -- route facts
  route_state          text NOT NULL CHECK (route_state IN ('none_observed','bypass_known','effect_unknown','not_analysed')),
  routes               jsonb NOT NULL DEFAULT '[]',
  evidence_rev         bigint NOT NULL,
  evidence_scan_run_id uuid,
  -- derived, never written
  outcome              text GENERATED ALWAYS AS (
    CASE
      WHEN exclusion = 'pending' THEN 'pending'
      WHEN exclusion = 'not_applied' OR restriction = 'contradicted' THEN 'not_removed'
      WHEN route_state = 'none_observed' THEN 'removed'
      WHEN route_state = 'bypass_known' THEN 'excluded_routes_remain'
      ELSE 'excluded_routes_unknown'
    END) STORED,
  assessed_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, account_id, role_id, service),
  CONSTRAINT iga_gov_sp_routes_chk CHECK ((route_state = 'none_observed') = (jsonb_array_length(routes) = 0)),
  CONSTRAINT iga_gov_sp_in_force_chk CHECK (
    exclusion <> 'applied' OR (current_deployment_id IS NOT NULL AND boundary_document_hash IS NOT NULL)),
  CONSTRAINT iga_gov_sp_evidence_chk CHECK (route_state = 'not_analysed' OR evidence_scan_run_id IS NOT NULL),
  FOREIGN KEY (workspace_id, control_id) REFERENCES iga_gov_control (workspace_id, id),
  FOREIGN KEY (workspace_id, current_deployment_id) REFERENCES iga_gov_deployment (workspace_id, id),
  FOREIGN KEY (workspace_id, boundary_document_hash) REFERENCES iga_gov_document (workspace_id, document_hash),
  FOREIGN KEY (workspace_id, evidence_rev) REFERENCES iga_publication (workspace_id, rev),
  FOREIGN KEY (workspace_id, evidence_scan_run_id) REFERENCES cloud_scan_run (workspace_id, id)
);

-- Route facts never move to older evidence. Enforcement facts are ordered per
-- control: the control is the epoch. Within one control they change only with
-- a newer enforcement_seq equal to the control's current value (the writer won
-- the compare-and-swap in this transaction). Moving a row to another control
-- (handoff) is allowed only from a retired control, to a control of the same
-- role, with that control's current sequence; the row's old sequence belongs to
-- the old epoch and is not compared.
CREATE OR REPLACE FUNCTION iga_gov_service_posture_order() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c iga_gov_control%ROWTYPE; old_state text;
BEGIN
  SELECT * INTO c FROM iga_gov_control
   WHERE workspace_id = NEW.workspace_id AND id = NEW.control_id;
  IF c.role_id <> NEW.role_id OR c.account_id <> NEW.account_id THEN
    RAISE EXCEPTION 'posture %/% cannot belong to control % of role %', NEW.role_id, NEW.service, c.id, c.role_id;
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.enforcement_seq <> c.enforcement_seq THEN
      RAISE EXCEPTION 'posture %/% inserted with enforcement_seq % but the control is at %',
        NEW.role_id, NEW.service, NEW.enforcement_seq, c.enforcement_seq;
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.evidence_rev < OLD.evidence_rev THEN
    RAISE EXCEPTION 'route facts for %/% at rev % cannot be replaced by rev %',
      OLD.role_id, OLD.service, OLD.evidence_rev, NEW.evidence_rev;
  END IF;
  IF NEW.control_id IS DISTINCT FROM OLD.control_id THEN
    SELECT state INTO old_state FROM iga_gov_control WHERE workspace_id = OLD.workspace_id AND id = OLD.control_id;
    IF old_state <> 'removed' THEN
      RAISE EXCEPTION 'posture %/% can be handed to a new control only from a retired one (control % is %)',
        OLD.role_id, OLD.service, OLD.control_id, old_state;
    END IF;
    IF NEW.enforcement_seq <> c.enforcement_seq THEN
      RAISE EXCEPTION 'handoff of %/% must carry the new control''s current sequence %', OLD.role_id, OLD.service, c.enforcement_seq;
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.exclusion, NEW.current_deployment_id, NEW.boundary_document_hash, NEW.restriction, NEW.enforcement_seq)
     IS DISTINCT FROM
     (OLD.exclusion, OLD.current_deployment_id, OLD.boundary_document_hash, OLD.restriction, OLD.enforcement_seq) THEN
    IF NEW.enforcement_seq <= OLD.enforcement_seq OR NEW.enforcement_seq <> c.enforcement_seq THEN
      RAISE EXCEPTION 'enforcement facts for %/% need a newer observation that won the control''s compare-and-swap (row %, new %, control %)',
        OLD.role_id, OLD.service, OLD.enforcement_seq, NEW.enforcement_seq, c.enforcement_seq;
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_service_posture_order ON iga_gov_service_posture;
CREATE TRIGGER iga_gov_service_posture_order BEFORE INSERT OR UPDATE ON iga_gov_service_posture
  FOR EACH ROW EXECUTE FUNCTION iga_gov_service_posture_order();

CREATE TABLE IF NOT EXISTS iga_gov_artifact (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  control_id            uuid NOT NULL,
  kind                  text NOT NULL CHECK (kind IN ('boundary_policy','boundary_attachment','dedicated_role','workload_binding')),
  native_arn            text NOT NULL,
  owned_by              text NOT NULL CHECK (owned_by IN ('authsec_direct','customer_iac')),
  state                 text NOT NULL CHECK (state IN ('intended','present','removed','released','drifted','lost')),
  document_hash         text,
  aws_version_id        text NOT NULL DEFAULT '',
  last_readback_at      timestamptz,
  last_readback_hash    text NOT NULL DEFAULT '',
  last_deployment_id    uuid NOT NULL,
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, control_id) REFERENCES iga_gov_control (workspace_id, id),
  FOREIGN KEY (workspace_id, last_deployment_id) REFERENCES iga_gov_deployment (workspace_id, id),
  FOREIGN KEY (workspace_id, document_hash) REFERENCES iga_gov_document (workspace_id, document_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_artifact_live
  ON iga_gov_artifact (control_id, kind) WHERE state IN ('intended','present','drifted');

-- Dedicated-identity isolation (§11): what moves, from which graph workloads
-- to which, and the live evidence that it has moved. Graph workloads are never
-- merged: an ECS task-definition revision is its own workload, so the old and
-- new revisions are linked here, not in the graph.
CREATE TABLE IF NOT EXISTS iga_gov_workload_migration (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  plan_id            uuid NOT NULL,
  control_id         uuid NOT NULL,     -- the source role's control
  subject_kind       text NOT NULL CHECK (subject_kind IN ('ecs_service','lambda_function','ec2_auto_scaling_group','ec2_instance')),
  subject_arn        text NOT NULL CHECK (subject_arn <> ''),
  from_role_arn      text NOT NULL,
  to_role_arn        text NOT NULL,
  from_workload_keys text[] NOT NULL,  -- graph workload keys bound to the source role
  to_workload_keys   text[] NOT NULL DEFAULT '{}',
  state              text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','moving','moved','incomplete','reverted')),
  evidence           jsonb NOT NULL DEFAULT '{}',   -- per API: pages read, items read, items failed
  evidence_complete  boolean NOT NULL DEFAULT false,
  remaining_old_refs int CHECK (remaining_old_refs >= 0),
  checked_at         timestamptz,
  UNIQUE (workspace_id, id),
  UNIQUE (plan_id, subject_kind, subject_arn),
  CONSTRAINT iga_gov_wm_roles_chk CHECK (from_role_arn <> to_role_arn),
  -- moved only on complete evidence, nothing left on the old role, and the new
  -- workload seen; IS TRUE so a missing count cannot pass.
  CONSTRAINT iga_gov_wm_moved_chk CHECK (state <> 'moved' OR (
    evidence_complete AND remaining_old_refs = 0 AND checked_at IS NOT NULL
    AND cardinality(to_workload_keys) > 0) IS TRUE),
  FOREIGN KEY (workspace_id, plan_id) REFERENCES iga_gov_plan (workspace_id, id),
  FOREIGN KEY (workspace_id, control_id) REFERENCES iga_gov_control (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS iga_gov_health_report (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL,
  reported_by   uuid NOT NULL REFERENCES users(id),
  kind          text NOT NULL CHECK (kind IN ('problem','working')),
  service       text NOT NULL DEFAULT '',
  detail        text NOT NULL DEFAULT '',
  channel       text NOT NULL CHECK (channel IN ('ui','slack')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT iga_gov_hr_problem_detail_chk CHECK (kind = 'working' OR detail <> ''),
  FOREIGN KEY (workspace_id, deployment_id) REFERENCES iga_gov_deployment (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iga_gov_validation (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL,
  created_by    uuid NOT NULL REFERENCES users(id),
  -- An event belongs to this test only if it comes from this role incarnation
  -- (sessionIssuer.principalId = role_id), this session name, one of the
  -- declared actions, inside the window. Anything else is ordinary traffic.
  role_id       text NOT NULL CHECK (role_id <> ''),
  correlation   text NOT NULL CHECK (correlation IN ('assumed_session','dedicated_workload')),
  session_name  text NOT NULL CHECK (session_name ~ '^[A-Za-z0-9+=,.@_-]{2,64}$'),
  dedicated_workload_id uuid,
  window_start  timestamptz NOT NULL,
  window_end    timestamptz NOT NULL,
  note          text NOT NULL DEFAULT '',
  result        text NOT NULL DEFAULT 'pending' CHECK (result IN ('pending','matched','partial','not_seen','contradicted')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT iga_gov_vr_window_chk CHECK (window_end > window_start),
  CONSTRAINT iga_gov_vr_correlation_chk CHECK (
    (correlation = 'dedicated_workload') = (dedicated_workload_id IS NOT NULL)
    AND (correlation <> 'assumed_session' OR session_name LIKE 'authsec-validate-%')),
  FOREIGN KEY (workspace_id, deployment_id) REFERENCES iga_gov_deployment (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, dedicated_workload_id) REFERENCES iga_workload (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_validation_session
  ON iga_gov_validation (deployment_id, session_name, window_start);

-- One row per declared action: what the test expects and what CloudTrail showed.
CREATE TABLE IF NOT EXISTS iga_gov_validation_item (
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  validation_id   uuid NOT NULL,
  action          text NOT NULL CHECK (action ~ '^[a-z0-9-]+:[A-Za-z0-9]+$'),
  expected        text NOT NULL CHECK (expected IN ('denied','allowed')),
  result          text NOT NULL DEFAULT 'pending' CHECK (result IN ('pending','matched','not_seen','contradicted')),
  matched_events  int  NOT NULL DEFAULT 0 CHECK (matched_events >= 0),
  opposite_events int  NOT NULL DEFAULT 0 CHECK (opposite_events >= 0),
  evidence        jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (workspace_id, validation_id, action),
  CONSTRAINT iga_gov_vi_result_chk CHECK (
    result = 'pending'
    OR (result = 'contradicted' AND opposite_events > 0)
    OR (result = 'matched' AND matched_events > 0 AND opposite_events = 0)
    OR (result = 'not_seen' AND matched_events = 0 AND opposite_events = 0)),
  FOREIGN KEY (workspace_id, validation_id) REFERENCES iga_gov_validation (workspace_id, id) ON DELETE CASCADE
);
