-- 061_r2_time_bound_access.sql
--
-- Phase 3 R2 -- time-bound access and session response
-- (SPEC-iga-phase3-policy.md §12.3; requirements C-10, E-09, R-08). There is
-- no R2 implementation spec; the decisions are DECISION R2-n comments in
-- internal/igagov/r2.go.
--
-- 1. iga_gov_job.kind gains 'temp_grant', 'session_revoke' and 'time_bound':
--    the temporary-grant and session-revocation lifecycles (deploy, verify,
--    expire / remove) and the time-bound retention notices and posture
--    observation at expiry.
-- 2. iga_gov_plan_kind_chk admits a split / split_revert plan delivered
--    DIRECTLY when its subject is a Lambda function (diff.split.subject_kind
--    = 'lambda_function'; DECISION R2-13). Every row valid before stays valid.
-- 3. iga_gov_notification.subject_kind gains 'temporary_grant',
--    'session_revocation' and 'time_bound' (R2's notices).
-- 4. iga_gov_temp_grant: temporary grants -- AuthSec-owned /authsec/
--    policies attached to a role until an expiry (privilege expansion),
--    requested -> approved (governance:grant, requester <> approver) ->
--    deployed -> verified (active) -> expired / revoked.
-- 5. iga_gov_session_revocation: AuthSec-owned deny-before-cutoff policies
--    (aws:TokenIssueTime) attached to a role, with their own approval or an
--    emergency path, removed automatically after the longest session lifetime.
-- 6. The governance:grant permission, seeded like 055 seeds governance:*,
--    bound to every workspace admin role.
--
-- Expand only: three CHECKs are widened (every row valid before is valid
-- after), two tables are added, and permission rows are inserted
-- idempotently. Idempotent: safe to run again (DROP CONSTRAINT IF EXISTS +
-- ADD, IF NOT EXISTS, ON CONFLICT DO NOTHING). 001_bootstrap.sql carries the
-- same objects.
--
-- R2 runs only when IGA_POLICY_R2=on, which requires IGA_POLICY=on and this
-- migration verified (services.VerifyPolicyR2Schema). The R1a gate
-- (VerifyPolicySchema, head 059) checks iga_gov_plan_kind_chk by NAME and
-- validation only, so the widened constraint keeps R1a available; a database
-- without 061 keeps R1a (and R1b) fully available.

ALTER TABLE iga_gov_job DROP CONSTRAINT IF EXISTS iga_gov_job_kind_check;
ALTER TABLE iga_gov_job ADD CONSTRAINT iga_gov_job_kind_check
  CHECK (kind IN ('evaluate_owner_rules','compile_plans','notify','refresh_activity',
                  'observe_tick','deploy','verify','drift_check','verify_binding','iac_sync','prune_evidence','metrics_rollup','resolve_unknown',
                  'temp_grant','session_revoke','time_bound'));

ALTER TABLE iga_gov_plan DROP CONSTRAINT IF EXISTS iga_gov_plan_kind_chk;
ALTER TABLE iga_gov_plan ADD CONSTRAINT iga_gov_plan_kind_chk CHECK (
    (kind IN ('split','split_revert')) = (desired_attachment = 'unchanged')
    AND (kind <> 'apply' OR desired_attachment = 'present')
    AND (kind NOT IN ('split','split_revert') OR delivery IN ('iac_pr','export')
         OR (delivery = 'direct' AND (eligibility = 'ineligible'
             OR (eligibility = 'eligible' AND (diff -> 'split' ->> 'subject_kind') = 'lambda_function')))));

ALTER TABLE iga_gov_notification DROP CONSTRAINT IF EXISTS iga_gov_notification_subject_kind_check;
ALTER TABLE iga_gov_notification ADD CONSTRAINT iga_gov_notification_subject_kind_check
  CHECK (subject_kind IN ('owner_review','approval_request','deployment','drift','canary_gate','finding_digest',
                          'temporary_grant','session_revocation','time_bound'));

CREATE TABLE IF NOT EXISTS iga_gov_temp_grant (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  -- The role's AWS connector and identity incarnation (§2.2). No FK to
  -- iga_identity_accounts: a grant is an audit record that outlives the row.
  connector_id          uuid NOT NULL,
  identity_account_id   uuid NOT NULL,
  account_id            text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  role_id               text NOT NULL,
  role_arn              text NOT NULL,
  -- Exactly what the request names (DECISION R2-9): literal actions,
  -- resources as ARNs or "*"; the escalation-catalog patterns they reach and
  -- the requester's acknowledgement of them.
  actions               jsonb NOT NULL CHECK (jsonb_typeof(actions) = 'array' AND jsonb_array_length(actions) BETWEEN 1 AND 50),
  resources             jsonb NOT NULL CHECK (jsonb_typeof(resources) = 'array' AND jsonb_array_length(resources) BETWEEN 1 AND 20),
  escalations           jsonb NOT NULL DEFAULT '[]'::jsonb,
  escalation_ack        text NOT NULL DEFAULT '',
  reason                text NOT NULL CHECK (reason <> ''),
  expires_at            timestamptz NOT NULL,
  policy_name           text NOT NULL,
  policy_arn            text NOT NULL,
  document_hash         text NOT NULL,
  -- request_hash binds the approval (role, actions, resources, expiry,
  -- document); request_key is "the same request for the same role" for the
  -- one-live-grant index.
  request_hash          text NOT NULL,
  request_key           text NOT NULL,
  state                 text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','rejected','cancelled','approved',
                          'deploying','active','expiring','expired','revoked','failed','outcome_unknown')),
  state_reason          text NOT NULL DEFAULT '',
  requested_by          uuid NOT NULL REFERENCES users(id),
  decided_by            uuid REFERENCES users(id),
  decided_at            timestamptz,
  decision_reason       text NOT NULL DEFAULT '',
  approved_request_hash text,
  ended_by              uuid REFERENCES users(id),
  end_reason            text NOT NULL DEFAULT '',
  deployed_at           timestamptz,
  verified_at           timestamptz,
  ended_at              timestamptz,
  last_readback_at      timestamptz,
  drift                 text NOT NULL DEFAULT '',
  -- Write-ahead marker of the one AWS write in flight (§8.1's idea for R2):
  -- set, fenced, immediately before the call; cleared with its answer. A
  -- marker found by a later run means "may have been sent": the run waits
  -- until settle_after and recognises the op from a fresh read.
  pending_op            text NOT NULL DEFAULT '',
  pending_op_at         timestamptz,
  settle_after          timestamptz,
  ops                   jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  -- Separation of duties (§2.10): the approver is never the requester.
  CONSTRAINT iga_gov_tg_sod_chk CHECK (decided_by IS NULL OR decided_by <> requested_by),
  -- Undecided exactly while requested or cancelled; everything past approval
  -- carries the approved request hash, equal to the request's.
  CONSTRAINT iga_gov_tg_decided_chk CHECK (
    ((state IN ('requested','cancelled')) = (decided_by IS NULL))
    AND (state IN ('requested','cancelled','rejected') OR approved_request_hash = request_hash)),
  -- DECISION R2-10: 15 minutes .. 30 days (plus slack for the request's own clock).
  CONSTRAINT iga_gov_tg_window_chk CHECK (expires_at > created_at AND expires_at <= created_at + interval '31 days'),
  FOREIGN KEY (workspace_id, document_hash) REFERENCES iga_gov_document (workspace_id, document_hash)
);
-- One live temporary grant per (role, request) (§12.3).
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_temp_grant_live
  ON iga_gov_temp_grant (workspace_id, account_id, role_id, request_key)
  WHERE state IN ('requested','approved','deploying','active','expiring','outcome_unknown');
CREATE INDEX IF NOT EXISTS idx_iga_gov_temp_grant_due ON iga_gov_temp_grant (state, expires_at);

CREATE TABLE IF NOT EXISTS iga_gov_session_revocation (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id          uuid NOT NULL,
  identity_account_id   uuid NOT NULL,
  account_id            text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  role_id               text NOT NULL,
  role_arn              text NOT NULL,
  reason                text NOT NULL CHECK (reason <> ''),
  -- governance:emergency: decided by the requester at request time,
  -- always notified (DECISION R2-12).
  emergency             boolean NOT NULL DEFAULT false,
  -- The cutoff is fixed at approval (DECISION R2-12); the deny is removed
  -- automatically at remove_after.
  keep_hours            integer NOT NULL DEFAULT 13 CHECK (keep_hours BETWEEN 13 AND 168),
  issued_before         timestamptz,
  remove_after          timestamptz,
  policy_name           text NOT NULL,
  policy_arn            text NOT NULL,
  document_hash         text,
  request_hash          text NOT NULL,
  state                 text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','rejected','cancelled','approved',
                          'deploying','active','removing','removed','failed','outcome_unknown')),
  state_reason          text NOT NULL DEFAULT '',
  requested_by          uuid NOT NULL REFERENCES users(id),
  decided_by            uuid REFERENCES users(id),
  decided_at            timestamptz,
  decision_reason       text NOT NULL DEFAULT '',
  approved_request_hash text,
  ended_by              uuid REFERENCES users(id),
  end_reason            text NOT NULL DEFAULT '',
  deployed_at           timestamptz,
  verified_at           timestamptz,
  ended_at              timestamptz,
  last_readback_at      timestamptz,
  drift                 text NOT NULL DEFAULT '',
  pending_op            text NOT NULL DEFAULT '',
  pending_op_at         timestamptz,
  settle_after          timestamptz,
  ops                   jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  -- Separation of duties, except the audited emergency path.
  CONSTRAINT iga_gov_sr_sod_chk CHECK (emergency OR decided_by IS NULL OR decided_by <> requested_by),
  CONSTRAINT iga_gov_sr_decided_chk CHECK (
    ((state IN ('requested','cancelled')) = (decided_by IS NULL))
    AND (state IN ('requested','cancelled','rejected')
         OR (approved_request_hash = request_hash AND issued_before IS NOT NULL
             AND document_hash IS NOT NULL AND remove_after IS NOT NULL))),
  -- The deny stays at least the longest session lifetime (12 h) + 1 h.
  CONSTRAINT iga_gov_sr_window_chk CHECK (remove_after IS NULL
    OR (issued_before IS NOT NULL AND remove_after >= issued_before + interval '13 hours')),
  FOREIGN KEY (workspace_id, document_hash) REFERENCES iga_gov_document (workspace_id, document_hash)
);
-- One live session revocation per role.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_session_revocation_live
  ON iga_gov_session_revocation (workspace_id, account_id, role_id)
  WHERE state IN ('requested','approved','deploying','active','removing','outcome_unknown');
CREATE INDEX IF NOT EXISTS idx_iga_gov_session_revocation_due ON iga_gov_session_revocation (state, remove_after);

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
  (gen_random_uuid(), NULL, 'governance', 'grant', 'Approve temporary access grants (privilege expansion)', 'governance:grant', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM public.roles r CROSS JOIN public.permissions p
WHERE r.name = 'admin' AND r.workspace_id IS NOT NULL AND p.workspace_id IS NULL
  AND p.resource = 'governance' AND p.action = 'grant'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- verify ----------------------------------------------------------------------
-- Row-level security (CLAUDE.md §7, migration 111): every workspace table
-- gets the tenancy policy. On a database where 111 already ran (production
-- upgrades), enable it here; on a fresh database 111 has not run yet when
-- 061 applies and its loop -- like 001's -- covers these tables later.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_gov_temp_grant');
        PERFORM public.tenancy_enable_rls('public.iga_gov_session_revocation');
    END IF;
END $$;

DO $$
DECLARE
    n integer;
BEGIN
    IF to_regclass('public.iga_gov_temp_grant') IS NULL OR to_regclass('public.iga_gov_session_revocation') IS NULL THEN
        RAISE EXCEPTION '061: iga_gov_temp_grant or iga_gov_session_revocation is missing';
    END IF;
    IF to_regclass('public.uq_iga_gov_temp_grant_live') IS NULL OR to_regclass('public.uq_iga_gov_session_revocation_live') IS NULL THEN
        RAISE EXCEPTION '061: a live-uniqueness index is missing';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_job'::regclass AND conname = 'iga_gov_job_kind_check'
       AND pg_get_constraintdef(oid) LIKE '%temp_grant%' AND pg_get_constraintdef(oid) LIKE '%resolve_unknown%';
    IF n <> 1 THEN
        RAISE EXCEPTION '061: iga_gov_job_kind_check does not admit the R2 kinds alongside the R1a kinds';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_plan'::regclass AND conname = 'iga_gov_plan_kind_chk'
       AND pg_get_constraintdef(oid) LIKE '%lambda_function%' AND pg_get_constraintdef(oid) LIKE '%iac_pr%';
    IF n <> 1 THEN
        RAISE EXCEPTION '061: iga_gov_plan_kind_chk does not admit direct Lambda splits';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_notification'::regclass AND conname = 'iga_gov_notification_subject_kind_check'
       AND pg_get_constraintdef(oid) LIKE '%temporary_grant%' AND pg_get_constraintdef(oid) LIKE '%finding_digest%';
    IF n <> 1 THEN
        RAISE EXCEPTION '061: iga_gov_notification_subject_kind_check does not admit the R2 notices';
    END IF;

    SELECT count(*) INTO n FROM public.permissions
     WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'grant';
    IF n <> 1 THEN
        RAISE EXCEPTION '061: permission governance:grant is missing';
    END IF;
END $$;
