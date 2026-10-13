-- 062_r3_runtime_controls.sql
--
-- Phase 3 R3 -- agent runtime controls (SPEC-iga-phase3-policy.md §12.4;
-- requirements R-01..R-11, and R-08's brokered sessions moved from R2 by
-- DECISION R2-1). There is no R3 implementation spec; every assumption is a
-- DECISION R3-n comment (internal/igagov/r3.go lists them).
--
-- 1. iga_gov_runtime_version: immutable, versioned runtime_controls intents
--    of a policy of family 'runtime' (049 already admits the family). One
--    version in review and one approved per policy; the approver is never
--    the author (§2.10).
-- 2. iga_gov_runtime_settings: per-workspace runtime posture -- argument
--    retention and redaction (R-11), decision cache TTL (R-05), hold timeout
--    and approval validity (R-06).
-- 3. iga_gov_runtime_decision: every AuthSec runtime decision (allow / deny /
--    hold), binding the arguments digest, policy version, approval and expiry
--    (R-03); single-use (consumed_at) and idempotent per (agent, key). The
--    tool / AWS outcome the agent reports is recorded apart from the AuthSec
--    decision (R-07). A trigger keeps the binding columns immutable.
-- 4. iga_gov_runtime_hold: durable human-in-the-loop holds (R-06), approved
--    by a member who is not the initiating human, resumed at most once.
-- 5. iga_gov_runtime_budget / iga_gov_runtime_budget_entry: per-session
--    budget ledger with atomic reservation and settlement (R-09).
-- 6. iga_gov_runtime_routing_proof: recorded proofs that a gateway is the only
--    route to its tools (§12.4 lab contract 3). Without one, every control
--    reports 'advisory' (R-04).
-- 7. iga_gov_runtime_agentcore_push: compiled Cedar pushed to an AgentCore
--    policy engine and its readback (R-01).
-- 8. iga_gov_runtime_broker_role / iga_gov_runtime_broker_session: opt-in
--    brokered AWS sessions (R-08): sts:AssumeRole with a session policy and
--    session tags, at most one hour, one session per allow decision.
--
-- Expand only: ten new tables, two trigger functions; no existing table or
-- constraint is altered. Idempotent: safe to run again (IF NOT EXISTS,
-- CREATE OR REPLACE, DROP TRIGGER IF EXISTS). 001_bootstrap.sql carries the
-- same objects.
--
-- R3 runs only when IGA_POLICY_R3=on, which requires IGA_POLICY=on and this
-- migration verified (services.VerifyPolicyR3Schema). R1a's VerifyPolicySchema
-- reads nothing of 062, so a database without it keeps R1a, R1b and R2 fully
-- available.

CREATE TABLE IF NOT EXISTS iga_gov_runtime_version (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id            uuid NOT NULL,
  version_no           int  NOT NULL CHECK (version_no > 0),
  intent               jsonb NOT NULL,
  intent_hash          text NOT NULL CHECK (intent_hash ~ '^sha256:[0-9a-f]{64}$'),
  status               text NOT NULL DEFAULT 'in_review' CHECK (status IN ('in_review','approved','superseded','withdrawn','rejected')),
  created_by           uuid NOT NULL REFERENCES users(id),
  created_at           timestamptz NOT NULL DEFAULT now(),
  decided_by           uuid REFERENCES users(id),
  decided_at           timestamptz,
  decision_reason      text NOT NULL DEFAULT '',
  approved_intent_hash text,
  status_changed_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, policy_id),
  UNIQUE (policy_id, version_no),
  FOREIGN KEY (workspace_id, policy_id) REFERENCES iga_gov_policy (workspace_id, id) ON DELETE CASCADE,
  -- Separation of duties (§2.10): the approver is never the author.
  CONSTRAINT iga_gov_rtv_sod_chk CHECK (decided_by IS NULL OR decided_by <> created_by),
  -- Undecided exactly while in review or withdrawn; an approved (or later
  -- superseded) version carries the approved hash, equal to its own.
  CONSTRAINT iga_gov_rtv_decided_chk CHECK (
    ((status IN ('in_review','withdrawn')) = (decided_by IS NULL))
    AND (status NOT IN ('approved','superseded') OR approved_intent_hash = intent_hash))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_runtime_version_one_approved
  ON iga_gov_runtime_version (policy_id) WHERE status = 'approved';
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_runtime_version_one_review
  ON iga_gov_runtime_version (policy_id) WHERE status = 'in_review';

CREATE OR REPLACE FUNCTION iga_gov_runtime_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.intent IS DISTINCT FROM OLD.intent OR NEW.intent_hash IS DISTINCT FROM OLD.intent_hash
     OR NEW.policy_id IS DISTINCT FROM OLD.policy_id OR NEW.version_no IS DISTINCT FROM OLD.version_no
     OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
    RAISE EXCEPTION 'iga_gov_runtime_version % is immutable; create a new version', OLD.id;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_runtime_version_immutable ON iga_gov_runtime_version;
CREATE TRIGGER iga_gov_runtime_version_immutable BEFORE UPDATE ON iga_gov_runtime_version
  FOR EACH ROW EXECUTE FUNCTION iga_gov_runtime_version_immutable();

CREATE TABLE IF NOT EXISTS iga_gov_runtime_settings (
  workspace_id           uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  -- R-11: digest_only keeps no argument values at all; redacted keeps them
  -- with the workspace's redact_keys replaced and long strings truncated.
  argument_retention     text NOT NULL DEFAULT 'digest_only' CHECK (argument_retention IN ('digest_only','redacted')),
  redact_keys            jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(redact_keys) = 'array' AND jsonb_array_length(redact_keys) <= 100),
  retention_days         int NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 400),
  -- R-05: how long a PEP may rely on an allow (it is single-use regardless).
  decision_ttl_seconds   int NOT NULL DEFAULT 60 CHECK (decision_ttl_seconds BETWEEN 5 AND 300),
  hold_timeout_minutes   int NOT NULL DEFAULT 60 CHECK (hold_timeout_minutes BETWEEN 1 AND 10080),
  approval_valid_minutes int NOT NULL DEFAULT 15 CHECK (approval_valid_minutes BETWEEN 1 AND 1440),
  updated_by             uuid REFERENCES users(id),
  updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iga_gov_runtime_decision (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  -- The runtime policy version that decided; NULL only for a default deny
  -- (no approved policy governs the agent).
  policy_id           uuid,
  version_id          uuid,
  intent_hash         text,
  -- R-02: the authenticated workload (from the verified credential only)
  -- and the initiating human. No FK on the human: a decision is an audit
  -- record that outlives the user row.
  agent_ref           text NOT NULL CHECK (agent_ref <> ''),
  agent_client_id     text NOT NULL DEFAULT '',
  human_user_id       uuid,
  credential_kind     text NOT NULL CHECK (credential_kind IN ('delegated_jwt_svid')),
  tool                text NOT NULL CHECK (tool <> ''),
  action              text NOT NULL DEFAULT '',
  target              text NOT NULL DEFAULT '',
  args_digest         text NOT NULL CHECK (args_digest ~ '^sha256:[0-9a-f]{64}$'),
  context_digest      text NOT NULL,
  -- Only the allow-listed context keys (R-11); never a prompt.
  context             jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- Present only while the workspace retains redacted arguments, and pruned
  -- after retention_days.
  args_redacted       jsonb,
  session_key         text NOT NULL DEFAULT '',
  idempotency_key     text NOT NULL CHECK (idempotency_key <> '' AND length(idempotency_key) <= 200),
  decision            text NOT NULL CHECK (decision IN ('allow','deny','hold')),
  reason_code         text NOT NULL CHECK (reason_code <> ''),
  reasons             jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- The hold whose approval this allow carries (a resume).
  approval_ref        uuid,
  binding_hash        text NOT NULL,
  -- sha256 of the single-use decision token; allow only.
  token_hash          text,
  expires_at          timestamptz NOT NULL,
  consumed_at         timestamptz,
  consumed_by         text CHECK (consumed_by IN ('redeem','broker')),
  -- R-07: what the agent reports happened, apart from what AuthSec decided.
  tool_outcome        text CHECK (tool_outcome IN ('succeeded','failed','not_executed','unknown')),
  aws_outcome         jsonb,
  actual_cost         bigint CHECK (actual_cost >= 0),
  outcome_source      text CHECK (outcome_source IN ('agent_reported')),
  outcome_reported_at timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT iga_gov_rtd_allow_chk CHECK ((decision = 'allow') = (token_hash IS NOT NULL)),
  CONSTRAINT iga_gov_rtd_consume_chk CHECK ((consumed_at IS NULL) = (consumed_by IS NULL) AND (consumed_at IS NULL OR decision = 'allow')),
  CONSTRAINT iga_gov_rtd_outcome_chk CHECK ((tool_outcome IS NULL) = (outcome_reported_at IS NULL) AND (tool_outcome IS NULL OR decision = 'allow')),
  CONSTRAINT iga_gov_rtd_policy_chk CHECK ((policy_id IS NULL) = (version_id IS NULL) AND (decision = 'deny' OR version_id IS NOT NULL))
);
-- Idempotency: one first decision per (agent, key); one resume per approval
-- (an approved operation executes at most once, R-06).
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_runtime_decision_idem
  ON iga_gov_runtime_decision (workspace_id, agent_ref, idempotency_key) WHERE approval_ref IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_runtime_decision_resume
  ON iga_gov_runtime_decision (workspace_id, approval_ref) WHERE approval_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_gov_runtime_decision_ws_created
  ON iga_gov_runtime_decision (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iga_gov_runtime_decision_due
  ON iga_gov_runtime_decision (expires_at) WHERE decision = 'allow' AND tool_outcome IS NULL;

-- The binding (R-03) never changes after insert; consumption happens once;
-- an outcome is reported once (an 'unknown' may be settled once more);
-- retained arguments may only be pruned.
CREATE OR REPLACE FUNCTION iga_gov_runtime_decision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.version_id IS DISTINCT FROM OLD.version_id OR NEW.intent_hash IS DISTINCT FROM OLD.intent_hash
     OR NEW.agent_ref IS DISTINCT FROM OLD.agent_ref OR NEW.agent_client_id IS DISTINCT FROM OLD.agent_client_id
     OR NEW.human_user_id IS DISTINCT FROM OLD.human_user_id OR NEW.tool IS DISTINCT FROM OLD.tool
     OR NEW.action IS DISTINCT FROM OLD.action OR NEW.target IS DISTINCT FROM OLD.target
     OR NEW.args_digest IS DISTINCT FROM OLD.args_digest OR NEW.context_digest IS DISTINCT FROM OLD.context_digest
     OR NEW.session_key IS DISTINCT FROM OLD.session_key OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.decision IS DISTINCT FROM OLD.decision OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
     OR NEW.approval_ref IS DISTINCT FROM OLD.approval_ref OR NEW.binding_hash IS DISTINCT FROM OLD.binding_hash
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'iga_gov_runtime_decision % binds its arguments, policy version, approval and expiry; it cannot change', OLD.id;
  END IF;
  IF OLD.consumed_at IS NOT NULL AND (NEW.consumed_at IS DISTINCT FROM OLD.consumed_at OR NEW.consumed_by IS DISTINCT FROM OLD.consumed_by) THEN
    RAISE EXCEPTION 'iga_gov_runtime_decision % was already consumed', OLD.id;
  END IF;
  IF OLD.tool_outcome IS NOT NULL AND OLD.tool_outcome <> 'unknown'
     AND (NEW.tool_outcome IS DISTINCT FROM OLD.tool_outcome OR NEW.aws_outcome IS DISTINCT FROM OLD.aws_outcome
          OR NEW.actual_cost IS DISTINCT FROM OLD.actual_cost) THEN
    RAISE EXCEPTION 'iga_gov_runtime_decision % already has its outcome', OLD.id;
  END IF;
  IF NEW.args_redacted IS NOT NULL AND NEW.args_redacted IS DISTINCT FROM OLD.args_redacted THEN
    RAISE EXCEPTION 'iga_gov_runtime_decision % retained arguments can only be pruned', OLD.id;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS iga_gov_runtime_decision_guard ON iga_gov_runtime_decision;
CREATE TRIGGER iga_gov_runtime_decision_guard BEFORE UPDATE ON iga_gov_runtime_decision
  FOR EACH ROW EXECUTE FUNCTION iga_gov_runtime_decision_guard();

CREATE TABLE IF NOT EXISTS iga_gov_runtime_hold (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  -- The 'hold' decision this row keeps durable.
  decision_id          uuid NOT NULL,
  policy_id            uuid NOT NULL,
  version_id           uuid NOT NULL,
  agent_ref            text NOT NULL,
  human_user_id        uuid NOT NULL,
  tool                 text NOT NULL,
  action               text NOT NULL DEFAULT '',
  target               text NOT NULL DEFAULT '',
  args_digest          text NOT NULL CHECK (args_digest ~ '^sha256:[0-9a-f]{64}$'),
  idempotency_key      text NOT NULL,
  reason               text NOT NULL DEFAULT '',
  state                text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','rejected','expired','cancelled','resumed')),
  expires_at           timestamptz NOT NULL,
  decided_by           uuid REFERENCES users(id),
  decided_at           timestamptz,
  decision_reason      text NOT NULL DEFAULT '',
  approval_valid_until timestamptz,
  resumed_decision_id  uuid,
  resumed_at           timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, decision_id) REFERENCES iga_gov_runtime_decision (workspace_id, id),
  -- Separation of duties: the human who initiated the operation never
  -- approves it.
  CONSTRAINT iga_gov_rth_sod_chk CHECK (decided_by IS NULL OR decided_by <> human_user_id),
  CONSTRAINT iga_gov_rth_decided_chk CHECK (
    (state NOT IN ('pending','cancelled') OR decided_by IS NULL)
    AND (state NOT IN ('approved','rejected','resumed') OR decided_by IS NOT NULL)
    AND (state NOT IN ('approved','resumed') OR approval_valid_until IS NOT NULL)),
  CONSTRAINT iga_gov_rth_resumed_chk CHECK ((state = 'resumed') = (resumed_decision_id IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_runtime_hold_decision ON iga_gov_runtime_hold (workspace_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_iga_gov_runtime_hold_due ON iga_gov_runtime_hold (state, expires_at);

CREATE TABLE IF NOT EXISTS iga_gov_runtime_budget (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id      uuid NOT NULL,
  -- The version whose limit opened this ledger (a later version applies to
  -- new sessions only, DECISION R3-14).
  version_id     uuid NOT NULL,
  agent_ref      text NOT NULL,
  session_key    text NOT NULL CHECK (session_key <> ''),
  budget_key     text NOT NULL CHECK (budget_key <> ''),
  unit           text NOT NULL CHECK (unit IN ('calls','cost')),
  limit_amount   bigint NOT NULL CHECK (limit_amount > 0),
  reserved       bigint NOT NULL DEFAULT 0 CHECK (reserved >= 0),
  spent          bigint NOT NULL DEFAULT 0 CHECK (spent >= 0),
  window_ends_at timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, policy_id, agent_ref, session_key, budget_key),
  FOREIGN KEY (workspace_id, policy_id) REFERENCES iga_gov_policy (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iga_gov_runtime_budget_entry (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  budget_id       uuid NOT NULL,
  decision_id     uuid NOT NULL,
  reserved_amount bigint NOT NULL CHECK (reserved_amount > 0),
  settled_amount  bigint CHECK (settled_amount >= 0),
  overrun         bigint NOT NULL DEFAULT 0 CHECK (overrun >= 0),
  state           text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','settled','released')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  settled_at      timestamptz,
  UNIQUE (workspace_id, id),
  UNIQUE (budget_id, decision_id),
  FOREIGN KEY (workspace_id, budget_id) REFERENCES iga_gov_runtime_budget (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, decision_id) REFERENCES iga_gov_runtime_decision (workspace_id, id),
  CONSTRAINT iga_gov_rtbe_state_chk CHECK ((state = 'reserved') = (settled_at IS NULL)
    AND (state <> 'settled' OR settled_amount IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_runtime_budget_entry_open ON iga_gov_runtime_budget_entry (state, created_at) WHERE state = 'reserved';

CREATE TABLE IF NOT EXISTS iga_gov_runtime_routing_proof (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  gateway_arn   text NOT NULL CHECK (gateway_arn ~ '^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:gateway/.+'),
  account_id    text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  method        text NOT NULL CHECK (method IN ('lab_probe','network_isolation','customer_attestation')),
  statement     text NOT NULL CHECK (statement <> ''),
  evidence      jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  evidence_hash text NOT NULL,
  recorded_by   uuid NOT NULL REFERENCES users(id),
  recorded_at   timestamptz NOT NULL DEFAULT now(),
  valid_until   timestamptz NOT NULL,
  revoked_at    timestamptz,
  revoked_by    uuid REFERENCES users(id),
  revoke_reason text NOT NULL DEFAULT '',
  UNIQUE (workspace_id, id),
  CONSTRAINT iga_gov_rtrp_window_chk CHECK (valid_until > recorded_at AND valid_until <= recorded_at + interval '91 days'),
  CONSTRAINT iga_gov_rtrp_revoked_chk CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_runtime_routing_proof_gw ON iga_gov_runtime_routing_proof (workspace_id, gateway_arn);

CREATE TABLE IF NOT EXISTS iga_gov_runtime_agentcore_push (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id        uuid NOT NULL,
  version_id       uuid NOT NULL,
  gateway_arn      text NOT NULL,
  policy_engine_id text NOT NULL CHECK (policy_engine_id <> ''),
  cedar            jsonb NOT NULL CHECK (jsonb_typeof(cedar) = 'array'),
  cedar_hash       text NOT NULL,
  state            text NOT NULL CHECK (state IN ('pushed','failed','readback_match','readback_mismatch')),
  remote           jsonb NOT NULL DEFAULT '[]'::jsonb,
  gateway_mode     text NOT NULL DEFAULT '',
  error            text NOT NULL DEFAULT '',
  pushed_by        uuid NOT NULL REFERENCES users(id),
  created_at       timestamptz NOT NULL DEFAULT now(),
  readback_at      timestamptz,
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, version_id, policy_id) REFERENCES iga_gov_runtime_version (workspace_id, id, policy_id)
);
CREATE INDEX IF NOT EXISTS idx_iga_gov_runtime_agentcore_push_gw ON iga_gov_runtime_agentcore_push (workspace_id, gateway_arn, created_at DESC);

CREATE TABLE IF NOT EXISTS iga_gov_runtime_broker_role (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  connector_id        uuid NOT NULL,
  account_id          text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  role_arn            text NOT NULL CHECK (role_arn ~ '^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+'),
  max_session_seconds int NOT NULL DEFAULT 900 CHECK (max_session_seconds BETWEEN 900 AND 3600),
  state               text NOT NULL DEFAULT 'active' CHECK (state IN ('active','disabled')),
  created_by          uuid NOT NULL REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  disabled_by         uuid REFERENCES users(id),
  disabled_at         timestamptz,
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, connector_id) REFERENCES cloud_connector (workspace_id, id),
  CONSTRAINT iga_gov_rtbr_disabled_chk CHECK ((state = 'disabled') = (disabled_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_runtime_broker_role_live
  ON iga_gov_runtime_broker_role (workspace_id, role_arn) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS iga_gov_runtime_broker_session (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  broker_role_id      uuid NOT NULL,
  decision_id         uuid NOT NULL,
  agent_ref           text NOT NULL,
  human_user_id       uuid NOT NULL,
  role_arn            text NOT NULL,
  session_name        text NOT NULL,
  source_identity     text NOT NULL,
  session_policy_hash text NOT NULL,
  session_tags        jsonb NOT NULL,
  duration_seconds    int NOT NULL CHECK (duration_seconds BETWEEN 900 AND 3600),
  -- Written ahead of the STS call ('requested'), then 'issued' or 'failed'.
  -- Credentials are returned once and never stored.
  state               text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','issued','failed')),
  assumed_role_arn    text NOT NULL DEFAULT '',
  expires_at          timestamptz,
  error               text NOT NULL DEFAULT '',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  -- One brokered session per allow decision.
  UNIQUE (workspace_id, decision_id),
  FOREIGN KEY (workspace_id, broker_role_id) REFERENCES iga_gov_runtime_broker_role (workspace_id, id),
  FOREIGN KEY (workspace_id, decision_id) REFERENCES iga_gov_runtime_decision (workspace_id, id)
);

-- verify ----------------------------------------------------------------------
-- Row-level security (CLAUDE.md §7, migration 111): every workspace table
-- gets the tenancy policy. On a database where 111 already ran (production
-- upgrades), enable it here; on a fresh database 111 has not run yet when
-- 062 applies and its loop -- like 001's -- covers these tables later.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_version');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_settings');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_decision');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_hold');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_budget');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_budget_entry');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_routing_proof');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_agentcore_push');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_broker_role');
        PERFORM public.tenancy_enable_rls('public.iga_gov_runtime_broker_session');
    END IF;
END $$;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['iga_gov_runtime_version','iga_gov_runtime_settings','iga_gov_runtime_decision',
                             'iga_gov_runtime_hold','iga_gov_runtime_budget','iga_gov_runtime_budget_entry',
                             'iga_gov_runtime_routing_proof','iga_gov_runtime_agentcore_push',
                             'iga_gov_runtime_broker_role','iga_gov_runtime_broker_session',
                             'uq_iga_gov_runtime_version_one_approved','uq_iga_gov_runtime_decision_idem',
                             'uq_iga_gov_runtime_decision_resume','uq_iga_gov_runtime_hold_decision',
                             'uq_iga_gov_runtime_broker_role_live'] LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            RAISE EXCEPTION '062: % is missing', t;
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'iga_gov_runtime_decision_guard'
                    AND tgrelid = 'public.iga_gov_runtime_decision'::regclass) THEN
        RAISE EXCEPTION '062: the decision guard trigger is missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'iga_gov_runtime_version_immutable'
                    AND tgrelid = 'public.iga_gov_runtime_version'::regclass) THEN
        RAISE EXCEPTION '062: the version immutability trigger is missing';
    END IF;
END $$;
