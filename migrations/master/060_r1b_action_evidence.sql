-- 060_r1b_action_evidence.sql
--
-- Phase 3 R1b -- action-level right-sizing (SPEC-iga-phase3-policy.md
-- §12.1; requirements P-15). There is no R1b implementation spec; the
-- decisions are DECISION R1b-n comments in internal/igagov/actions.go.
--
-- 1. iga_gov_finding.kind gains 'unused_action': an action of a service the
--    role keeps, with no CloudTrail event in a qualified window.
-- 2. iga_gov_action_evidence: the per-revision, per role x action evidence
--    the evaluation step copies out of cloud_observation (CloudTrail
--    management events attributed by session issuer, T3.04), frozen like
--    iga_gov_activity_evidence once its evaluation completes.
--
-- Expand only: the kind CHECK is widened (every row valid before is valid
-- after) and one table is added. Idempotent: safe to run again (DROP
-- CONSTRAINT IF EXISTS + ADD, IF NOT EXISTS, DROP TRIGGER IF EXISTS).
-- 001_bootstrap.sql carries the same objects.
--
-- R1b runs only when IGA_POLICY_R1B=on, which requires IGA_POLICY=on and
-- this migration verified (services.VerifyPolicyR1BSchema). The R1a gate
-- (VerifyPolicySchema, head 059) does not read anything here, so a database
-- without 060 keeps R1a fully available.

ALTER TABLE iga_gov_finding DROP CONSTRAINT IF EXISTS iga_gov_finding_kind_check;
ALTER TABLE iga_gov_finding ADD CONSTRAINT iga_gov_finding_kind_check
  CHECK (kind IN ('unused_service','broad_grant','shared_role',
                  'missing_owner','missing_review_date','activity_not_read','unused_action'));

CREATE TABLE IF NOT EXISTS iga_gov_action_evidence (
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  rev                  bigint NOT NULL,
  identity_account_id  uuid NOT NULL,
  role_id              text NOT NULL,
  service              text NOT NULL,
  -- The action as granted (lower-cased namespace), and its case-insensitive
  -- key (IAM action names are case-insensitive).
  action               text NOT NULL,
  action_key           text NOT NULL,
  state                text NOT NULL CHECK (state IN ('collected','not_collected')),
  outcome              text NOT NULL CHECK (outcome IN ('observed','no_event','not_enough_history',
                         'not_observable','unreviewed','not_collected')),
  reason               text NOT NULL DEFAULT '',
  last_event_at        timestamptz,
  event_count          integer NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  coverage_start       timestamptz,
  covered_until        timestamptz,
  window_start         timestamptz,
  qualified_days       integer NOT NULL DEFAULT 0 CHECK (qualified_days >= 0),
  grant_observed_since timestamptz,
  grant_age_basis      text NOT NULL CHECK (grant_age_basis IN ('observed_since_change','predates_observation','unknown')),
  -- CloudTrail records the action only as a data event (catalog actions@N).
  data_event           boolean NOT NULL DEFAULT false,
  -- The role connector's run in rev's manifest (as iga_gov_activity_evidence).
  scan_run_id          uuid,
  -- The event->action map and data-event catalog version ("actions@1").
  catalog              text NOT NULL,
  PRIMARY KEY (workspace_id, rev, identity_account_id, action_key),
  CONSTRAINT iga_gov_xe_key_chk CHECK (action_key = lower(action)),
  CONSTRAINT iga_gov_xe_state_chk CHECK ((state = 'not_collected') = (outcome = 'not_collected')),
  CONSTRAINT iga_gov_xe_collected_chk CHECK (state = 'not_collected' OR (covered_until IS NOT NULL AND window_start IS NOT NULL)),
  FOREIGN KEY (workspace_id, scan_run_id) REFERENCES cloud_scan_run (workspace_id, id),
  FOREIGN KEY (workspace_id, rev) REFERENCES iga_gov_evaluation (workspace_id, rev) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, identity_account_id) REFERENCES iga_identity_accounts (workspace_id, id) ON DELETE CASCADE
);

-- Written only while its evaluation is running; frozen afterwards (048's
-- function, shared with iga_gov_activity_evidence and iga_gov_finding_result).
DROP TRIGGER IF EXISTS iga_gov_action_evidence_frozen ON iga_gov_action_evidence;
CREATE TRIGGER iga_gov_action_evidence_frozen BEFORE INSERT OR UPDATE ON iga_gov_action_evidence
  FOR EACH ROW EXECUTE FUNCTION iga_gov_evaluation_rows_frozen();

-- verify ----------------------------------------------------------------------
-- Row-level security (CLAUDE.md §7, migration 111): every workspace table
-- gets the tenancy policy. On a database where 111 already ran (production
-- upgrades), enable it here; on a fresh database 111 has not run yet when
-- 060 applies and its loop -- like 001's -- covers this table later.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_gov_action_evidence');
    END IF;
END $$;

DO $$
DECLARE
    n integer;
BEGIN
    IF to_regclass('public.iga_gov_action_evidence') IS NULL THEN
        RAISE EXCEPTION '060: table iga_gov_action_evidence is missing';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_finding'::regclass AND conname = 'iga_gov_finding_kind_check'
       AND pg_get_constraintdef(oid) LIKE '%unused_action%' AND pg_get_constraintdef(oid) LIKE '%activity_not_read%';
    IF n <> 1 THEN
        RAISE EXCEPTION '060: iga_gov_finding_kind_check does not admit unused_action alongside the R1a kinds';
    END IF;

    SELECT count(*) INTO n FROM pg_trigger
     WHERE tgrelid = 'public.iga_gov_action_evidence'::regclass AND tgname = 'iga_gov_action_evidence_frozen' AND NOT tgisinternal;
    IF n <> 1 THEN
        RAISE EXCEPTION '060: trigger iga_gov_action_evidence_frozen is missing';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_action_evidence'::regclass AND contype = 'f'
       AND confrelid = 'public.iga_gov_evaluation'::regclass AND confdeltype = 'c';
    IF n <> 1 THEN
        RAISE EXCEPTION '060: iga_gov_action_evidence has no cascading key to iga_gov_evaluation';
    END IF;
END $$;
