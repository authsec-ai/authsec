-- 163_gateway_runtime_pending_change.sql
--
-- AS-174 (gateway revocation can fail open).
--
-- 1. agent_gateway.fail_mode / cache_ttl_seconds: AuthSec sets each
--    gateway's fail mode (what it does when the PDP cannot answer) and the
--    longest it may cache a decision. The gateway receives both in its
--    policy hints and its local configuration can only make them stricter.
--    Defaults keep today's behaviour: fail mode auto, cache cap 30 s (the
--    workspace default); the cache lifetime handed out is the smaller of
--    the workspace setting and the gateway's cap. Tightening applies at
--    once; loosening (closed -> auto/open, auto -> open, a longer cache) is
--    a tier-3 change that a second person must approve (pending_change).
--
-- 2. pending_change: a generic two-person change request (tier 3). One row
--    per requested change of one kind on one target: who asked, why, the
--    payload to apply, and who approved or rejected it. The approver is
--    never the requester (CHECK). At most one open request per kind and
--    target. break_glass marks a change applied alone because the workspace
--    had no second approver (review due by review_due_at).
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

ALTER TABLE agent_gateway ADD COLUMN IF NOT EXISTS fail_mode text NOT NULL DEFAULT 'auto'
  CHECK (fail_mode IN ('closed','auto','open'));
ALTER TABLE agent_gateway ADD COLUMN IF NOT EXISTS cache_ttl_seconds integer NOT NULL DEFAULT 30
  CHECK (cache_ttl_seconds BETWEEN 0 AND 300);

CREATE TABLE IF NOT EXISTS pending_change (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind            text NOT NULL CHECK (kind ~ '^[a-z0-9_.]{1,64}$'),
  target_ref      text NOT NULL CHECK (btrim(target_ref) <> '' AND length(target_ref) <= 512),
  payload         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
  reason          text NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
  state           text NOT NULL DEFAULT 'pending'
                  CHECK (state IN ('pending','approved','rejected','applied','expired')),
  requested_by    uuid NOT NULL REFERENCES users(id),
  requested_at    timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  approved_by     uuid REFERENCES users(id),
  approved_at     timestamptz,
  rejected_by     uuid REFERENCES users(id),
  rejected_at     timestamptz,
  decision_reason text NOT NULL DEFAULT '' CHECK (length(decision_reason) <= 2000),
  applied_at      timestamptz,
  break_glass     boolean NOT NULL DEFAULT false,
  review_due_at   timestamptz,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  CONSTRAINT pending_change_second_person_chk CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CONSTRAINT pending_change_break_glass_chk CHECK (NOT break_glass OR (approved_by IS NULL AND review_due_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_pending_change_ws_state ON pending_change (workspace_id, state, requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_change_open ON pending_change (workspace_id, kind, target_ref)
  WHERE state IN ('pending','approved');

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.pending_change');
    END IF;
END $$;
