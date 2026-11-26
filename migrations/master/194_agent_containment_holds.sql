-- 194_agent_containment_holds.sql
--
-- SecOps W2 (SPEC-secops-backend-upgrade.md P2, P3, decision 4): stops held
-- by cases, and their release by a second person.
--
-- 1. agent_containment_release_request: a request to release one case's
--    hold on a containment (case_id set) or a containment without holds
--    (case_id NULL). Releasing is tier 3: a DIFFERENT user holding
--    governance:approve approves it (author != approver, enforced here as
--    well). A workspace where no other user holds governance:approve gets
--    break-glass: the request applies alone (break_glass) and a review by
--    another person is due within 24 hours (review_due_at).
-- 2. agent_containment_hold: one case holding one containment. The
--    containment is released only when its last active hold is released.
--    case_id is a uuid WITHOUT a foreign key: agent_case is created by W3
--    (migrations 186-192) on another branch.
--    -- FK to agent_case added when W3 merges
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS agent_containment_release_request (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  containment_id  uuid NOT NULL,
  -- NULL: release of a containment no case holds.
  case_id         uuid,
  reason          text NOT NULL CHECK (btrim(reason) <> ''),
  state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','rejected','withdrawn')),
  requested_by    uuid NOT NULL REFERENCES users(id),
  requested_at    timestamptz NOT NULL DEFAULT now(),
  decided_by      uuid REFERENCES users(id),
  decided_at      timestamptz,
  decision_reason text NOT NULL DEFAULT '',
  break_glass     boolean NOT NULL DEFAULT false,
  review_due_at   timestamptz,
  reviewed_by     uuid REFERENCES users(id),
  reviewed_at     timestamptz,
  review_note     text NOT NULL DEFAULT '',
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, containment_id) REFERENCES agent_containment (workspace_id, id) ON DELETE CASCADE,
  CONSTRAINT agent_containment_release_request_second_person_chk
    CHECK (decided_by IS NULL OR break_glass OR decided_by <> requested_by),
  CONSTRAINT agent_containment_release_request_review_chk
    CHECK (reviewed_by IS NULL OR reviewed_by <> requested_by),
  CONSTRAINT agent_containment_release_request_break_glass_chk
    CHECK (NOT break_glass OR review_due_at IS NOT NULL),
  CONSTRAINT agent_containment_release_request_decided_chk
    CHECK ((state = 'pending') = (decided_at IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_containment_release_request_pending
  ON agent_containment_release_request (workspace_id, containment_id, (coalesce(case_id, '00000000-0000-0000-0000-000000000000'::uuid)))
  WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_agent_containment_release_request_state
  ON agent_containment_release_request (workspace_id, state, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_containment_release_request_review
  ON agent_containment_release_request (workspace_id, review_due_at)
  WHERE break_glass AND reviewed_at IS NULL;

CREATE TABLE IF NOT EXISTS agent_containment_hold (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  containment_id     uuid NOT NULL,
  case_id            uuid NOT NULL, -- FK to agent_case added when W3 merges
  state              text NOT NULL DEFAULT 'active' CHECK (state IN ('active','released')),
  held_by            uuid NOT NULL REFERENCES users(id),
  held_at            timestamptz NOT NULL DEFAULT now(),
  released_by        uuid REFERENCES users(id),
  released_at        timestamptz,
  release_reason     text NOT NULL DEFAULT '',
  release_request_id uuid,
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, containment_id) REFERENCES agent_containment (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, release_request_id) REFERENCES agent_containment_release_request (workspace_id, id),
  CONSTRAINT agent_containment_hold_released_chk CHECK ((state = 'released') = (released_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_containment_hold_active
  ON agent_containment_hold (workspace_id, containment_id, case_id) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_agent_containment_hold_case ON agent_containment_hold (workspace_id, case_id);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_containment_release_request');
        PERFORM public.tenancy_enable_rls('public.agent_containment_hold');
    END IF;
END $$;
