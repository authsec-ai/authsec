-- 054_slack_and_notifications.sql
--
-- Phase 3 Slack installation, Slack user links and the notification outbox
-- (sections 7.11, 8).
--
-- New tables: workspace_slack_integration, slack_user_link,
-- iga_gov_notification.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 054_slack_and_notifications.sql, verbatim; section 6.3 lists the probes
-- that prove it (tests/igagovschema). 001_bootstrap.sql carries the same
-- objects.

CREATE TABLE IF NOT EXISTS workspace_slack_integration (
  workspace_id         uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  slack_team_id        text NOT NULL,
  slack_team_name      text NOT NULL DEFAULT '',
  bot_token_ref        text NOT NULL,
  approvals_channel_id text NOT NULL DEFAULT '',
  installed_by         uuid NOT NULL REFERENCES users(id),
  installed_at         timestamptz NOT NULL DEFAULT now(),
  revoked_at           timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_slack_team
  ON workspace_slack_integration (slack_team_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS slack_user_link (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  slack_user_id text NOT NULL,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  linked_via    text NOT NULL CHECK (linked_via IN ('verified_email','console_confirmation')),
  linked_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, slack_user_id)
);

CREATE TABLE IF NOT EXISTS iga_gov_notification (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  subject_kind  text NOT NULL CHECK (subject_kind IN ('owner_review','approval_request','deployment','drift','canary_gate','finding_digest')),
  subject_id    uuid NOT NULL,
  channel       text NOT NULL CHECK (channel IN ('email','webhook','slack')),
  recipient     text NOT NULL,
  state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sent','failed','dead')),
  attempt_count int NOT NULL DEFAULT 0,
  last_error    text NOT NULL DEFAULT '',
  slack_ts      text NOT NULL DEFAULT '',
  last_action_ts text NOT NULL DEFAULT '',
  available_at  timestamptz NOT NULL DEFAULT now(),
  sent_at       timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (subject_kind, subject_id, channel, recipient),
  CONSTRAINT iga_gov_pn_sent_chk CHECK ((state = 'sent') = (sent_at IS NOT NULL))
);
