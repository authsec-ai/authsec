-- 057_slack_link_one_per_member.sql
--
-- One Slack link per member (Phase 3 review fix P0-3, SPEC-iga-phase3-policy.md
-- §7.11, §2.10 separation of duties).
--
-- expand only (one new unique index on an existing table). Idempotent: safe
-- to run again.
--
-- WHY
-- slack_user_link (054) maps a Slack user to a workspace member; Slack
-- approvals act as the mapped member. 054 keys the table by
-- (workspace_id, slack_user_id) -- one member per Slack user -- but nothing
-- stopped one member holding several Slack users, and POST /link/confirm
-- bound whatever Slack user a link token named to whoever signed in, without
-- proof that the member owned that Slack account. An author could forward
-- the token their own Slack account was given to an approver; once the
-- approver confirmed it, the author's Slack clicks acted as the approver.
--
-- The application now links a Slack user to a member only when Slack reports
-- the Slack account's email as confirmed and it equals the member's email
-- (automatically when exactly one member has it, by /link/confirm when the
-- email is ambiguous). This file adds the database half:
--
--   uq_slack_user_link_member UNIQUE (workspace_id, user_id): a member holds
--   at most one Slack link per workspace. A workspace has at most one Slack
--   team (workspace_slack_integration is keyed by workspace_id) and every
--   link of a workspace is deleted when its team is disconnected or replaced,
--   so per workspace is per Slack team.
--
-- EXISTING LINKS (decided: revoked). Before the index exists -- i.e. on the
-- first run only; a re-run finds the index and changes no row -- this file
-- deletes:
--   1. every console_confirmation link: each was made by the old
--      /link/confirm, which proved nothing about who owns the Slack account,
--      so none can be told apart from a forwarded one. The member is linked
--      again automatically by confirmed email on their next Slack action, or
--      confirms again under the new rule;
--   2. every link of a member who still holds more than one: there is no
--      basis to pick one. The confirmed-email rule relinks the right one.
-- Each deleted link is listed in a NOTICE (workspace, Slack user, member,
-- how it was made) for the deploy log. Unlinked members keep receiving
-- email; a Slack click from an unlinked account is answered "Link your Slack
-- account" and does nothing.
--
-- 001_bootstrap.sql carries the same index.

DO $$
DECLARE
    r record;
    n int := 0;
BEGIN
    IF to_regclass('public.uq_slack_user_link_member') IS NOT NULL THEN
        RETURN;
    END IF;
    FOR r IN
        DELETE FROM public.slack_user_link l
         WHERE l.linked_via = 'console_confirmation'
            OR EXISTS (SELECT 1 FROM public.slack_user_link o
                        WHERE o.workspace_id = l.workspace_id AND o.user_id = l.user_id
                          AND o.slack_user_id <> l.slack_user_id
                          AND o.linked_via <> 'console_confirmation')
         RETURNING l.workspace_id, l.slack_user_id, l.user_id, l.linked_via
    LOOP
        n := n + 1;
        RAISE NOTICE '057: revoked Slack link workspace=% slack_user=% member=% (%)',
            r.workspace_id, r.slack_user_id, r.user_id, r.linked_via;
    END LOOP;
    RAISE NOTICE '057: % Slack link(s) revoked', n;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_slack_user_link_member
  ON public.slack_user_link (workspace_id, user_id);

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    d text;
BEGIN
    SELECT pg_get_indexdef(i.indexrelid) INTO d
      FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
     WHERE c.relname = 'uq_slack_user_link_member' AND i.indisunique AND i.indisvalid;
    IF d IS NULL OR d NOT LIKE '%(workspace_id, user_id)%' OR d LIKE '%WHERE%' THEN
        RAISE EXCEPTION '057: uq_slack_user_link_member is not UNIQUE (workspace_id, user_id) (%)', d;
    END IF;
END $$;
