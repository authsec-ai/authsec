-- ============================================================================
-- 132: iga_gov_notification's natural key is per workspace
--
-- 054 made (subject_kind, subject_id, channel, recipient) unique across ALL
-- workspaces, and EnqueueGovNotificationTx's ON CONFLICT names that key. Under
-- row-level security a conflict with another workspace's row is invisible:
-- the insert does nothing, the follow-up read finds nothing, and the notice
-- is lost (CLAUDE.md §4 rule 8: unique constraints are scoped per tenant).
--
-- Expand, then contract: the key led by workspace_id is built first (as an
-- index, then attached as a constraint), and only then is 054's global key
-- dropped. Idempotent: a database that already has the new key (bootstrap)
-- is left as it is.
--
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS iga_gov_notification_ws_subject_channel_recipient_key
    ON public.iga_gov_notification (workspace_id, subject_kind, subject_id, channel, recipient);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.iga_gov_notification'::regclass
                      AND conname = 'iga_gov_notification_ws_subject_channel_recipient_key') THEN
        ALTER TABLE public.iga_gov_notification
            ADD CONSTRAINT iga_gov_notification_ws_subject_channel_recipient_key
            UNIQUE USING INDEX iga_gov_notification_ws_subject_channel_recipient_key;
    END IF;
END $$;

ALTER TABLE public.iga_gov_notification
    DROP CONSTRAINT IF EXISTS iga_gov_notification_subject_kind_subject_id_channel_recipi_key;
