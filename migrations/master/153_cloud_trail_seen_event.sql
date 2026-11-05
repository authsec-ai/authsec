-- ============================================================================
-- 153: CloudTrail event ids already counted as model-call evidence
-- (SPEC-agent-runtime-visibility.md §5.1).
--
-- CloudTrail delivers some events later than its "within 15 minutes on
-- average": an event can reach LookupEvents hours after its eventTime. A read
-- that starts exactly at the previous read_to never sees it. Reads now overlap
-- by a lookback (re-reading from read_to less an hour), and this table is what
-- keeps the overlap from counting an event twice: an event whose id is here
-- was already folded into cloud_usage and is skipped.
--
-- One row per counted event per connector, kept TRAILING_DAYS (7) by the
-- writer (rows older than that by event_time are deleted in the same
-- transaction that adds new ones). The id is CloudTrail's eventID: an opaque
-- id, never a credential or a request body.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_trail_seen_event (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id uuid        NOT NULL,
    event_id     text        NOT NULL,
    event_time   timestamptz NOT NULL,
    seen_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_trail_seen_event_id_chk CHECK (event_id <> ''),
    CONSTRAINT cloud_trail_seen_event_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_cloud_trail_seen_event
        PRIMARY KEY (workspace_id, connector_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_trail_seen_event_time
    ON public.cloud_trail_seen_event (workspace_id, connector_id, event_time);

COMMENT ON TABLE public.cloud_trail_seen_event IS
    'CloudTrail eventIDs already counted as model-call evidence, kept 7 days so overlapping reads never count an event twice.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.cloud_trail_seen_event');
    END IF;
END $$;
