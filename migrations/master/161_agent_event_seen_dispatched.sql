-- 161_agent_event_seen_dispatched.sql
--
-- The event stream's dedupe ledger records whether an event's consumers ran
-- (SPEC-agent-runtime-visibility.md §5.6).
--
-- Until now an event's row in agent_event_seen was committed BEFORE the
-- consumers (live counter, alerts, activity, containment check) ran, and only
-- a normal dispatch error removed it. A process that died between the commit
-- and the dispatch left the row behind: EventBridge's retry of the same event
-- was then deduplicated away and the consumers never saw it.
--
-- Now a row is inserted with dispatched_at NULL, set once every consumer has
-- returned; a delivery whose rows are still NULL is dispatched again. Every
-- consumer is idempotent by eventID, so a second dispatch changes nothing.
--
-- Expand + backfill. Idempotent. Existing rows were dispatched (or released on
-- error), so they are marked dispatched at their receipt time.
-- 001_bootstrap.sql carries the same block at its end.

ALTER TABLE public.agent_event_seen ADD COLUMN IF NOT EXISTS dispatched_at timestamptz;
UPDATE public.agent_event_seen SET dispatched_at = received_at WHERE dispatched_at IS NULL;
