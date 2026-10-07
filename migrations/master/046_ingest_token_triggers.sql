-- 046_ingest_token_triggers.sql — the database itself keeps a source-bound
-- ingest token bound, and revokes it when its source is deleted.
--
-- expand only. Idempotent: safe to run again.
--
-- WHY
-- 044 keeps a deleted source's tokens (ON DELETE SET NULL) and relies on the
-- APPLICATION for the two things that stop such a token from widening into a
-- workspace-wide one: Mint sets source_bound on a token minted for a source,
-- and DeleteSource revokes the source's tokens before it deletes the source.
-- Code that predates 044 does neither. While a rollout still has pods running
-- it (or anything else writes these tables directly), a bound token can be
-- minted with source_bound left false, and a source can be deleted without
-- revoking its tokens. The foreign key then nulls discovery_source_id of a
-- live, unflagged token -- source NULL, source_bound false, revoked_at NULL --
-- which is exactly what a workspace-wide token looks like, and
-- discovery_ingest_tokens_bound_chk cannot object (it only constrains rows
-- that are source_bound).
--
-- So both rules move into the database, where no code path can skip them:
--
--   1. discovery_ingest_tokens_mark_bound, BEFORE INSERT OR UPDATE on
--      discovery_ingest_tokens: a row with a discovery_source_id is
--      source_bound, whatever the writer said. source_bound is never cleared
--      by it: a row that was bound stays bound, so a later UPDATE cannot turn
--      a once-bound token into a workspace token either.
--
--   2. discovery_sources_revoke_ingest_tokens, BEFORE DELETE on
--      discovery_sources: every token bound to the source being deleted is
--      revoked (revoked_at = COALESCE(revoked_at, now()), so an earlier
--      revocation keeps its time) and marked source_bound, BEFORE the foreign
--      key nulls its source. The application's own DeleteSource already did
--      exactly this in the same transaction, so for it the trigger finds
--      nothing left to change and is a no-op; a delete that bypasses the
--      application gets the same result. Deleting a whole workspace still
--      deletes its tokens (043's workspace FK cascades); the trigger only
--      revokes rows that are deleted a moment later.
--
-- Both keep discovery_ingest_tokens_bound_chk (044) and _hash_chk (043)
-- satisfied: (1) only ever sets source_bound on a row that has a source, and
-- (2) revokes while the source is still set, so when the FK nulls it the row
-- is already revoked.
--
-- 3. Backfill: tokens minted for a source by pre-044 code since 044 ran are
--    marked source_bound now, as 044 did for the tokens that existed then.
--    (A token whose source was deleted by pre-044 code in that window is
--    already indistinguishable from a workspace token and cannot be repaired
--    here; see the deploy note on the commit.)

-- 1. A token with a source is bound ---------------------------------------
CREATE OR REPLACE FUNCTION public.discovery_ingest_tokens_mark_bound()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF NEW.discovery_source_id IS NOT NULL THEN
        NEW.source_bound := true;
    ELSIF TG_OP = 'UPDATE' AND OLD.source_bound THEN
        NEW.source_bound := true;
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS discovery_ingest_tokens_mark_bound ON public.discovery_ingest_tokens;
CREATE TRIGGER discovery_ingest_tokens_mark_bound
    BEFORE INSERT OR UPDATE ON public.discovery_ingest_tokens
    FOR EACH ROW EXECUTE FUNCTION public.discovery_ingest_tokens_mark_bound();

-- 2. Deleting a source revokes its tokens ---------------------------------
CREATE OR REPLACE FUNCTION public.discovery_sources_revoke_ingest_tokens()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    UPDATE public.discovery_ingest_tokens
       SET revoked_at   = COALESCE(revoked_at, now()),
           source_bound = true
     WHERE workspace_id = OLD.workspace_id
       AND discovery_source_id = OLD.id
       AND (revoked_at IS NULL OR NOT source_bound);
    RETURN OLD;
END
$fn$;

DROP TRIGGER IF EXISTS discovery_sources_revoke_ingest_tokens ON public.discovery_sources;
CREATE TRIGGER discovery_sources_revoke_ingest_tokens
    BEFORE DELETE ON public.discovery_sources
    FOR EACH ROW EXECUTE FUNCTION public.discovery_sources_revoke_ingest_tokens();

-- 3. Backfill -------------------------------------------------------------
UPDATE public.discovery_ingest_tokens
   SET source_bound = true
 WHERE discovery_source_id IS NOT NULL AND NOT source_bound;

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM pg_trigger
     WHERE tgrelid = 'public.discovery_ingest_tokens'::regclass
       AND tgname = 'discovery_ingest_tokens_mark_bound'
       AND tgenabled <> 'D' AND NOT tgisinternal;
    IF n <> 1 THEN
        RAISE EXCEPTION '046: trigger discovery_ingest_tokens_mark_bound is missing or disabled';
    END IF;

    SELECT count(*) INTO n FROM pg_trigger
     WHERE tgrelid = 'public.discovery_sources'::regclass
       AND tgname = 'discovery_sources_revoke_ingest_tokens'
       AND tgenabled <> 'D' AND NOT tgisinternal;
    IF n <> 1 THEN
        RAISE EXCEPTION '046: trigger discovery_sources_revoke_ingest_tokens is missing or disabled';
    END IF;

    SELECT count(*) INTO n FROM public.discovery_ingest_tokens
     WHERE discovery_source_id IS NOT NULL AND NOT source_bound;
    IF n <> 0 THEN
        RAISE EXCEPTION '046: % ingest token(s) bound to a source are not source_bound', n;
    END IF;
END $$;
