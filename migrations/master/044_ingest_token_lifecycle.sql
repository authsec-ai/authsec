-- 044_ingest_token_lifecycle.sql — ingest tokens outlive their source, and can
-- expire.
--
-- expand only.
--
-- WHY
-- 043 bound a token to a discovery source with ON DELETE CASCADE, so deleting
-- a source deleted its tokens -- and with them the record of which token
-- authorised which writes, which is the audit trail the table exists for.
-- Here the reference is ON DELETE SET NULL instead. Because a NULL
-- discovery_source_id means "valid for any source in the workspace", the
-- application REVOKES a source's bound tokens in the same transaction before
-- deleting the source; the FK change only keeps the revoked row. A bound token
-- whose source vanished must never widen into a workspace token, so the CHECK
-- below refuses an active token that was ever bound and lost its source.
--
-- expires_at is optional: NULL never expires (as before). A token past its
-- expiry is refused exactly like a revoked one.

ALTER TABLE public.discovery_ingest_tokens
    ADD COLUMN IF NOT EXISTS expires_at timestamptz,
    -- true when the token was minted for one source; kept after the source is
    -- gone so a NULL discovery_source_id can never read as "workspace-wide".
    ADD COLUMN IF NOT EXISTS source_bound boolean NOT NULL DEFAULT false;

-- Existing bound tokens are bound.
UPDATE public.discovery_ingest_tokens
   SET source_bound = true
 WHERE discovery_source_id IS NOT NULL AND NOT source_bound;

ALTER TABLE public.discovery_ingest_tokens
    DROP CONSTRAINT IF EXISTS discovery_ingest_tokens_source_fkey;
ALTER TABLE public.discovery_ingest_tokens
    ADD CONSTRAINT discovery_ingest_tokens_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id)
        ON DELETE SET NULL (discovery_source_id);

-- A bound token is bound to a source while it is active; once its source is
-- gone it must already be revoked.
ALTER TABLE public.discovery_ingest_tokens
    DROP CONSTRAINT IF EXISTS discovery_ingest_tokens_bound_chk;
ALTER TABLE public.discovery_ingest_tokens
    ADD CONSTRAINT discovery_ingest_tokens_bound_chk CHECK (
        NOT source_bound OR discovery_source_id IS NOT NULL OR revoked_at IS NOT NULL);

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    d text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO d FROM pg_constraint
     WHERE conname = 'discovery_ingest_tokens_source_fkey';
    IF d IS NULL OR d NOT LIKE '%SET NULL%' THEN
        RAISE EXCEPTION '044: discovery_ingest_tokens_source_fkey is not ON DELETE SET NULL (%)', d;
    END IF;
END $$;
