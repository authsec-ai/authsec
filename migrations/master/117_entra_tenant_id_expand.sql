-- ============================================================================
-- 117: sync_configurations.entra_tenant_id (AS-097), expand step
--
-- The column that holds the Microsoft Entra *tenant* id was renamed to
-- entra_workspace_id by an over-eager tenant -> workspace rename. It is an
-- Entra directory id, not an AuthSec workspace. Expand -> backfill ->
-- contract:
--   expand (this file): add entra_tenant_id, copy existing values, and keep
--     the two columns equal with a trigger while binaries that still write
--     entra_workspace_id may be running.
--   contract (a later migration, after every running binary uses
--     entra_tenant_id): drop the trigger, its function and entra_workspace_id.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

ALTER TABLE public.sync_configurations
    ADD COLUMN IF NOT EXISTS entra_tenant_id character varying(500);

UPDATE public.sync_configurations
   SET entra_tenant_id = entra_workspace_id
 WHERE entra_tenant_id IS NULL AND entra_workspace_id IS NOT NULL;

CREATE OR REPLACE FUNCTION public.sync_configurations_entra_tenant_sync()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.entra_tenant_id    := COALESCE(NEW.entra_tenant_id, NEW.entra_workspace_id);
        NEW.entra_workspace_id := COALESCE(NEW.entra_workspace_id, NEW.entra_tenant_id);
    ELSIF NEW.entra_tenant_id IS DISTINCT FROM OLD.entra_tenant_id THEN
        NEW.entra_workspace_id := NEW.entra_tenant_id;
    ELSIF NEW.entra_workspace_id IS DISTINCT FROM OLD.entra_workspace_id THEN
        NEW.entra_tenant_id := NEW.entra_workspace_id;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_sync_configurations_entra_tenant ON public.sync_configurations;
CREATE TRIGGER trg_sync_configurations_entra_tenant
    BEFORE INSERT OR UPDATE ON public.sync_configurations
    FOR EACH ROW EXECUTE FUNCTION public.sync_configurations_entra_tenant_sync();
