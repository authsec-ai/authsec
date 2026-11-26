-- ============================================================================
-- 102: trusted issuers belong to a workspace
--
-- trusted_issuers had no owner, yet any workspace admin could create, list,
-- test and revoke rows, and an ID-JAG from any registered issuer could map
-- subjects into any workspace's users (AS-011). An issuer registered by a
-- workspace admin now records that workspace: it is visible and revocable only
-- there, and its ID-JAGs map subjects only into that workspace.
--
-- Rows that exist today keep workspace_id NULL. NULL means platform-owned:
-- current redemption behaviour is unchanged for them, and workspace admins can
-- no longer see, test or revoke them.
--
-- Additive and idempotent: a nullable column and an index.
-- ============================================================================

ALTER TABLE public.trusted_issuers
    ADD COLUMN IF NOT EXISTS workspace_id uuid
        REFERENCES public.workspaces(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_trusted_issuers_workspace
    ON public.trusted_issuers (workspace_id);
