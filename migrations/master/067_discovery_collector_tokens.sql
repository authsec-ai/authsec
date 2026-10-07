-- ============================================================================
-- 067: discovery_collector_tokens
--
-- Per-workspace collector credentials for the discovery ingress
-- (/authsec/discovery/sightings, agent-registration, lifecycle,
-- rbac-snapshot, resync-manifest). An admin mints one; the collector sends it
-- as its bearer token (controlPlane.sourceToken) and the workspace is taken
-- from the credential, never from the request body (AS-014).
--
-- Only a SHA-256 hash of the token is stored (it is 32 random bytes, not a
-- password). Workspace-owned: RLS through tenancy_enable_rls (054).
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.discovery_collector_tokens (
    id           uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    name         text NOT NULL DEFAULT '',
    token_hash   text NOT NULL,
    token_prefix text NOT NULL DEFAULT '',
    created_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_collector_tokens_hash
    ON public.discovery_collector_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_discovery_collector_tokens_workspace
    ON public.discovery_collector_tokens (workspace_id);

SELECT public.tenancy_enable_rls('public.discovery_collector_tokens');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authsec_tenant') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.discovery_collector_tokens TO authsec_tenant;
    END IF;
END $$;
