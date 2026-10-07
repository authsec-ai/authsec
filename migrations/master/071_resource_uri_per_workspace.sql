-- ============================================================================
-- 071: resource_servers.resource_uri unique per workspace, not globally (AS-060)
--
-- resource_servers_workspace_resource_uri_uq (workspace_id, resource_uri)
-- already exists. The global unique index is dropped: a workspace that owns a
-- URI's host (a verified workspace_domains entry for the host or a parent
-- domain) may now register a URI another workspace registered first, and the
-- pre-workspace lookup resolves the URI to the owner's resource server
-- (services/resource_server_service.go GetByResourceURI). The application
-- refuses the same URI from a workspace that does not own its host, so an
-- unowned URI stays single-holder. The plain index on resource_uri stays for
-- the lookup.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DROP INDEX IF EXISTS public.idx_resource_servers_resource_uri_active;
CREATE INDEX IF NOT EXISTS idx_resource_servers_resource_uri ON public.resource_servers (resource_uri);
