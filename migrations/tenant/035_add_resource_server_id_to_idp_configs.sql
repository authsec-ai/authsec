-- 035_add_resource_server_id_to_idp_configs.sql
--
-- Per-MCP scoping for federated identity provider configs.
--
-- Pre-035 schema:
--   oidc_providers (tenant_id, provider_name)              — one Google/Okta/etc per tenant
--   saml_providers (tenant_id, client_id, provider_name)   — one per (tenant, legacy client_id, name)
--
-- Post-035 schema (additive — existing rows keep working):
--   oidc_providers (tenant_id, [resource_server_id], provider_name)
--   saml_providers (tenant_id, [resource_server_id], client_id, provider_name)
--
-- Lookup pattern:
--   SELECT ... WHERE tenant_id = ? AND provider_name = ?
--     AND (resource_server_id = ? OR resource_server_id IS NULL)
--   ORDER BY resource_server_id NULLS LAST
--   LIMIT 1
--
-- That gives admins a knob: leave NULL for a tenant-wide default (legacy
-- behavior), or set the column to scope a config to a single Application.
-- Per-MCP rows shadow tenant-wide rows for the same provider_name.

ALTER TABLE oidc_providers
  ADD COLUMN IF NOT EXISTS resource_server_id UUID NULL;

ALTER TABLE saml_providers
  ADD COLUMN IF NOT EXISTS resource_server_id UUID NULL;

-- Partial unique indexes so admins can register the same provider_name
-- multiple times (once per Application + once tenant-wide).
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_providers_tenant_rs_name
  ON oidc_providers (tenant_id, resource_server_id, provider_name)
  WHERE resource_server_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_saml_providers_tenant_rs_name
  ON saml_providers (tenant_id, resource_server_id, provider_name)
  WHERE resource_server_id IS NOT NULL;
