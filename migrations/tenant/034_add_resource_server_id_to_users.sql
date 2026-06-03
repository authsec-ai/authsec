-- 034_add_resource_server_id_to_users.sql
--
-- Per-MCP federated user scoping. Pre-MCP, a (tenant_id, client_id, email)
-- tuple uniquely identified a user. With v2 each Application (mcp_server
-- resource_servers row) is a discrete logical scope, so the same Google
-- account logging into two different MCPs in the same tenant should
-- produce two distinct AuthSec users.
--
-- Adds resource_server_id (nullable) to:
--   - users                — federated users get this populated; legacy
--                            custom-login / AD-sync / Entra users keep it NULL
--   - oidc_user_identities — identity link is per-MCP, not per-tenant
--
-- The legacy uniqueness contract (tenant_id, client_id, email) stays valid
-- for legacy users (resource_server_id IS NULL). Federated users get a
-- separate uniqueness contract (tenant_id, resource_server_id, email)
-- enforced by the partial index below.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS resource_server_id UUID NULL;

ALTER TABLE oidc_user_identities
  ADD COLUMN IF NOT EXISTS resource_server_id UUID NULL;

CREATE INDEX IF NOT EXISTS idx_users_tenant_rs_email
  ON users (tenant_id, resource_server_id, LOWER(email))
  WHERE resource_server_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_oidc_identities_tenant_rs_provider_sub
  ON oidc_user_identities (tenant_id, resource_server_id, provider_name, provider_user_id)
  WHERE resource_server_id IS NOT NULL;
