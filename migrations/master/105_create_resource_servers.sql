-- Migration 105: Create resource_servers table
-- Resource servers represent MCP servers registered with AuthSec (the tool providers).
-- They are OAuth 2.1 Resource Servers, NOT OAuth clients.

CREATE TABLE IF NOT EXISTS resource_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    public_base_url TEXT NOT NULL,
    protected_base_path TEXT NOT NULL DEFAULT '/mcp',
    resource_uri TEXT NOT NULL UNIQUE,
    scopes_supported TEXT[] DEFAULT '{}',
    registration_modes TEXT[] DEFAULT '{dcr,cimd,prereg}',
    introspection_secret TEXT NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_resource_servers_tenant_id ON resource_servers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_servers_resource_uri ON resource_servers(resource_uri);
