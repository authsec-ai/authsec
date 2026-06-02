-- resource_servers: the tenant's Application registry. An MCP server, an AI
-- agent, a Clawbot, or an API service is a row here. OAuth clients (in master
-- DB mcp_oauth_clients) bind to a resource_server via
-- resource_server_client_registrations.
--
-- Ported from authsec-dev's workspace-scoped resource_servers table, rebound
-- to tenant_id (string) for this branch's tenant-per-database isolation.

CREATE TABLE IF NOT EXISTS resource_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_type TEXT NOT NULL DEFAULT 'mcp_server',
    legacy_client_id UUID,
    name VARCHAR(255) NOT NULL,
    public_base_url TEXT NOT NULL,
    protected_base_path TEXT NOT NULL DEFAULT '/mcp',
    resource_uri TEXT NOT NULL UNIQUE,
    scopes_supported TEXT[] DEFAULT '{}',
    registration_modes TEXT[] DEFAULT '{dcr,cimd,prereg}',
    introspection_secret TEXT DEFAULT '',
    introspection_secret_hash TEXT,
    active BOOLEAN DEFAULT true,
    status TEXT NOT NULL DEFAULT 'pending_scan',
    state TEXT NOT NULL DEFAULT 'pending_scan',
    setup_completed_at TIMESTAMPTZ,
    setup_completed_by UUID,
    scan_generation INTEGER NOT NULL DEFAULT 0,
    last_successful_generation INTEGER NOT NULL DEFAULT 0,
    scan_in_progress BOOLEAN NOT NULL DEFAULT false,
    last_scan_status TEXT,
    last_scan_error TEXT,
    last_scan_started_at TIMESTAMPTZ,
    last_scan_completed_at TIMESTAMPTZ,
    last_validated_at TIMESTAMPTZ,
    last_validation_status TEXT,
    last_validation_error TEXT,
    spiffe_id TEXT,
    agent_type TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_resource_servers_tenant_id ON resource_servers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_servers_application_type ON resource_servers(application_type);
CREATE INDEX IF NOT EXISTS idx_resource_servers_active ON resource_servers(active);
CREATE INDEX IF NOT EXISTS idx_resource_servers_deleted_at ON resource_servers(deleted_at);
