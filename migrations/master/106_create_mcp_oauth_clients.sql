-- Migration 106: Create mcp_oauth_clients table
-- OAuth clients in the MCP plane (Codex, Claude, Cursor, Inspector).
-- Global (no tenant_id) — clients access RS via resource_server_client_registrations join table.

CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(512) UNIQUE NOT NULL,
    hydra_client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255),
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{authorization_code}',
    response_types TEXT[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'none',
    scope TEXT,
    registration_type VARCHAR(20) NOT NULL DEFAULT 'dcr',
    cimd_url TEXT,
    cimd_cached_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_client_id ON mcp_oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_hydra_client_id ON mcp_oauth_clients(hydra_client_id);
