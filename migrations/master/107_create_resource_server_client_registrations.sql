-- Migration 107: Create resource_server_client_registrations join table
-- Controls which OAuth clients are registered/allowed for which resource servers.
-- All access paths must check this table before allowing client-RS interaction.

CREATE TABLE IF NOT EXISTS resource_server_client_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id),
    oauth_client_id UUID NOT NULL REFERENCES mcp_oauth_clients(id),
    status VARCHAR(20) NOT NULL DEFAULT 'approved',
    registration_type VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(resource_server_id, oauth_client_id)
);

CREATE INDEX IF NOT EXISTS idx_rscr_rs_id ON resource_server_client_registrations(resource_server_id);
CREATE INDEX IF NOT EXISTS idx_rscr_client_id ON resource_server_client_registrations(oauth_client_id);
