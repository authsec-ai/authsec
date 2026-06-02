-- resource_server_client_registrations: join between an Application
-- (resource_servers row, tenant-DB) and an OAuth client
-- (mcp_oauth_clients.client_id, master DB).
--
-- The client_id column stores the public client_id string, not a UUID FK,
-- because the authoritative client row is in master DB and PostgreSQL cannot
-- declare a cross-database FK. Integrity is maintained by application logic
-- and the Hydra reconciler.

CREATE TABLE IF NOT EXISTS resource_server_client_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    client_id VARCHAR(512) NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved',
    registration_type VARCHAR(20) NOT NULL DEFAULT 'dcr',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    CONSTRAINT resource_server_client_registrations_uq UNIQUE (resource_server_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_rscr_client_id ON resource_server_client_registrations(client_id);
CREATE INDEX IF NOT EXISTS idx_rscr_status ON resource_server_client_registrations(status);
