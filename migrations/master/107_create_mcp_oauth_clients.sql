-- mcp_oauth_clients: global OAuth client registry for the standards-compliant
-- MCP OAuth flow (DCR / CIMD / PreReg). Mirrors Hydra; sync_status tracks
-- convergence. Lives in master DB because OAuth clients are protocol artifacts
-- shared by any tenant whose resource_servers the client may target.
--
-- This is intentionally distinct from tenant_hydra_clients (which is the
-- legacy per-tenant Hydra mirror for the /clientms/tenants/.../clients flow).

CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(512) NOT NULL UNIQUE,
    hydra_client_id VARCHAR(255) NOT NULL UNIQUE,
    client_name VARCHAR(255),
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{authorization_code}',
    response_types TEXT[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'none',
    scope TEXT,
    registration_type VARCHAR(20) NOT NULL DEFAULT 'dcr',
    cimd_url TEXT,
    cimd_cached_at TIMESTAMPTZ,
    pending_redirect_uris TEXT[] DEFAULT '{}',
    redirect_review_pending BOOLEAN DEFAULT false,
    post_logout_redirect_uris TEXT[] DEFAULT '{}',
    supports_refresh_token BOOLEAN DEFAULT false,
    sync_status TEXT NOT NULL DEFAULT 'active',
    sync_last_error TEXT,
    sync_last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_sync_status ON mcp_oauth_clients(sync_status);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_deleted_at ON mcp_oauth_clients(deleted_at);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_registration_type ON mcp_oauth_clients(registration_type);
