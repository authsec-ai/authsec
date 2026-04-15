-- 120: OAuth Consent Grants - remembered consent per (user x client x RS)
-- Enables consent memory with TTL so users aren't prompted on every auth flow.

CREATE TABLE IF NOT EXISTS oauth_consent_grants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    user_id             UUID NOT NULL,
    client_id           UUID NOT NULL REFERENCES mcp_oauth_clients(id) ON DELETE CASCADE,
    resource_server_id  UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    granted_scopes      TEXT[] NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, client_id, resource_server_id)
);

CREATE INDEX IF NOT EXISTS idx_consent_grants_user_client
    ON oauth_consent_grants (user_id, client_id, resource_server_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_consent_grants_tenant
    ON oauth_consent_grants (tenant_id)
    WHERE revoked_at IS NULL;
