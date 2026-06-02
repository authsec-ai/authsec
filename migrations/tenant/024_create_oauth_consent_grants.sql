-- oauth_consent_grants: durable record of which user granted which scopes to
-- which Application. Used by self-service consent management and to skip the
-- consent screen for already-granted scope sets on subsequent authorizations.

CREATE TABLE IF NOT EXISTS oauth_consent_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    client_id VARCHAR(512) NOT NULL,
    resource_server_id UUID REFERENCES resource_servers(id) ON DELETE CASCADE,
    granted_scopes TEXT[] NOT NULL DEFAULT '{}',
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_consent_grants_uq UNIQUE (user_id, client_id, resource_server_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_consent_grants_tenant ON oauth_consent_grants(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consent_grants_user ON oauth_consent_grants(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consent_grants_revoked ON oauth_consent_grants(revoked);
