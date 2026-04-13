-- Migration 108: Create auth_request_contexts bridge table
-- Short-lived context stored between /oauth/authorize and hmgr login/consent.
-- Keyed by OAuth state parameter. Bound to login_challenge in hmgr.
-- TTL ~10 minutes, one-time consumption, periodic cleanup required.

CREATE TABLE IF NOT EXISTS auth_request_contexts (
    state VARCHAR(255) PRIMARY KEY,
    hydra_client_id VARCHAR(255) NOT NULL,
    resource_server_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    resource_uri TEXT NOT NULL,
    redirect_uri TEXT,
    requested_scopes TEXT,
    login_challenge VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arc_hydra_client_id ON auth_request_contexts(hydra_client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_arc_login_challenge ON auth_request_contexts(login_challenge) WHERE login_challenge IS NOT NULL;
