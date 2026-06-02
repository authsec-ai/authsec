-- auth_request_context: PKCE state + resource + redirect_uri + tenant binding
-- captured at /oauth/v2/authorize, consumed at /oauth/v2/token. consumed=true
-- after token exchange to prevent replay. Lives in tenant DB because the row
-- is already keyed by tenant scope.

CREATE TABLE IF NOT EXISTS auth_request_context (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    context_id TEXT NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(512) NOT NULL,
    resource_uri TEXT,
    resource_server_id UUID,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    state TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(20),
    nonce TEXT,
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_request_context_expires ON auth_request_context(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_request_context_client ON auth_request_context(client_id);
