-- HMGR: Main database tables for SAML SP certificates and request tracking

CREATE TABLE IF NOT EXISTS saml_sp_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE,
    certificate TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_certificates_tenant_id ON saml_sp_certificates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_sp_certificates_expires_at ON saml_sp_certificates(expires_at);

CREATE TABLE IF NOT EXISTS saml_requests (
    id VARCHAR(255) PRIMARY KEY,
    login_challenge VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    provider_name VARCHAR(255) NOT NULL,
    relay_state TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_requests_login_challenge ON saml_requests(login_challenge);
CREATE INDEX IF NOT EXISTS idx_saml_requests_tenant_id ON saml_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_requests_expires_at ON saml_requests(expires_at);

CREATE TABLE IF NOT EXISTS saml_callback_states (
    id TEXT PRIMARY KEY,
    redirect_to TEXT NOT NULL,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    provider_name VARCHAR(255),
    tenant_id UUID,
    client_id UUID,
    login_challenge TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_callback_states_expires_at ON saml_callback_states(expires_at);
