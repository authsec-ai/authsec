-- HMGR: Tenant database table for SAML Identity Provider configurations

CREATE TABLE IF NOT EXISTS saml_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    provider_name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    entity_id VARCHAR(500) NOT NULL,
    sso_url VARCHAR(500) NOT NULL,
    slo_url VARCHAR(500),
    certificate TEXT NOT NULL,
    metadata_url VARCHAR(500),
    name_id_format VARCHAR(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mapping JSONB DEFAULT '{"email":"email","first_name":"givenName","last_name":"surname","name":"displayName"}',
    is_active BOOLEAN DEFAULT true,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_saml_provider_unique UNIQUE (tenant_id, client_id, provider_name)
);

CREATE INDEX IF NOT EXISTS idx_saml_providers_tenant_id ON saml_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_providers_client_id ON saml_providers(client_id);
CREATE INDEX IF NOT EXISTS idx_saml_providers_is_active ON saml_providers(is_active);
