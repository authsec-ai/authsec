-- OOCMGR: Tenant database tables for OIDC Configuration Manager
-- These tables are created in each tenant's dedicated database.

-- oauth_oidc_configurations: per-tenant OIDC/OAuth config records
CREATE TABLE IF NOT EXISTS oauth_oidc_configurations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    org_id      VARCHAR(255) NOT NULL,
    tenant_id   VARCHAR(255) NOT NULL,
    config_type VARCHAR(100) NOT NULL,
    config_files JSONB,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMP,
    created_by  VARCHAR(255) NOT NULL DEFAULT '',
    updated_by  VARCHAR(255) NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_oauth_oidc_config_name      ON oauth_oidc_configurations(name);
CREATE INDEX IF NOT EXISTS idx_oauth_oidc_config_org_id    ON oauth_oidc_configurations(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_oidc_config_tenant_id ON oauth_oidc_configurations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_oidc_config_deleted_at ON oauth_oidc_configurations(deleted_at);

-- saml_providers: per-tenant SAML identity provider configurations
CREATE TABLE IF NOT EXISTS saml_providers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL,
    client_id         UUID NOT NULL,
    provider_name     VARCHAR(255) NOT NULL,
    display_name      VARCHAR(255) NOT NULL,
    entity_id         VARCHAR(500) NOT NULL,
    sso_url           VARCHAR(500) NOT NULL,
    slo_url           VARCHAR(500),
    certificate       TEXT NOT NULL,
    metadata_url      VARCHAR(500),
    name_id_format    VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mapping JSONB,
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, client_id, provider_name)
);

CREATE INDEX IF NOT EXISTS idx_saml_providers_tenant_id ON saml_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_providers_client_id ON saml_providers(client_id);
