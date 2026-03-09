-- OOCMGR: Main database tables for OIDC Configuration Manager
-- These tables live in the main (shared) database.

-- tenant_hydra_clients: maps tenants to their Hydra OAuth2 clients
CREATE TABLE IF NOT EXISTS tenant_hydra_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              VARCHAR(255) NOT NULL DEFAULT '',
    tenant_id           VARCHAR(255) NOT NULL,
    tenant_name         VARCHAR(255) NOT NULL DEFAULT '',
    hydra_client_id     VARCHAR(255) NOT NULL UNIQUE,
    hydra_client_secret VARCHAR(255) NOT NULL DEFAULT '',
    client_name         VARCHAR(255) NOT NULL DEFAULT '',
    redirect_uris       JSONB NOT NULL DEFAULT '[]',
    scopes              TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    client_type         VARCHAR(50) NOT NULL,
    provider_name       VARCHAR(255) NOT NULL DEFAULT '',
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by          VARCHAR(255) NOT NULL DEFAULT 'system',
    updated_by          VARCHAR(255) NOT NULL DEFAULT 'system',
    deleted_at          TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tenant_hydra_clients_tenant_id    ON tenant_hydra_clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_hydra_clients_org_id       ON tenant_hydra_clients(org_id);
CREATE INDEX IF NOT EXISTS idx_tenant_hydra_clients_client_type  ON tenant_hydra_clients(client_type);
CREATE INDEX IF NOT EXISTS idx_tenant_hydra_clients_provider_name ON tenant_hydra_clients(provider_name);
CREATE INDEX IF NOT EXISTS idx_tenant_hydra_clients_deleted_at   ON tenant_hydra_clients(deleted_at);
