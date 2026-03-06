-- Migration: Create clients table for the clients service (merged into authsec)
-- Applied per-tenant: runs on each tenant database when a client is first created.
-- Note: RBAC tables (roles, permissions, role_permissions) are managed by the main authsec schema.

-- Create clients table in tenant database
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL UNIQUE,
    tenant_id TEXT,
    project_id TEXT,
    owner_id TEXT,
    org_id TEXT,
    name TEXT NOT NULL,
    email TEXT,
    status TEXT DEFAULT 'Active',
    tags TEXT,
    active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_method TEXT,
    mfa_default_method TEXT,
    mfa_enrolled_at TIMESTAMP,
    mfa_verified BOOLEAN DEFAULT FALSE,
    hydra_client_id TEXT UNIQUE,
    oidc_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    deleted BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_clients_tenant_id ON clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_clients_project_id ON clients(project_id);
CREATE INDEX IF NOT EXISTS idx_clients_owner_id ON clients(owner_id);
CREATE INDEX IF NOT EXISTS idx_clients_org_id ON clients(org_id);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_hydra_client_id ON clients(hydra_client_id) WHERE hydra_client_id IS NOT NULL AND hydra_client_id != '';
CREATE INDEX IF NOT EXISTS idx_clients_oidc_enabled ON clients(oidc_enabled);
CREATE INDEX IF NOT EXISTS idx_clients_deleted ON clients(deleted);
CREATE INDEX IF NOT EXISTS idx_clients_tenant_org ON clients(tenant_id, org_id);
CREATE INDEX IF NOT EXISTS idx_clients_owner ON clients(owner_id);
CREATE INDEX IF NOT EXISTS idx_clients_tags ON clients(tags);
