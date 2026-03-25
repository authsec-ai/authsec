-- Migration: 007_create_delegation_tables.sql
-- Description: Creates delegation_policies and delegation_tokens tables
--              for AI agent trust delegation governance.
-- Source: authsec-migration repo (migration 004) — needed for existing deployments
--         where base schema (000) was applied before delegation tables existed.

-- delegation_policies: governs what permissions can be delegated per role/agent_type
CREATE TABLE IF NOT EXISTS delegation_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    role_name TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    allowed_permissions JSONB DEFAULT '[]'::jsonb,
    max_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_deleg_policy_tenant_role_agent UNIQUE (tenant_id, role_name, agent_type)
);

CREATE INDEX IF NOT EXISTS idx_deleg_policy_tenant_id ON delegation_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_deleg_policy_lookup ON delegation_policies(tenant_id, role_name, agent_type, enabled);

-- delegation_tokens: SDK/AI agents pull their delegated JWT-SVID tokens and permissions
CREATE TABLE IF NOT EXISTS delegation_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    client_id       UUID NOT NULL,
    policy_id       UUID REFERENCES delegation_policies(id) ON DELETE SET NULL,
    token           TEXT NOT NULL,
    spiffe_id       TEXT NOT NULL,
    permissions     JSONB NOT NULL DEFAULT '[]'::jsonb,
    audience        JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at      TIMESTAMPTZ NOT NULL,
    delegated_by    UUID NOT NULL,
    ttl_seconds     INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_delegation_token_client UNIQUE (tenant_id, client_id),
    CONSTRAINT chk_deleg_token_status CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_deleg_token_lookup ON delegation_tokens(tenant_id, client_id, status);
CREATE INDEX IF NOT EXISTS idx_deleg_token_expires ON delegation_tokens(expires_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_deleg_token_policy ON delegation_tokens(policy_id);
