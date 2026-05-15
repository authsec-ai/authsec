-- Migration: 108_create_tenant_memberships.sql
-- Description: Operator-side tenant membership table.
--   Models the relationship between a user and a tenant for users who hold
--   operational roles inside the tenant (Owner, Admin, Member, Contractor,
--   Service Operator, Readonly Auditor).
--   END USERS (consumers of a tenant's public Applications) are NOT modeled
--   here -- they live in `tenant_end_user_states` (migration 109).
-- Date: 2026-05-14
-- Phase: A

CREATE TABLE IF NOT EXISTS tenant_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,

    -- Lifecycle metadata
    status TEXT NOT NULL DEFAULT 'active',           -- active | invited | suspended | left
    membership_type TEXT NOT NULL DEFAULT 'member',  -- owner | admin | member | contractor | service_operator | readonly_auditor
    source TEXT NOT NULL DEFAULT 'manual',           -- signup | invite | scim | oidc_jit | saml_jit | api | migration

    -- Audit trail
    external_id TEXT,                                -- e.g. SCIM externalId
    invited_by UUID,
    joined_at TIMESTAMPTZ,
    suspended_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Composite FK enforces tenant isolation: user_id must belong to the same tenant
    CONSTRAINT fk_tm_user FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_tm_invited_by FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL,

    -- Status / membership_type / source must be one of the allowed values
    CONSTRAINT chk_tm_status CHECK (status IN ('active','invited','suspended','left')),
    CONSTRAINT chk_tm_type CHECK (membership_type IN ('owner','admin','member','contractor','service_operator','readonly_auditor')),
    CONSTRAINT chk_tm_source CHECK (source IN ('signup','invite','scim','oidc_jit','saml_jit','api','migration')),

    -- One row per (tenant, user)
    UNIQUE (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_tm_tenant_status ON tenant_memberships(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_tm_user ON tenant_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_tm_tenant_type ON tenant_memberships(tenant_id, membership_type);
CREATE INDEX IF NOT EXISTS idx_tm_invited_by ON tenant_memberships(invited_by) WHERE invited_by IS NOT NULL;
