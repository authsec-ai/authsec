-- Migration: 109_create_tenant_end_user_states.sql
-- Description: Per-(tenant, user) state for END USERS (consumers).
--   An end user is anyone who has consented to one of a tenant's published
--   Applications (MCP server, AI agent, web app, etc.). End users are NOT
--   members of the tenant -- they have a global identity and a stateful
--   relationship per tenant captured here.
--
--   Created lazily on first consent. Tenant admins use this table to:
--     - suspend an abusive end user (status = suspended)
--     - assign a plan tier (Free / Pro / custom)
--     - apply a per-user rate-limit override
--     - see first/last activity for the end user against this tenant
--
--   In Phase A `user_id` references the existing per-tenant `users.id`.
--   Phase D will migrate this column to point at the new global `identities.id`.
-- Date: 2026-05-14
-- Phase: A

CREATE TABLE IF NOT EXISTS tenant_end_user_states (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,

    -- Lifecycle
    status TEXT NOT NULL DEFAULT 'active',          -- active | suspended
    plan_tier TEXT,                                  -- null | free | pro | custom (free-form, validated by app)
    rate_limit_override JSONB,                       -- optional per-user overrides; null means use plan defaults

    -- Activity stamps
    first_consent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,

    -- Bookkeeping
    suspended_at TIMESTAMPTZ,
    suspended_by UUID,
    suspended_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, user_id),

    CONSTRAINT fk_teus_user FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_teus_suspended_by FOREIGN KEY (suspended_by) REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT chk_teus_status CHECK (status IN ('active','suspended'))
);

CREATE INDEX IF NOT EXISTS idx_teus_tenant_status ON tenant_end_user_states(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_teus_tenant_plan ON tenant_end_user_states(tenant_id, plan_tier) WHERE plan_tier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_teus_last_seen ON tenant_end_user_states(tenant_id, last_seen_at DESC);
