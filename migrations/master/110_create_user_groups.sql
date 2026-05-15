-- Migration: 110_create_user_groups.sql
-- Description: User-to-group membership table. Closes a long-standing schema gap:
--   `internal/sharedmodels/enduser.go` declares a many-to-many between User and
--   Group, but no migration ever created the backing table. This migration adds
--   it and is a prerequisite for group-derived RBAC (migration 111).
-- Date: 2026-05-14
-- Phase: A

CREATE TABLE IF NOT EXISTS user_groups (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,

    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by UUID,

    PRIMARY KEY (tenant_id, user_id, group_id),

    -- Both endpoints must belong to the same tenant
    CONSTRAINT fk_ug_user FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_ug_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    CONSTRAINT fk_ug_added_by FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Group-level lookup (who's in this group?) — primary admin-UI query.
CREATE INDEX IF NOT EXISTS idx_ug_tenant_group ON user_groups(tenant_id, group_id);
-- User-level lookup (what groups is this user in?) — primary scope_resolver query.
CREATE INDEX IF NOT EXISTS idx_ug_tenant_user ON user_groups(tenant_id, user_id);
