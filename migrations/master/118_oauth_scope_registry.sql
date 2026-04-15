-- Migration 118: OAuth Scope Registry
-- Creates a first-class scope catalog with metadata, hierarchy, and permission mapping.
-- Replaces the flat pq.StringArray on resource_servers.scopes_supported with a proper table.

CREATE TABLE IF NOT EXISTS oauth_scopes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    resource_server_id  UUID REFERENCES resource_servers(id) ON DELETE CASCADE,
    scope_string        TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    description         TEXT,
    icon                TEXT,
    risk_level          TEXT NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    parent_scope_id     UUID REFERENCES oauth_scopes(id) ON DELETE SET NULL,
    is_auto_discovered  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, resource_server_id, scope_string)
);

CREATE INDEX idx_oauth_scopes_tenant ON oauth_scopes(tenant_id);
CREATE INDEX idx_oauth_scopes_rs ON oauth_scopes(resource_server_id);
CREATE INDEX idx_oauth_scopes_parent ON oauth_scopes(parent_scope_id);
CREATE UNIQUE INDEX idx_oauth_scopes_tenant_global_scope
    ON oauth_scopes(tenant_id, scope_string)
    WHERE resource_server_id IS NULL;

-- Scope → Permission mapping: maps an OAuth scope to internal RBAC permissions.
-- When a user has roles granting permissions, we reverse-map to find which scopes they're entitled to.
CREATE TABLE IF NOT EXISTS oauth_scope_permissions (
    scope_id      UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (scope_id, permission_id)
);

CREATE INDEX idx_oauth_scope_perms_permission ON oauth_scope_permissions(permission_id);

-- Best-effort backfill from the legacy API scope model.
-- Global API scopes become tenant-scoped oauth_scopes with no bound resource server.
INSERT INTO oauth_scopes (
    tenant_id,
    resource_server_id,
    scope_string,
    display_name,
    description,
    risk_level,
    is_auto_discovered,
    created_at,
    updated_at
)
SELECT
    a.tenant_id,
    NULL,
    a.name,
    a.name,
    a.description,
    CASE
        WHEN LOWER(a.name) LIKE '%admin%' OR LOWER(a.name) LIKE '%delete%' THEN 'critical'
        WHEN LOWER(a.name) LIKE '%write%' OR LOWER(a.name) LIKE '%create%' OR LOWER(a.name) LIKE '%update%' THEN 'medium'
        WHEN RIGHT(a.name, 2) = ':*' THEN 'high'
        ELSE 'low'
    END,
    FALSE,
    COALESCE(a.created_at, NOW()),
    NOW()
FROM api_scopes a
WHERE a.tenant_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO oauth_scope_permissions (scope_id, permission_id)
SELECT
    os.id,
    asp.permission_id
FROM api_scope_permissions asp
JOIN api_scopes a ON a.id = asp.scope_id
JOIN oauth_scopes os
    ON os.tenant_id = a.tenant_id
   AND os.resource_server_id IS NULL
   AND os.scope_string = a.name
WHERE a.tenant_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- Best-effort backfill from scope_resource_mappings into RS-scoped oauth_scopes.
-- This preserves legacy tenant/resource scope contracts where the resource mapping
-- can be matched to a resource server name.
INSERT INTO oauth_scopes (
    tenant_id,
    resource_server_id,
    scope_string,
    display_name,
    description,
    risk_level,
    is_auto_discovered,
    created_at,
    updated_at
)
SELECT
    srm.tenant_id,
    rs.id,
    srm.scope_name,
    srm.scope_name,
    a.description,
    CASE
        WHEN LOWER(srm.scope_name) LIKE '%admin%' OR LOWER(srm.scope_name) LIKE '%delete%' THEN 'critical'
        WHEN LOWER(srm.scope_name) LIKE '%write%' OR LOWER(srm.scope_name) LIKE '%create%' OR LOWER(srm.scope_name) LIKE '%update%' THEN 'medium'
        WHEN RIGHT(srm.scope_name, 2) = ':*' THEN 'high'
        ELSE 'low'
    END,
    FALSE,
    COALESCE(srm.created_at, NOW()),
    NOW()
FROM scope_resource_mappings srm
JOIN resource_servers rs
    ON rs.tenant_id = srm.tenant_id
   AND LOWER(rs.name) = LOWER(srm.resource_name)
LEFT JOIN api_scopes a
    ON a.tenant_id = srm.tenant_id
   AND a.name = srm.scope_name
ON CONFLICT DO NOTHING;

INSERT INTO oauth_scope_permissions (scope_id, permission_id)
SELECT
    os.id,
    asp.permission_id
FROM scope_resource_mappings srm
JOIN resource_servers rs
    ON rs.tenant_id = srm.tenant_id
   AND LOWER(rs.name) = LOWER(srm.resource_name)
JOIN oauth_scopes os
    ON os.tenant_id = srm.tenant_id
   AND os.resource_server_id = rs.id
   AND os.scope_string = srm.scope_name
JOIN api_scopes a
    ON a.tenant_id = srm.tenant_id
   AND a.name = srm.scope_name
JOIN api_scope_permissions asp
    ON asp.scope_id = a.id
ON CONFLICT DO NOTHING;
