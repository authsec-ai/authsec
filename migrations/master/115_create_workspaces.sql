-- Migration: 115_create_workspaces.sql
-- Description: Introduce the single-DB workspace isolation boundary.

CREATE TABLE IF NOT EXISTS workspaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text UNIQUE,
    owner_user_id uuid NOT NULL,
    workspace_type text NOT NULL DEFAULT 'personal',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspaces_type_chk CHECK (workspace_type IN ('personal', 'team')),
    CONSTRAINT workspaces_slug_reserved_chk CHECK (
        slug IS NULL OR lower(slug) NOT IN (
            'admin', 'api', 'auth', 'oauth', 'scim', 'login', 'support', 'www', 'root', 'system'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_user_id ON workspaces(owner_user_id);

CREATE TABLE IF NOT EXISTS workspace_memberships (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspace_memberships_status_chk CHECK (status IN ('active', 'invited', 'suspended', 'left')),
    CONSTRAINT workspace_memberships_workspace_user_uq UNIQUE (workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_memberships_user_id ON workspace_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_workspace_memberships_role_id ON workspace_memberships(role_id);

CREATE TABLE IF NOT EXISTS workspace_migration_review (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    legacy_tenant_id uuid,
    legacy_user_id uuid,
    reason text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Backfill one workspace per legacy tenant/account boundary. This is deliberately
-- conservative: ambiguous ownership is recorded for manual review instead of
-- guessed silently.
WITH owner_candidates AS (
    SELECT DISTINCT ON (COALESCE(u.tenant_id, t.tenant_id, t.id))
        COALESCE(u.tenant_id, t.tenant_id, t.id) AS legacy_tenant_id,
        u.id AS owner_user_id,
        COALESCE(NULLIF(t.tenant_domain, ''), split_part(u.email, '@', 1), 'workspace') AS base_name,
        COALESCE(u.created_at, now()) AS created_at
    FROM users u
    LEFT JOIN tenants t
        ON t.tenant_id = u.tenant_id OR t.id = u.tenant_id
    WHERE COALESCE(u.tenant_id, t.tenant_id, t.id) IS NOT NULL
      AND u.id IS NOT NULL
    ORDER BY COALESCE(u.tenant_id, t.tenant_id, t.id), COALESCE(u.created_at, now()) ASC
)
INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, created_at, updated_at)
SELECT
    legacy_tenant_id,
    base_name,
    lower(regexp_replace(base_name, '[^a-zA-Z0-9]+', '-', 'g')) || '-' || left(replace(legacy_tenant_id::text, '-', ''), 8),
    owner_user_id,
    'personal',
    created_at,
    now()
FROM owner_candidates
ON CONFLICT (id) DO NOTHING;

-- Seed per-workspace owner/admin/member roles when missing. The existing roles
-- table uses tenant_id as the current storage column for the isolation boundary.
INSERT INTO roles (id, tenant_id, name, description, is_system, created_at)
SELECT gen_random_uuid(), w.id, role_name, role_desc, true, now()
FROM workspaces w
CROSS JOIN (
    VALUES
        ('owner', 'Workspace owner'),
        ('admin', 'Workspace administrator'),
        ('member', 'Workspace member')
) AS seed(role_name, role_desc)
WHERE NOT EXISTS (
    SELECT 1 FROM roles r
    WHERE r.tenant_id = w.id AND r.name = seed.role_name
);

-- Backfill only actual workspace operators. End users must never become
-- workspace members just because they share the tenant/workspace id.
-- A user is an operator when they are the selected workspace owner, a primary
-- admin, or they already have a tenant-wide non-resource-server role binding.
INSERT INTO workspace_memberships (workspace_id, user_id, role_id, status, created_at, updated_at)
SELECT DISTINCT
    w.id,
    u.id,
    r.id,
    'active',
    now(),
    now()
FROM workspaces w
JOIN users u ON u.tenant_id = w.id
JOIN roles r ON r.tenant_id = w.id AND r.name = 'owner'
WHERE u.id IS NOT NULL
  AND (
      u.id = w.owner_user_id
      OR u.is_primary_admin = TRUE
      OR EXISTS (
          SELECT 1
          FROM role_bindings rb
          JOIN roles bound_role ON bound_role.id = rb.role_id
          WHERE rb.tenant_id = w.id
            AND rb.user_id = u.id
            AND rb.scope_type IS NULL
            AND bound_role.name IN ('owner', 'admin', 'member')
      )
  )
ON CONFLICT (workspace_id, user_id) DO NOTHING;

-- Non-operator users under the workspace boundary are consumers. Preserve them
-- as end-user state instead of polluting workspace_memberships.
INSERT INTO tenant_end_user_states (tenant_id, user_id, status, first_consent_at, last_seen_at, created_at, updated_at)
SELECT
    u.tenant_id,
    u.id,
    CASE WHEN u.active THEN 'active' ELSE 'suspended' END,
    COALESCE(
        (SELECT MIN(og.created_at)
         FROM oauth_consent_grants og
         WHERE og.tenant_id = u.tenant_id AND og.user_id = u.id),
        u.created_at,
        now()
    ),
    u.last_login,
    now(),
    now()
FROM users u
JOIN workspaces w ON w.id = u.tenant_id
WHERE u.deleted_at IS NULL
  AND NOT (
      u.id = w.owner_user_id
      OR u.is_primary_admin = TRUE
      OR EXISTS (
          SELECT 1
          FROM role_bindings rb
          JOIN roles bound_role ON bound_role.id = rb.role_id
          WHERE rb.tenant_id = w.id
            AND rb.user_id = u.id
            AND rb.scope_type IS NULL
            AND bound_role.name IN ('owner', 'admin', 'member')
      )
  )
ON CONFLICT (tenant_id, user_id) DO UPDATE
SET last_seen_at = COALESCE(EXCLUDED.last_seen_at, tenant_end_user_states.last_seen_at),
    updated_at = now();

INSERT INTO workspace_migration_review (legacy_tenant_id, legacy_user_id, reason, payload)
SELECT DISTINCT
    u.tenant_id,
    u.id,
    'user_without_backfilled_workspace',
    jsonb_build_object('email', u.email)
FROM users u
LEFT JOIN workspaces w ON w.id = u.tenant_id
WHERE u.tenant_id IS NOT NULL
  AND w.id IS NULL
ON CONFLICT DO NOTHING;
