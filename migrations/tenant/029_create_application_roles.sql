-- application_roles: per-Application RBAC roles. A role is a named bundle
-- of scope grants. Users get scopes by being bound to a role via
-- application_role_bindings (Phase 8 part 2).
--
-- Backport-lean equivalent of dev's per-RS role system. Dev integrates
-- with workspace-level roles + a global permission graph; on the backport
-- we keep this strictly scoped to a single Application — no inheritance,
-- no cross-application reuse.

CREATE TABLE IF NOT EXISTS application_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT application_roles_application_name_uq UNIQUE (application_id, name)
);

CREATE INDEX IF NOT EXISTS idx_application_roles_tenant      ON application_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_application_roles_application ON application_roles(application_id);

-- application_role_scope_grants: many-to-many between roles and scopes.
-- One row per (role_id, scope_id). When a role is granted to a user (via
-- application_role_bindings), the user gets every scope_id linked here.
--
-- We reference oauth_scopes.id (Phase 5 table) by FK so deleting a scope
-- automatically cleans up the grant rows. The unique constraint also
-- prevents accidental duplicates.

CREATE TABLE IF NOT EXISTS application_role_scope_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES application_roles(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT application_role_scope_grants_uq UNIQUE (role_id, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_app_role_scope_grants_role  ON application_role_scope_grants(role_id);
CREATE INDEX IF NOT EXISTS idx_app_role_scope_grants_scope ON application_role_scope_grants(scope_id);
