-- application_role_bindings: the user ↔ role join. When a user has a
-- binding to a role, they inherit every scope grant that role holds
-- (via application_role_scope_grants). This is the "who has access"
-- side of the per-Application RBAC stack.
--
-- Backport semantics:
--   - One binding per (application, role, user). Re-granting is a no-op.
--   - granted_by is the admin user who created the binding (audit trail).
--   - Bindings live in the tenant DB alongside users.id, so the FK to
--     users is real (vs cross-DB pseudo-FKs we use elsewhere).
--
-- PHASE9-NOTE: dev's effective-access query joins bindings -> roles ->
-- scope_grants -> scopes. We mirror that pattern in UserAccessService.

CREATE TABLE IF NOT EXISTS application_role_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES application_roles(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID,
    CONSTRAINT application_role_bindings_uq UNIQUE (application_id, role_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_app_role_bindings_application ON application_role_bindings(application_id);
CREATE INDEX IF NOT EXISTS idx_app_role_bindings_role        ON application_role_bindings(role_id);
CREATE INDEX IF NOT EXISTS idx_app_role_bindings_user        ON application_role_bindings(user_id);
