-- Migration 103: Add permissions for User Flow Service
-- Fixed to use production schema (no resources table, permissions uses tenant_id/resource/action)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Ensure system tenant exists
    INSERT INTO tenants (id, tenant_id, email, tenant_domain, name, created_at)
    VALUES (sys_tenant, sys_tenant, 'system@authsec.local', 'system.authsec.dev', 'System', NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Ensure users:delete permission exists
    INSERT INTO permissions (id, tenant_id, resource, action, description, full_permission_string, created_at)
    VALUES (gen_random_uuid(), sys_tenant, 'users', 'delete', 'Delete a user', 'users:delete', NOW())
    ON CONFLICT ON CONSTRAINT permissions_tenant_resource_action_key DO NOTHING;

    -- Ensure users:read permission exists
    INSERT INTO permissions (id, tenant_id, resource, action, description, full_permission_string, created_at)
    VALUES (gen_random_uuid(), sys_tenant, 'users', 'read', 'Read user information', 'users:read', NOW())
    ON CONFLICT ON CONSTRAINT permissions_tenant_resource_action_key DO NOTHING;

    -- Ensure users:write permission exists
    INSERT INTO permissions (id, tenant_id, resource, action, description, full_permission_string, created_at)
    VALUES (gen_random_uuid(), sys_tenant, 'users', 'write', 'Create and update users', 'users:write', NOW())
    ON CONFLICT ON CONSTRAINT permissions_tenant_resource_action_key DO NOTHING;

    -- Assign permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id
    FROM roles r, permissions p
    WHERE r.name = 'admin' AND r.tenant_id = sys_tenant
      AND p.tenant_id = sys_tenant
      AND p.resource = 'users'
      AND p.action IN ('delete', 'read', 'write')
    ON CONFLICT DO NOTHING;
END $$;
