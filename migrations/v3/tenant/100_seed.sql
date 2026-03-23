DO $$
DECLARE
    v_tenant_id uuid;
    v_admin_role_id uuid;
BEGIN
    SELECT COALESCE(tenant_id, id)
    INTO v_tenant_id
    FROM tenants
    ORDER BY created_at NULLS FIRST, id
    LIMIT 1;

    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant seed requires a tenant row before v3 tenant seed runs';
    END IF;

    INSERT INTO roles (id, tenant_id, name, description, is_system, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'admin', 'Tenant administrator', true, NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'user', 'Tenant user', true, NOW(), NOW())
    ON CONFLICT (tenant_id, name) DO UPDATE
    SET
        description = EXCLUDED.description,
        is_system = EXCLUDED.is_system,
        updated_at = NOW();

    SELECT id
    INTO v_admin_role_id
    FROM roles
    WHERE tenant_id = v_tenant_id AND name = 'admin'
    LIMIT 1;

    INSERT INTO permissions (id, tenant_id, resource, action, description, full_permission_string, created_at, updated_at)
    VALUES
        (gen_random_uuid(), v_tenant_id, 'admin', 'access', 'Administrative access gate', 'admin:access', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'admin', 'manage', 'Administrative management gate', 'admin:manage', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'users', 'delete', 'Delete user accounts', 'users:delete', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'tenants', 'delete', 'Delete tenant records', 'tenants:delete', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'external-service', 'create', 'Create external service entries', 'external-service:create', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'external-service', 'read', 'Read external service entries', 'external-service:read', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'external-service', 'update', 'Update external service entries', 'external-service:update', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'external-service', 'delete', 'Delete external service entries', 'external-service:delete', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'external-service', 'credentials', 'Read external service credentials', 'external-service:credentials', NOW(), NOW()),
        (gen_random_uuid(), v_tenant_id, 'clients', 'admin', 'Administrative access to clients', 'clients:admin', NOW(), NOW())
    ON CONFLICT (tenant_id, resource, action) DO UPDATE
    SET
        description = EXCLUDED.description,
        full_permission_string = EXCLUDED.full_permission_string,
        updated_at = NOW();

    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_admin_role_id, p.id
    FROM permissions p
    WHERE p.tenant_id = v_tenant_id
      AND (p.resource, p.action) IN (
          ('admin', 'access'),
          ('admin', 'manage'),
          ('users', 'delete'),
          ('tenants', 'delete'),
          ('external-service', 'create'),
          ('external-service', 'read'),
          ('external-service', 'update'),
          ('external-service', 'delete'),
          ('external-service', 'credentials'),
          ('clients', 'admin')
      )
    ON CONFLICT DO NOTHING;
END $$;
