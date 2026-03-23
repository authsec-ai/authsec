DO $$
DECLARE
    system_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    INSERT INTO tenants (id, tenant_id, tenant_db, email, tenant_domain, name, status, migration_status, created_at, updated_at)
    VALUES (
        system_tenant,
        system_tenant,
        'authsec',
        'system@authsec.local',
        'system.authsec.dev',
        'System',
        'active',
        'completed',
        NOW(),
        NOW()
    )
    ON CONFLICT (id) DO UPDATE
    SET
        email = EXCLUDED.email,
        tenant_domain = EXCLUDED.tenant_domain,
        name = EXCLUDED.name,
        status = EXCLUDED.status,
        migration_status = EXCLUDED.migration_status,
        updated_at = NOW();

    INSERT INTO roles (id, tenant_id, name, description, is_system, created_at, updated_at)
    VALUES
        (gen_random_uuid(), system_tenant, 'admin', 'System administrator', true, NOW(), NOW()),
        (gen_random_uuid(), system_tenant, 'user', 'System user', true, NOW(), NOW())
    ON CONFLICT (tenant_id, name) DO UPDATE
    SET
        description = EXCLUDED.description,
        is_system = EXCLUDED.is_system,
        updated_at = NOW();
END $$;
