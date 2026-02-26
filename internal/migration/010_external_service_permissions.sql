-- Migration: Add permissions for external-service (Standalone/Backup)
-- Executed per-tenant, assigning permissions to the existing 'admin' role.

BEGIN;

-- ============================================
-- STEP 1: Define Permissions for external-service
-- ============================================
INSERT INTO permissions (id, tenant_id, resource, action, description)
VALUES 
    (gen_random_uuid(), :tenant_id, 'external-service', 'create',      'Create new external services'),
    (gen_random_uuid(), :tenant_id, 'external-service', 'read',        'View external service details'),
    (gen_random_uuid(), :tenant_id, 'external-service', 'update',      'Modify external service details'),
    (gen_random_uuid(), :tenant_id, 'external-service', 'delete',      'Delete external services'),
    (gen_random_uuid(), :tenant_id, 'external-service', 'credentials', 'View external service credentials')
ON CONFLICT (tenant_id, resource, action) DO NOTHING;

-- ============================================
-- STEP 2: Grant permissions to Admin role
-- ============================================
-- Assign all external-service permissions to the 'admin' role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name = 'admin' AND r.tenant_id = :tenant_id
  AND p.resource = 'external-service' AND p.tenant_id = :tenant_id
ON CONFLICT DO NOTHING;

COMMIT;
