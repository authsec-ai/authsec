-- 052_backfill_admin_global_permissions.sql
--
-- 038 added runtime_policy:* and itdr:triage / itdr:respond to the global
-- catalog and granted them to nobody. 003 and 005 already ran, so they do
-- not cover permissions added later. EnsureAdminRoleAndPermissions grants
-- the catalog only when a workspace is created, and an admin role has no
-- name-based bypass. Existing admins therefore get a hard 403 on
-- GET /api/iga/v2/runtime-policies.
--
-- The ITDR routes require itdr:read, itdr:write, and itdr:approve. Those
-- actions were never seeded. Insert them, then grant every global
-- permission to every existing workspace admin role.
--
-- Idempotent: ON CONFLICT DO NOTHING.

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'itdr', 'read',    'Read identity threat findings and detection rules', 'itdr:read',    NOW()),
    (gen_random_uuid(), NULL, 'itdr', 'write',   'Create and update identity threat findings',        'itdr:write',   NOW()),
    (gen_random_uuid(), NULL, 'itdr', 'approve', 'Approve an identity threat response plan',          'itdr:approve', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.name = 'admin'
  AND r.workspace_id IS NOT NULL
  AND p.workspace_id IS NULL
ON CONFLICT (role_id, permission_id) DO NOTHING;
