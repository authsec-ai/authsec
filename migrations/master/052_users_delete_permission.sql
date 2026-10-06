-- ============================================================================
-- 052: workspace admins hold users:delete
--
-- DELETE /uflow/admin/users/:user_id, /admin/users/delete_all/:user_id and the
-- end-user delete routes require the users:delete permission
-- (middlewares.Require("users", "delete")). It existed only in the system
-- workspace, so no workspace admin had it and every delete answered 403
-- (AS-048).
--
-- users:delete joins the global catalog (workspace_id IS NULL), like
-- connector:*, discovery:*, iga:* and governance:*. New workspaces get it
-- through EnsureAdminRoleAndPermissions, which binds the admin role to every
-- global permission; existing workspaces' admin roles are backfilled here,
-- as 003 does for the rest of the catalog.
--
-- Idempotent. 001_bootstrap.sql carries the same catalog row.
-- ============================================================================

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES (gen_random_uuid(), NULL, 'users', 'delete', 'Delete a user of the workspace', 'users:delete', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.name = 'admin'
  AND r.workspace_id IS NOT NULL
  AND p.workspace_id IS NULL
  AND p.resource = 'users'
  AND p.action = 'delete'
ON CONFLICT (role_id, permission_id) DO NOTHING;
