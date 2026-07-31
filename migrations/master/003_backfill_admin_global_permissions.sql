-- 003_backfill_admin_global_permissions.sql
--
-- Backfills every existing workspace 'admin' role with the global permission
-- catalog (permissions.workspace_id IS NULL).
--
-- Why this is needed: EnsureAdminRoleAndPermissions
-- (database/admin_seed_repository.go) already grants an admin role every global
-- permission via `SELECT id FROM permissions WHERE workspace_id IS NULL`, but it
-- runs only when a workspace is created. Permissions added to the global catalog
-- afterwards therefore reach new workspaces automatically and existing ones never
-- — their admin role keeps the exact permission set that existed on the day the
-- workspace was made.
--
-- 002_agent_discovery.sql hit precisely that gap: it inserted discovery:report,
-- read, claim, quarantine and admin into the global catalog, so every workspace
-- predating it had an admin who could not call a single /authsec/discovery/*
-- endpoint. The authz layer has no name-based bypass for the role called "admin"
-- (see internal/authz/authz.go, "Admin claim bypass removed"), so the missing
-- role_permissions rows are a hard 403, not a soft default.
--
-- This mirrors the application's own query rather than naming discovery
-- explicitly, so it repairs any other catalog drift at the same time and stays
-- correct if the catalog grows again before this runs.
--
-- Idempotent: ON CONFLICT DO NOTHING, and re-running it is a no-op once the
-- rows exist.

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.name = 'admin'
  AND r.workspace_id IS NOT NULL
  AND p.workspace_id IS NULL
ON CONFLICT (role_id, permission_id) DO NOTHING;
