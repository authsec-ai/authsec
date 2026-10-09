-- 005_backfill_iga_global_permissions.sql
--
-- Backfills every existing workspace 'admin' role with the global permission
-- catalog, after 004_agentic_iga.sql added iga:read / iga:admin / iga:review.
--
-- Why this is needed, again: EnsureAdminRoleAndPermissions
-- (database/admin_seed_repository.go) grants an admin role every global
-- permission via `SELECT id FROM permissions WHERE workspace_id IS NULL`, but it
-- runs only when a workspace is created. Anything added to the global catalog
-- afterwards reaches new workspaces automatically and existing ones never.
--
-- This is exactly the gap 003 was written to close for discovery:*. 004 walked
-- straight back into it: it inserts three iga:* permissions into the same global
-- catalog and grants them to nobody, so on any workspace that predates it every
-- authenticated /api/iga/v1 route returns a hard 403. The migration runner skips
-- already-executed files, so 003 does not re-run and cannot cover 004.
--
-- The lesson worth writing down: adding a global permission is only half a
-- change. The other half is a backfill, and it belongs in the SAME migration
-- that adds the permission. This file exists because that was missed.
--
-- Like 003, this mirrors the application's own query rather than naming iga:*
-- explicitly, so it also repairs any other catalog drift and stays correct if
-- the catalog grows again before it runs.
--
-- Idempotent: ON CONFLICT DO NOTHING, and re-running it is a no-op.

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.name = 'admin'
  AND r.workspace_id IS NOT NULL
  AND p.workspace_id IS NULL
ON CONFLICT (role_id, permission_id) DO NOTHING;
