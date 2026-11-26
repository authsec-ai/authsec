-- ============================================================================
-- 210: the governance:remediate right (SPEC-secops-backend-upgrade.md P3,
-- tier 4; W5).
--
-- Tier 4 is a remediation write to the customer cloud (W8). The right is
-- added to the platform permission catalog and bound to every workspace
-- admin role, as 055 did for governance:author/approve/enforce/emergency.
-- New workspaces get it from the catalog (database/admin_seed_repository.go
-- binds the admin role to every catalog permission). Decision 2: the cloud
-- write itself is gated by the customer remediation template (a workspace
-- without the remediation role only ever produces prepared changes), not by
-- this right.
--
-- Expand only. Idempotent (ON CONFLICT DO NOTHING).
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
  (gen_random_uuid(), NULL, 'governance', 'remediate', 'Apply remediation writes to the customer cloud (tier 4)', 'governance:remediate', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM public.roles r CROSS JOIN public.permissions p
WHERE r.name = 'admin' AND r.workspace_id IS NOT NULL AND p.workspace_id IS NULL
  AND p.resource = 'governance' AND p.action = 'remediate'
ON CONFLICT (role_id, permission_id) DO NOTHING;
