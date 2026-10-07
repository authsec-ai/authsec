-- 055_iga_gov_settings_permissions.sql
--
-- Phase 3 workspace settings, and the four new governance:* permissions bound
-- to every workspace admin role (sections 2.10, 4.3).
--
-- This file's insert into permissions and role_permissions is the only change
-- 047-056 make to an existing table; it is idempotent (ON CONFLICT DO
-- NOTHING), as 003 / 004 / 005 are.
--
-- New tables: iga_gov_settings.
--
-- Expand only: no existing table is altered. Idempotent: safe to run again
-- (IF NOT EXISTS, guarded DO blocks, DROP TRIGGER IF EXISTS). The DDL below
-- is SPEC-iga-phase3-policy.md section 6.2, heading
-- 055_iga_gov_settings_permissions.sql, verbatim; section 6.3 lists the
-- probes that prove it (tests/igagovschema). 001_bootstrap.sql carries the
-- same objects.

CREATE TABLE IF NOT EXISTS iga_gov_settings (
  workspace_id             uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  enforcement_mode         text NOT NULL DEFAULT 'findings_only' CHECK (enforcement_mode IN ('findings_only','enforce')),
  default_window_days      int NOT NULL DEFAULT 90 CHECK (default_window_days BETWEEN 30 AND 400),
  default_observation_days int NOT NULL DEFAULT 7  CHECK (default_observation_days BETWEEN 1 AND 90),
  owner_review_days        int NOT NULL DEFAULT 3  CHECK (owner_review_days BETWEEN 1 AND 30),
  approval_valid_days      int NOT NULL DEFAULT 7  CHECK (approval_valid_days BETWEEN 1 AND 30),
  canary_hours             int NOT NULL DEFAULT 48 CHECK (canary_hours BETWEEN 1 AND 336),
  iac_apply_hours          int NOT NULL DEFAULT 24 CHECK (iac_apply_hours BETWEEN 1 AND 336),
  evidence_retention_revs  int NOT NULL DEFAULT 30 CHECK (evidence_retention_revs BETWEEN 5 AND 365),
  updated_by               uuid REFERENCES users(id),
  updated_at               timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
  (gen_random_uuid(), NULL, 'governance', 'author',    'Create policies, versions and proposals',                 'governance:author',    NOW()),
  (gen_random_uuid(), NULL, 'governance', 'approve',   'Approve or reject policy versions',                       'governance:approve',   NOW()),
  (gen_random_uuid(), NULL, 'governance', 'enforce',   'Enable enforcement; start, pause, undo deployments',      'governance:enforce',   NOW()),
  (gen_random_uuid(), NULL, 'governance', 'emergency', 'Break-glass undo or control removal without new approval', 'governance:emergency', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM public.roles r CROSS JOIN public.permissions p
WHERE r.name = 'admin' AND r.workspace_id IS NOT NULL AND p.workspace_id IS NULL
  AND p.resource = 'governance' AND p.action IN ('author','approve','enforce','emergency')
ON CONFLICT (role_id, permission_id) DO NOTHING;
