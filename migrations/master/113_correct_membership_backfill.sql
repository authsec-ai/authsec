-- Migration: 113_correct_membership_backfill.sql
-- Description: Fix the Phase A backfill: only real operators belong in
--   tenant_memberships; everyone else moves to tenant_end_user_states.
--
--   Migration 112 was too aggressive — it inserted a membership row for
--   every existing user. In reality, only the tenant owner and any user
--   with a tenant-level admin role binding (role name not prefixed `rs-`
--   and not the default `user` role) is an operator. The rest are end
--   users who consented to one of the tenant's Applications.
--
-- Steps:
--   1. Mark primary admins as membership_type='owner'.
--   2. Delete memberships for users who have no tenant-level admin/owner
--      role binding (only `rs-*` per-resource roles or `user` default).
--   3. Backfill tenant_end_user_states for those moved users plus anyone
--      not already covered. first_consent_at uses the earliest OAuth
--      consent grant if present, else the user's created_at.
--
-- Idempotent: re-running this is a no-op on a corrected dataset.
-- Date: 2026-05-15
-- Phase: A

-- 1. Owner labeling
UPDATE tenant_memberships tm
SET membership_type = 'owner', updated_at = NOW()
FROM users u
WHERE tm.user_id = u.id
  AND u.is_primary_admin = TRUE
  AND tm.membership_type <> 'owner';

-- 2. Drop memberships for non-operators
DELETE FROM tenant_memberships tm
WHERE NOT EXISTS (
    SELECT 1
    FROM role_bindings rb
    JOIN roles r ON r.id = rb.role_id
    WHERE rb.user_id = tm.user_id
      AND (rb.tenant_id = tm.tenant_id OR rb.tenant_id IS NULL)
      AND r.name NOT LIKE 'rs-%'
      AND r.name <> 'user'
)
AND NOT EXISTS (
    SELECT 1 FROM users u
    WHERE u.id = tm.user_id AND u.is_primary_admin = TRUE
);

-- 3. Backfill end-user states for everyone not now in tenant_memberships
INSERT INTO tenant_end_user_states (tenant_id, user_id, status, first_consent_at)
SELECT
    u.tenant_id,
    u.id,
    CASE WHEN u.active THEN 'active' ELSE 'suspended' END,
    COALESCE(
        (SELECT MIN(og.created_at) FROM oauth_consent_grants og
         WHERE og.user_id = u.id AND og.tenant_id = u.tenant_id),
        u.created_at,
        NOW()
    )
FROM users u
WHERE u.tenant_id IS NOT NULL
  AND u.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM tenant_memberships tm
      WHERE tm.tenant_id = u.tenant_id AND tm.user_id = u.id
  )
ON CONFLICT (tenant_id, user_id) DO NOTHING;
