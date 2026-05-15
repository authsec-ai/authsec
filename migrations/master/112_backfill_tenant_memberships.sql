-- Migration: 112_backfill_tenant_memberships.sql
-- Description: Backfill tenant_memberships from existing users.
--
--   Strategy: every existing user becomes a member of their tenant, with
--   status='active', membership_type='member', source='migration'. The next
--   migrations / Phase D will distinguish operators from end users; until
--   then, "everyone is a member" preserves all current access without
--   breaking suspended-membership precheck (added in scope_resolver Phase A).
--
--   Idempotent: ON CONFLICT (tenant_id, user_id) DO NOTHING.
-- Date: 2026-05-14
-- Phase: A

INSERT INTO tenant_memberships (tenant_id, user_id, status, membership_type, source, joined_at)
SELECT
    u.tenant_id,
    u.id,
    CASE WHEN u.active THEN 'active' ELSE 'suspended' END AS status,
    'member' AS membership_type,
    'migration' AS source,
    COALESCE(u.created_at, NOW()) AS joined_at
FROM users u
WHERE u.tenant_id IS NOT NULL
  AND u.deleted_at IS NULL
ON CONFLICT (tenant_id, user_id) DO NOTHING;
