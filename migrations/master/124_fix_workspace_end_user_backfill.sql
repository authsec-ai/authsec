-- Migration: 124_fix_workspace_end_user_backfill.sql
-- Description: Move consumer identities out of workspace_memberships.
--
-- Migration 115 originally inserted every user in a workspace as owner. That
-- confused end users who completed OAuth browser-login tests with workspace
-- operators who can administer AuthSec. Workspace membership is only for
-- operators; consumers belong in tenant_end_user_states.

WITH non_operator_members AS (
    SELECT
        wm.workspace_id,
        wm.user_id,
        wm.created_at AS membership_created_at
    FROM workspace_memberships wm
    JOIN workspaces w ON w.id = wm.workspace_id
    JOIN users u ON u.id = wm.user_id AND u.tenant_id = wm.workspace_id
    WHERE NOT (
        u.id = w.owner_user_id
        OR u.is_primary_admin = TRUE
        OR EXISTS (
            SELECT 1
            FROM role_bindings rb
            JOIN roles bound_role ON bound_role.id = rb.role_id
            WHERE rb.tenant_id = wm.workspace_id
              AND rb.user_id = wm.user_id
              AND rb.scope_type IS NULL
              AND bound_role.name IN ('owner', 'admin', 'member')
        )
    )
),
upsert_end_users AS (
    INSERT INTO tenant_end_user_states (tenant_id, user_id, status, first_consent_at, last_seen_at, created_at, updated_at)
    SELECT
        n.workspace_id,
        n.user_id,
        CASE WHEN u.active THEN 'active' ELSE 'suspended' END,
        COALESCE(
            (SELECT MIN(og.created_at)
             FROM oauth_consent_grants og
             WHERE og.tenant_id = n.workspace_id AND og.user_id = n.user_id),
            u.created_at,
            n.membership_created_at,
            now()
        ),
        u.last_login,
        now(),
        now()
    FROM non_operator_members n
    JOIN users u ON u.id = n.user_id
    ON CONFLICT (tenant_id, user_id) DO UPDATE
    SET status = EXCLUDED.status,
        last_seen_at = COALESCE(EXCLUDED.last_seen_at, tenant_end_user_states.last_seen_at),
        updated_at = now()
    RETURNING tenant_id, user_id
)
DELETE FROM workspace_memberships wm
USING non_operator_members n
WHERE wm.workspace_id = n.workspace_id
  AND wm.user_id = n.user_id;

