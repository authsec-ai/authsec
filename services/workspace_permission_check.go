package services

import (
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkspaceUserHoldsPermission reports whether user holds resource:action
// in workspace ws NOW: through the role of their ACTIVE membership or a live
// role binding (the chains PermissionService resolves tokens from),
// including the "*" wildcards on resource or action. It is the database
// counterpart of a token's scopes, for decisions that must still hold after
// the token was issued (Phase 3 §2.8: an approval stays usable only while
// its approver holds governance:approve).
func WorkspaceUserHoldsPermission(db *gorm.DB, ws, user uuid.UUID, resource, action string) (bool, error) {
	var n int64
	err := tenancy.GormRaw(inWorkspace(db.Statement.Context, ws), db, `SELECT count(*) FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id
	                WHERE p.resource IN ($2, '*') AND p.action IN ($3, '*') AND (p.workspace_id IS NULL OR p.workspace_id = $1)
	                  AND rp.role_id IN (
	                        SELECT role_id FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $4 AND status = 'active'
	                        UNION
	                        SELECT role_id FROM role_bindings WHERE workspace_id = $1 AND user_id = $4 AND (expires_at IS NULL OR expires_at > now()))`,
		resource, action, user).Scan(&n).Error
	return n > 0, err
}

// WorkspaceUsersHoldingPermission lists the active members (and live role-binding
// holders) of ws who hold resource:action now, as WorkspaceUserHoldsPermission
// decides it for one. It lives here, outside the IGA files, for the same reason.
func WorkspaceUsersHoldingPermission(db *gorm.DB, ws uuid.UUID, resource, action string) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := tenancy.GormRaw(inWorkspace(db.Statement.Context, ws), db, `SELECT DISTINCT u FROM (
	        SELECT m.user_id AS u FROM workspace_memberships m
	          JOIN role_permissions rp ON rp.role_id = m.role_id
	          JOIN permissions p ON p.id = rp.permission_id
	         WHERE m.workspace_id = $1 AND m.status = 'active'
	           AND p.resource IN ($2, '*') AND p.action IN ($3, '*') AND (p.workspace_id IS NULL OR p.workspace_id = $1)
	        UNION
	        SELECT b.user_id FROM role_bindings b
	          JOIN role_permissions rp ON rp.role_id = b.role_id
	          JOIN permissions p ON p.id = rp.permission_id
	         WHERE b.workspace_id = $1 AND (b.expires_at IS NULL OR b.expires_at > now())
	           AND p.resource IN ($2, '*') AND p.action IN ($3, '*') AND (p.workspace_id IS NULL OR p.workspace_id = $1)) x
	  WHERE u IS NOT NULL`, resource, action).Scan(&ids).Error
	return ids, err
}
