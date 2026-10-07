package services

import (
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
	err := db.Raw(`SELECT count(*) FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id
	                WHERE p.resource IN (?, '*') AND p.action IN (?, '*') AND (p.workspace_id IS NULL OR p.workspace_id = ?)
	                  AND rp.role_id IN (
	                        SELECT role_id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ? AND status = 'active'
	                        UNION
	                        SELECT role_id FROM role_bindings WHERE workspace_id = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > now()))`,
		resource, action, ws, ws, user, ws, user).Scan(&n).Error
	return n > 0, err
}
