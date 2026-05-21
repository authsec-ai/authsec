package shared

import (
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ResolvePermissionUUIDs collects permission IDs from explicit UUIDs and resource:action strings.
// At least one permission must be provided; duplicates are removed.
func ResolvePermissionUUIDs(db *gorm.DB, tenantID uuid.UUID, ids []string, permStrings []string) ([]uuid.UUID, error) {
	result := make(map[uuid.UUID]struct{})

	if len(ids) > 0 {
		parsed, err := ParseUUIDs(ids, "permission_id")
		if err != nil {
			return nil, err
		}
		for _, id := range parsed {
			result[id] = struct{}{}
		}
	}

	for _, ps := range permStrings {
		sep := strings.LastIndexAny(ps, ":.")
		if sep <= 0 || sep >= len(ps)-1 {
			return nil, fmt.Errorf("invalid permission string: %s (expected resource:action)", ps)
		}
		resource := ps[:sep]
		action := ps[sep+1:]
		var perm models.RBACPermission
		if err := db.Where("tenant_id = ? AND resource = ? AND action = ?", tenantID, resource, action).First(&perm).Error; err != nil {
			return nil, fmt.Errorf("permission not found: %s", ps)
		}
		result[perm.ID] = struct{}{}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("permission_ids or permission_strings required")
	}

	out := make([]uuid.UUID, 0, len(result))
	for id := range result {
		out = append(out, id)
	}
	return out, nil
}

// DerefString safely dereferences *string or returns empty string.
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ResolveTenantIDFromToken extracts tenant ID from context/token and returns a pointer UUID.
func ResolveTenantIDFromToken(c *gin.Context) (*uuid.UUID, error) {
	tenantIDStr, ok := middlewares.GetTenantIDFromToken(c)
	if !ok {
		return nil, fmt.Errorf("Tenant ID not found in context")
	}
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("Invalid tenant ID format")
	}
	return &tenantID, nil
}

// ResolveWorkspaceIDFromToken extracts the active workspace_id from the JWT.
// Falls back to tenant_id during the tenant_id -> workspace_id rollout so
// existing tokens continue to authorize correctly.
func ResolveWorkspaceIDFromToken(c *gin.Context) (uuid.UUID, error) {
	workspaceIDStr, ok := middlewares.GetWorkspaceIDFromToken(c)
	if !ok {
		return uuid.Nil, fmt.Errorf("Workspace ID not found in context")
	}
	workspaceID, err := uuid.Parse(workspaceIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("Invalid workspace ID format")
	}
	return workspaceID, nil
}

// ParseUUIDs converts a slice of strings to UUIDs with field context for errors.
func ParseUUIDs(values []string, field string) ([]uuid.UUID, error) {
	uuids := make([]uuid.UUID, 0, len(values))
	for _, v := range values {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("invalid %s %q: %v", field, v, err)
		}
		uuids = append(uuids, id)
	}
	return uuids, nil
}
