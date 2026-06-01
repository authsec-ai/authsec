package platform

import (
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// validateClientActive checks that a delegation policy's client_id references an
// active ai_agent resource server in the given workspace. Phase B: the legacy
// `clients` table was dropped; an "agent" is now a resource_servers row with
// application_type='ai_agent'. The policy's client_id holds that resource_servers.id.
func validateClientActive(clientID, workspaceID string) error {
	masterDB := config.GetDatabase()
	if masterDB == nil {
		return fmt.Errorf("master database not initialized")
	}

	query := `
		SELECT id FROM resource_servers
		WHERE id::text = $1
		AND workspace_id::text = $2
		AND application_type = 'ai_agent'
		AND active = true
		AND deleted_at IS NULL
		LIMIT 1
	`
	var id string
	if err := masterDB.DB.QueryRow(query, clientID, workspaceID).Scan(&id); err != nil {
		return fmt.Errorf("agent %s not found or not active in workspace %s", clientID, workspaceID)
	}
	return nil
}

// isDuplicateKeyError checks if an error is a PostgreSQL unique constraint violation.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "duplicate key") || strings.Contains(errStr, "23505")
}

// delegationContextString normalises a gin context value to a trimmed string.
func delegationContextString(c *gin.Context, key string) string {
	value, exists := c.Get(key)
	if !exists || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case uuid.UUID:
		if v == uuid.Nil {
			return ""
		}
		return v.String()
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// resolveDelegationTenantID extracts the tenant UUID from the gin context.
func resolveDelegationTenantID(c *gin.Context) (*uuid.UUID, error) {
	tenantIDStr := delegationContextString(c, "workspace_id")
	if tenantIDStr == "" {
		return nil, fmt.Errorf("workspace_id not found in authentication token")
	}
	tid, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid workspace_id in token: %w", err)
	}
	return &tid, nil
}
