package platform

import (
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// validateClientActive checks that a delegation policy's client_id references an
// active ai_agent resource server in the request's workspace. An agent is a
// resource_servers row with application_type='ai_agent'; the policy's
// client_id holds that resource_servers.id. Another workspace's agent is
// tenancy.ErrNotFound.
func validateClientActive(c *gin.Context, clientID uuid.UUID) error {
	db := config.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}
	var id uuid.UUID
	return tenancy.QueryRow(c, db.DB, `
		SELECT id FROM resource_servers
		WHERE workspace_id = $1 AND id = $2
		  AND application_type = 'ai_agent' AND active = true`,
		[]interface{}{clientID}, &id)
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

// resolveDelegationWorkspaceID returns the request's workspace from the
// tenancy context set by the auth middleware.
func resolveDelegationWorkspaceID(c *gin.Context) (*uuid.UUID, error) {
	ws, err := tenancy.Workspace(c)
	if err != nil {
		return nil, fmt.Errorf("workspace_id not found in authentication token")
	}
	return &ws, nil
}
