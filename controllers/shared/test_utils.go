package shared

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// setTokenClaimsInContext sets JWT claims in the Gin context for testing
// This mimics what the auth middleware does after validating a token
// It sets both the "claims" and "workspace_id" keys as the middleware does
func setTokenClaimsInContext(c *gin.Context, workspaceID string, userID string) {
	claims := jwt.MapClaims{
		"workspace_id": workspaceID,
		"sub":       userID,
	}
	c.Set("claims", claims)
	// Also set tenant_id directly as the middleware does
	c.Set("workspace_id", workspaceID)
}

// setTokenClaimsWithProjectInContext sets JWT claims including project_id for testing
func setTokenClaimsWithProjectInContext(c *gin.Context, workspaceID, userID, projectID string) {
	claims := jwt.MapClaims{
		"workspace_id":  workspaceID,
		"sub":        userID,
		"project_id": projectID,
	}
	c.Set("claims", claims)
	// Also set tenant_id directly as the middleware does
	c.Set("workspace_id", workspaceID)
}
