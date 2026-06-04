package enduser

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// setTokenClaimsInContext sets JWT claims in the Gin context for testing.
// Mirrors what the auth middleware does after validating a token.
func setTokenClaimsInContext(c *gin.Context, workspaceID string, userID string) {
	claims := jwt.MapClaims{
		"workspace_id": workspaceID,
		"sub":       userID,
	}
	c.Set("claims", claims)
	c.Set("workspace_id", workspaceID)
}
