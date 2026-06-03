package middlewares

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ValidateTenantFromToken ensures URL workspace_id matches JWT token workspace_id.
// Function name preserved (deprecated) to avoid churning route registrations.
func ValidateTenantFromToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		urlWorkspaceID := c.Param("workspace_id")
		if urlWorkspaceID == "" {
			c.Next()
			return
		}

		tokenWorkspaceID, exists := c.Get("workspace_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Workspace ID not found in authentication token",
			})
			c.Abort()
			return
		}

		tokenWorkspaceIDStr, ok := tokenWorkspaceID.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid workspace ID format in token",
			})
			c.Abort()
			return
		}

		if tokenWorkspaceIDStr != urlWorkspaceID {
			log.Printf("SECURITY: Workspace mismatch - Token: %s, URL: %s, User: %v, Admin: %v",
				tokenWorkspaceIDStr, urlWorkspaceID, c.GetString("user_id"), isAdminUser(c))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied: workspace mismatch",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetWorkspaceIDFromToken returns the active workspace_id claim from the JWT.
func GetWorkspaceIDFromToken(c *gin.Context) (string, bool) {
	workspaceID, exists := c.Get("workspace_id")
	if !exists {
		return "", false
	}
	if s, ok := workspaceID.(string); ok && s != "" {
		return s, true
	}
	return "", false
}

// isAdminUser checks if user has admin role
func isAdminUser(c *gin.Context) bool {
	roles, exists := c.Get("roles")
	if !exists {
		return false
	}

	rolesSlice, ok := roles.([]string)
	if !ok {
		return false
	}

	for _, role := range rolesSlice {
		if role == "admin" || role == "super_admin" {
			return true
		}
	}
	return false
}


