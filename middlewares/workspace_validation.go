package middlewares

import (
	"log"
	"net/http"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/gin-gonic/gin"
)

// ValidateWorkspaceFromToken ensures URL workspace_id matches JWT token workspace_id.
func ValidateWorkspaceFromToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		urlWorkspaceID := c.Param("workspace_id")
		if urlWorkspaceID == "" {
			c.Next()
			return
		}

		tokenWorkspaceID, exists := WorkspaceValue(c)
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
			// Another workspace's resources do not exist for this caller: 404,
			// so the response does not confirm the workspace exists (AS-063).
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetWorkspaceIDFromToken returns the active workspace_id claim from the JWT.
func GetWorkspaceIDFromToken(c *gin.Context) (string, bool) {
	tc, err := tenancy.From(c)
	if err != nil {
		return "", false
	}
	return tc.WorkspaceID.String(), true
}

// WorkspaceIDString is the request's workspace ("" when there is none). Like
// GetWorkspaceIDFromToken it reads the tenancy context the authenticating
// middleware set from a verified credential (ADR-0001 §4.2; the legacy gin
// key "workspace_id" was retired in Phase 6).
func WorkspaceIDString(c *gin.Context) string {
	s, _ := GetWorkspaceIDFromToken(c)
	return s
}

// WorkspaceValue mirrors WorkspaceValue(c) for code written against the
// retired legacy key: the workspace as a string, from the tenancy context.
func WorkspaceValue(c *gin.Context) (interface{}, bool) {
	s, ok := GetWorkspaceIDFromToken(c)
	if !ok {
		return nil, false
	}
	return s, true
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


