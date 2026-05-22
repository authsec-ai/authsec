package middlewares

import (
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequireWorkspaceRole gates operator-facing console routes by workspace role
// membership. It intentionally does not read the legacy permissions table:
// platform administration is role membership, while application access is
// scope-driven through resource-server roles.
func RequireWorkspaceRole(allowedRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		if role != "" {
			allowed[role] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		if config.DB == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
			c.Abort()
			return
		}

		workspaceIDStr, ok := GetWorkspaceIDFromToken(c)
		if !ok || workspaceIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required"})
			c.Abort()
			return
		}
		userIDStr := c.GetString("user_id")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required"})
			c.Abort()
			return
		}

		workspaceID, err := uuid.Parse(workspaceIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid workspace_id"})
			c.Abort()
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user_id"})
			c.Abort()
			return
		}

		var count int64
		query := config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.user_id = ? AND rb.tenant_id = ?", userID, workspaceID).
			Where("rb.expires_at IS NULL OR rb.expires_at > NOW()")
		if len(allowed) > 0 {
			names := make([]string, 0, len(allowed))
			for name := range allowed {
				names = append(names, name)
			}
			query = query.Where("r.name IN ?", names)
		}

		if err := query.Count(&count).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "workspace role check failed"})
			c.Abort()
			return
		}
		if count == 0 {
			workspaceQuery := config.DB.Table("workspace_memberships wm").
				Joins("JOIN roles r ON r.id = wm.role_id").
				Where("wm.user_id = ? AND wm.workspace_id = ?", userID, workspaceID).
				Where("wm.status = ?", "active")
			if len(allowed) > 0 {
				names := make([]string, 0, len(allowed))
				for name := range allowed {
					names = append(names, name)
				}
				workspaceQuery = workspaceQuery.Where("r.name IN ?", names)
			}
			if err := workspaceQuery.Count(&count).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "workspace role check failed"})
				c.Abort()
				return
			}
		}
		if count == 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "workspace admin role required"})
			c.Abort()
			return
		}

		c.Next()
	}
}
