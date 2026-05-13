package middlewares

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ValidateTenantFromToken ensures URL tenant_id matches JWT token tenant_id
func ValidateTenantFromToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant_id from URL parameter
		urlTenantID := c.Param("tenant_id")
		if urlTenantID == "" {
			// No tenant_id in URL, skip validation (for non-tenant routes)
			c.Next()
			return
		}

		// Get tenant_id from validated JWT token
		tokenTenantID, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Tenant ID not found in authentication token",
			})
			c.Abort()
			return
		}

		tokenTenantIDStr, ok := tokenTenantID.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid tenant ID format in token",
			})
			c.Abort()
			return
		}

		// Check if user is admin (admins can access any tenant)
		if isAdminUser(c) {
			// Log cross-tenant access for audit
			if tokenTenantIDStr != urlTenantID {
				logCrossTenantAccess(c, tokenTenantIDStr, urlTenantID)
			}
			c.Next()
			return
		}

		// Regular users must match their token tenant_id
		if tokenTenantIDStr != urlTenantID {
			log.Printf("SECURITY: Tenant mismatch - Token: %s, URL: %s, User: %v",
				tokenTenantIDStr, urlTenantID, c.GetString("user_id"))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied: tenant mismatch",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetTenantIDFromToken helper function for controllers
func GetTenantIDFromToken(c *gin.Context) (string, bool) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return "", false
	}
	tenantIDStr, ok := tenantID.(string)
	return tenantIDStr, ok
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

// logCrossTenantAccess logs admin cross-tenant access for audit
func logCrossTenantAccess(c *gin.Context, tokenTenantID, urlTenantID string) {
	log.Printf("AUDIT: Cross-tenant access | Admin: %s | Token Tenant: %s | Access Tenant: %s | Path: %s | Method: %s",
		c.GetString("user_id"), tokenTenantID, urlTenantID, c.Request.URL.Path, c.Request.Method)
}
