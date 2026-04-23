package platform

import (
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
)

// auditAdminMutation logs an admin mutation event via the global AuditLogger.
// statusCode must be the actual HTTP status that will be returned (201, 200, 204, etc.).
func auditAdminMutation(
	c *gin.Context,
	tenantID, action, resource, resourceID string,
	statusCode int,
	oldValues, newValues interface{},
) {
	if config.AuditLogger == nil {
		return
	}
	userID, _ := middlewares.ResolveUserID(c)
	config.AuditLogger.LogAdminAction(
		c.GetString("request_id"),
		tenantID,
		userID,
		action,
		resource,
		resourceID,
		c.Request.Method,
		c.Request.URL.Path,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
		statusCode,
		time.Duration(0),
		oldValues,
		newValues,
		"",
	)
}
