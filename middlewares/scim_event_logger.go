package middlewares

import (
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// SCIMEventLogger writes one scim_events row after each SCIM provisioning
// request. Must be chained after SCIMConnectionAuth so that workspace_id and
// scim_connection_id are already set in the context.
func SCIMEventLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		connIDStr, _ := c.Get("scim_connection_id")
		wsIDStr, _ := c.Get("workspace_id")

		connID, err := uuid.Parse(connIDStr.(string))
		if err != nil {
			return
		}
		wsID, err := uuid.Parse(wsIDStr.(string))
		if err != nil {
			return
		}

		path := c.Request.URL.Path
		resourceType := scimResourceTypeFromPath(path)
		resourceID := scimResourceIDFromPath(path)

		statusCode := c.Writer.Status()
		var errText *string
		if statusCode >= 400 {
			detail := c.GetString("scim_error_detail")
			if detail != "" {
				errText = &detail
			}
		}

		ip := c.ClientIP()
		ua := c.Request.UserAgent()
		event := &models.SCIMEvent{
			WorkspaceID:      wsID,
			SCIMConnectionID: connID,
			Ts:               time.Now(),
			Method:           c.Request.Method,
			Path:             path,
			ResourceType:     resourceType,
			ResourceID:       resourceID,
			StatusCode:       statusCode,
			ErrorText:        errText,
			IPAddress:        &ip,
			UserAgent:        &ua,
		}

		if err := config.DB.Create(event).Error; err != nil {
			log.Printf("[SCIMEventLogger] failed to write event: %v", err)
		}
	}
}

func scimResourceTypeFromPath(path string) string {
	switch {
	case strings.Contains(path, "/Users"):
		return "User"
	case strings.Contains(path, "/Groups"):
		return "Group"
	default:
		return ""
	}
}

func scimResourceIDFromPath(path string) *string {
	// Path shape: .../Users/<id> or .../Groups/<id>
	for _, segment := range []string{"/Users/", "/Groups/"} {
		if idx := strings.Index(path, segment); idx >= 0 {
			rest := path[idx+len(segment):]
			rest = strings.Split(rest, "/")[0]
			if rest != "" {
				return &rest
			}
		}
	}
	return nil
}
