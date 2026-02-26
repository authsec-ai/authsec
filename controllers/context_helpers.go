package controllers

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// contextStringValue normalizes a value stored in the Gin context to a trimmed string.
func contextStringValue(c *gin.Context, key string) string {
	value, exists := c.Get(key)
	if !exists || value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case uuid.UUID:
		if v == uuid.Nil {
			return ""
		}
		return v.String()
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// requireTenantID retrieves tenant_id from context, returning an error when missing.
func requireTenantID(c *gin.Context) (string, error) {
	tenantID := contextStringValue(c, "tenant_id")
	if tenantID == "" {
		return "", fmt.Errorf("tenant not found")
	}
	return tenantID, nil
}
