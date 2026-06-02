package shared

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// ResolveTenantIDString returns the tenant_id from context as a string. The
// tenant-DB column type is varchar(255), so most tenant-DB queries want the
// raw string form rather than a parsed UUID.
//
// For the *uuid.UUID variant see ResolveTenantIDFromToken in role_helpers.go.
func ResolveTenantIDString(c *gin.Context) (string, error) {
	raw, ok := c.Get("tenant_id")
	if !ok {
		return "", errors.New("tenant_id not in context")
	}
	s, _ := raw.(string)
	if s == "" {
		return "", errors.New("tenant_id empty in context")
	}
	return s, nil
}
