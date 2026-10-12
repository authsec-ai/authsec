package shared

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// TenantScope returns the request's tenant context and a GORM handle
// restricted to its workspace (ADR-0001 §4.3). When the request carries no
// tenant it answers 401 itself and returns ok=false.
func TenantScope(c *gin.Context) (tenancy.Context, *gorm.DB, bool) {
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return tenancy.Context{}, nil, false
	}
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database connection not available"})
		return tenancy.Context{}, nil, false
	}
	db, err := tenancy.DB(c, config.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return tenancy.Context{}, nil, false
	}
	return tc, db, true
}

// IsNotFound reports whether err means "no such row in this workspace": a
// tenancy.ErrNotFound or a GORM record-not-found.
func IsNotFound(err error) bool {
	return errors.Is(err, tenancy.ErrNotFound) || errors.Is(err, gorm.ErrRecordNotFound)
}
