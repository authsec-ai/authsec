package admin

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// requireInWorkspace checks that table has a row with this id in the
// workspace db is scoped to. Another workspace's row is tenancy.ErrNotFound.
func requireInWorkspace(db *gorm.DB, table string, id uuid.UUID) error {
	var n int64
	if err := db.Table(table).Where("id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return tenancy.ErrNotFound
	}
	return nil
}

// requireBindingScopeInWorkspace checks a role binding's scope id. The only
// scope the runtime resolves is a resource server (scope_type
// 'resource_server'), so the id must name one of this workspace's resource
// servers. A binding pointing at another workspace's server leaked its name
// and URI through the access views (AS-062).
func requireBindingScopeInWorkspace(db *gorm.DB, id uuid.UUID) error {
	return requireInWorkspace(db, "resource_servers", id)
}

// writeBindingLookupError answers 404 for a missing referent and 500 for a
// database error.
func writeBindingLookupError(c *gin.Context, err error, notFound string) {
	if errors.Is(err, tenancy.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": notFound})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
}
