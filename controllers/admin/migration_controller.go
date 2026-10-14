package admin

import (
	"log"
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/migration"
	"github.com/gin-gonic/gin"
)

// MigrationController handles HTTP endpoints for database migration management.
type MigrationController struct {
	masterMigrationsDir string
}

// NewMigrationController creates a MigrationController using the canonical migration directories.
func NewMigrationController() *MigrationController {
	return &MigrationController{
		masterMigrationsDir: migration.MigrationsDir("master"),
	}
}

// GetMasterMigrationStatus GET /authsec-migration/migrations/master/status
func (mc *MigrationController) GetMasterMigrationStatus(c *gin.Context) {
	rawDB := config.Database.DB
	runner := migration.NewMasterMigrationRunner(mc.masterMigrationsDir, rawDB, config.DB)
	status, err := runner.GetMigrationStatus()
	if err != nil {
		log.Printf("[MigrationController] Failed to get master migration status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get migration status"})
		return
	}
	c.JSON(http.StatusOK, status)
}
