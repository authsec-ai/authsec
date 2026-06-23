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
	tenantMigrationsDir string
}

// NewMigrationController creates a MigrationController using the canonical migration directories.
func NewMigrationController() *MigrationController {
	return &MigrationController{
		masterMigrationsDir: migration.MigrationsDir("master"),
		tenantMigrationsDir: migration.MigrationsDir("tenant"),
	}
}

// RunMasterMigrations POST /authsec-migration/migrations/master/run
func (mc *MigrationController) RunMasterMigrations(c *gin.Context) {
	log.Println("[MigrationController] Running master database migrations")

	rawDB := config.Database.DB
	runner := migration.NewMasterMigrationRunner(mc.masterMigrationsDir, rawDB, config.DB)
	if err := runner.RunMigrations(); err != nil {
		log.Printf("[MigrationController] Master migration error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to execute master migrations",
			"details": err.Error(),
		})
		return
	}

	status, err := runner.GetMigrationStatus()
	if err != nil || status == nil {
		c.JSON(http.StatusOK, gin.H{"message": "Master migrations executed but status unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Master migrations executed successfully",
		"status":  status,
	})
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

// CreateWorkspaceDB POST /authsec-migration/tenants/create-db
func (mc *MigrationController) CreateWorkspaceDB(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// RunTenantMigrations POST /authsec-migration/tenants/:workspace_id/migrations/run
func (mc *MigrationController) RunTenantMigrations(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// GetTenantMigrationStatus GET /authsec-migration/tenants/:workspace_id/migrations/status
//
// Single master DB architecture: there are no per-tenant databases and the
// `tenants` table no longer exists. Per-tenant DB operations, if ever needed,
// are owned by the mt-plugin microservice. This endpoint reports unavailable
// rather than querying the dropped table (which would 500).
func (mc *MigrationController) GetTenantMigrationStatus(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// MigrateAllTenants POST /authsec-migration/tenants/migrate-all
func (mc *MigrationController) MigrateAllTenants(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// ListTenants GET /authsec-migration/tenants
//
// Single master DB architecture: the `tenants` table was dropped in the
// tenant→workspace collapse. Per-tenant DB operations are owned by mt-plugin.
// Reports unavailable rather than querying the dropped table (which would 500).
func (mc *MigrationController) ListTenants(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// CreateTenantFromTemplate POST /authsec/migration/tenants/create-from-template
// Clones the golden template DB to create a new tenant database — much faster than running migrations.
func (mc *MigrationController) CreateTenantFromTemplate(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// GetTemplateStatus GET /authsec/migration/tenants/template-status
func (mc *MigrationController) GetTemplateStatus(c *gin.Context) {
	c.JSON(http.StatusOK, migration.TemplateStatusResponse{
		TemplateName: migration.TemplateDBName,
		Ready:        migration.TemplateReady,
	})
}
