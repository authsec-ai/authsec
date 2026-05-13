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

// CreateTenantDB POST /authsec-migration/tenants/create-db
func (mc *MigrationController) CreateTenantDB(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// RunTenantMigrations POST /authsec-migration/tenants/:tenant_id/migrations/run
func (mc *MigrationController) RunTenantMigrations(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": "Tenant database operations are managed by mt-plugin",
		"hint":  "Start the mt-plugin microservice and configure MT_PLUGIN_GRPC_ADDR",
	})
}

// GetTenantMigrationStatus GET /authsec-migration/tenants/:tenant_id/migrations/status
func (mc *MigrationController) GetTenantMigrationStatus(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	var tenant migration.TenantInfo
	if err := config.DB.Where("tenant_id = ?", tenantID).First(&tenant).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	dbName := ""
	if tenant.TenantDB != nil {
		dbName = *tenant.TenantDB
	}

	migStatus := "pending"
	if tenant.MigrationStatus != nil {
		migStatus = *tenant.MigrationStatus
	}

	if dbName == "" {
		c.JSON(http.StatusOK, gin.H{
			"tenant_id":        tenant.TenantID.String(),
			"migration_status": migStatus,
			"last_migration":   tenant.LastMigration,
		})
		return
	}

	cfg := config.AppConfig
	tenantDBConn, err := migration.ConnectToTenantDB(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, dbName)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"tenant_id":        tenant.TenantID.String(),
			"database_name":    dbName,
			"migration_status": migStatus,
			"last_migration":   tenant.LastMigration,
			"error":            "Unable to connect to tenant database",
		})
		return
	}
	defer tenantDBConn.Close()

	masterRaw := config.Database.DB
	runner := migration.NewTenantMigrationRunner(tenantID, tenantDBConn, mc.tenantMigrationsDir, masterRaw)
	status, err := runner.GetMigrationStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get migration status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":        tenant.TenantID.String(),
		"database_name":    dbName,
		"migration_status": migStatus,
		"status":           status,
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
func (mc *MigrationController) ListTenants(c *gin.Context) {
	var tenants []migration.TenantInfo
	if err := config.DB.Find(&tenants).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read tenants", "details": err.Error()})
		return
	}

	items := make([]migration.TenantListItem, 0, len(tenants))
	for _, t := range tenants {
		item := migration.TenantListItem{
			TenantID:      t.TenantID.String(),
			Email:         t.Email,
			TenantDomain:  t.TenantDomain,
			LastMigration: t.LastMigration,
		}
		if t.TenantDB != nil {
			item.DatabaseName = *t.TenantDB
		}
		if t.MigrationStatus != nil {
			item.MigrationStatus = *t.MigrationStatus
		} else {
			item.MigrationStatus = "pending"
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, gin.H{"total": len(items), "tenants": items})
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


