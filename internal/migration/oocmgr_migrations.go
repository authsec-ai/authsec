package migration

import (
	_ "embed"
	"log"
	"strings"

	"gorm.io/gorm"
)

//go:embed oocmgr_main_schema.sql
var oocmgrMainSchemaSQLEmbedded string

//go:embed oocmgr_tenant_schema.sql
var oocmgrTenantSchemaSQLEmbedded string

// MigrateOocmgrMainTables runs the OOCMGR main database migrations (tenant_hydra_clients).
func MigrateOocmgrMainTables(db *gorm.DB) error {
	if strings.TrimSpace(oocmgrMainSchemaSQLEmbedded) == "" {
		return nil
	}
	log.Println("MIGRATION: Running oocmgr_main_schema.sql")
	if err := db.Exec(oocmgrMainSchemaSQLEmbedded).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "SQLSTATE 42P07") ||
			strings.Contains(errStr, "SQLSTATE 42710") {
			log.Println("MIGRATION: oocmgr_main_schema.sql — objects already exist, continuing")
			return nil
		}
		log.Printf("MIGRATION: oocmgr_main_schema.sql warning: %v", err)
		return nil
	}
	log.Println("MIGRATION: Completed oocmgr_main_schema.sql")
	return nil
}

// MigrateOocmgrTenantTables runs the OOCMGR tenant database migrations (oauth_oidc_configurations, saml_providers).
// Call this when provisioning a new tenant database.
func MigrateOocmgrTenantTables(db *gorm.DB) error {
	if strings.TrimSpace(oocmgrTenantSchemaSQLEmbedded) == "" {
		return nil
	}
	log.Println("MIGRATION: Running oocmgr_tenant_schema.sql")
	if err := db.Exec(oocmgrTenantSchemaSQLEmbedded).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "SQLSTATE 42P07") ||
			strings.Contains(errStr, "SQLSTATE 42710") {
			log.Println("MIGRATION: oocmgr_tenant_schema.sql — objects already exist, continuing")
			return nil
		}
		log.Printf("MIGRATION: oocmgr_tenant_schema.sql warning: %v", err)
		return nil
	}
	log.Println("MIGRATION: Completed oocmgr_tenant_schema.sql")
	return nil
}
