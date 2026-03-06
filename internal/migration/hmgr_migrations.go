package migration

import (
	_ "embed"
	"log"
	"strings"

	"gorm.io/gorm"
)

//go:embed hmgr_main_schema.sql
var hmgrMainSchemaSQLEmbedded string

//go:embed hmgr_tenant_schema.sql
var hmgrTenantSchemaSQLEmbedded string

// MigrateHmgrMainTables runs the HMGR main database migrations (saml_sp_certificates, saml_requests, saml_callback_states).
func MigrateHmgrMainTables(db *gorm.DB) error {
	if strings.TrimSpace(hmgrMainSchemaSQLEmbedded) == "" {
		return nil
	}
	log.Println("MIGRATION: Running hmgr_main_schema.sql")
	if err := db.Exec(hmgrMainSchemaSQLEmbedded).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "SQLSTATE 42P07") ||
			strings.Contains(errStr, "SQLSTATE 42710") {
			log.Println("MIGRATION: hmgr_main_schema.sql — objects already exist, continuing")
			return nil
		}
		log.Printf("MIGRATION: hmgr_main_schema.sql warning: %v", err)
		return nil
	}
	log.Println("MIGRATION: Completed hmgr_main_schema.sql")
	return nil
}

// MigrateHmgrTenantTables runs the HMGR tenant database migrations (saml_providers).
// Call this when provisioning a new tenant database.
func MigrateHmgrTenantTables(db *gorm.DB) error {
	if strings.TrimSpace(hmgrTenantSchemaSQLEmbedded) == "" {
		return nil
	}
	log.Println("MIGRATION: Running hmgr_tenant_schema.sql")
	if err := db.Exec(hmgrTenantSchemaSQLEmbedded).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "SQLSTATE 42P07") ||
			strings.Contains(errStr, "SQLSTATE 42710") {
			log.Println("MIGRATION: hmgr_tenant_schema.sql — objects already exist, continuing")
			return nil
		}
		log.Printf("MIGRATION: hmgr_tenant_schema.sql warning: %v", err)
		return nil
	}
	log.Println("MIGRATION: Completed hmgr_tenant_schema.sql")
	return nil
}
