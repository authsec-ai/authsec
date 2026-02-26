package migration

import (
	_ "embed"
	"fmt"
	"log"
	"strings"

	"gorm.io/gorm"
)

//go:embed 007_services_schema.sql
var servicesSchemaSQLextsvc string

//go:embed 010_external_service_permissions.sql
var externalServicePermissionsSQL string

const extsvcMigrationTable = "external_service_migrations"

// MigrateExternalServiceTables creates the services table in the given (tenant) DB.
func MigrateExternalServiceTables(db *gorm.DB) error {
	if strings.TrimSpace(servicesSchemaSQLextsvc) == "" {
		return nil
	}
	log.Println("MIGRATION: Running 007_services_schema.sql")
	if err := db.Exec(servicesSchemaSQLextsvc).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "SQLSTATE 42P07") ||
			strings.Contains(errStr, "SQLSTATE 42710") {
			log.Println("MIGRATION: 007_services_schema.sql — objects already exist, continuing")
			return nil
		}
		return fmt.Errorf("failed to execute 007_services_schema.sql: %w", err)
	}
	log.Println("MIGRATION: Completed 007_services_schema.sql")
	return nil
}

// EnsureExternalServicePermissions seeds RBAC permissions for the external-service
// resource in the global DB for the given tenant. Idempotent.
func EnsureExternalServicePermissions(db *gorm.DB, tenantID string) error {
	if extsvcMigrationExists(db, tenantID, "010_external_service_permissions") {
		log.Printf("MIGRATION: 010_external_service_permissions already applied for tenant %s", tenantID)
		return nil
	}

	stmt := strings.ReplaceAll(externalServicePermissionsSQL, ":tenant_id", fmt.Sprintf("'%s'", tenantID))
	log.Printf("MIGRATION: Running 010_external_service_permissions for tenant %s", tenantID)

	if err := db.Exec(stmt).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "SQLSTATE 23505") ||
			strings.Contains(errStr, "uni_roles_name") {
			log.Printf("MIGRATION: permissions already exist for tenant %s, marking complete", tenantID)
			extsvcRecordMigration(db, tenantID, "010_external_service_permissions")
			return nil
		}
		return fmt.Errorf("failed to execute 010_external_service_permissions: %w", err)
	}

	extsvcRecordMigration(db, tenantID, "010_external_service_permissions")
	log.Printf("MIGRATION: Completed 010_external_service_permissions for tenant %s", tenantID)
	return nil
}

func extsvcEnsureMigrationTable(db *gorm.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS ` + extsvcMigrationTable + ` (
		id SERIAL PRIMARY KEY,
		tenant_id UUID NOT NULL,
		migration_name VARCHAR(255) NOT NULL,
		applied_at TIMESTAMPTZ DEFAULT NOW(),
		UNIQUE(tenant_id, migration_name)
	)`)
}

func extsvcMigrationExists(db *gorm.DB, tenantID, migrationName string) bool {
	extsvcEnsureMigrationTable(db)
	var count int64
	db.Raw(`SELECT COUNT(*) FROM `+extsvcMigrationTable+` WHERE tenant_id = ? AND migration_name = ?`,
		tenantID, migrationName).Scan(&count)
	return count > 0
}

func extsvcRecordMigration(db *gorm.DB, tenantID, migrationName string) {
	extsvcEnsureMigrationTable(db)
	db.Exec(`INSERT INTO `+extsvcMigrationTable+` (tenant_id, migration_name) VALUES (?, ?)
		ON CONFLICT (tenant_id, migration_name) DO NOTHING`, tenantID, migrationName)
}
