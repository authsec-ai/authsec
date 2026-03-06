package migration

import (
	_ "embed"
	"log"
	"strings"

	"gorm.io/gorm"
)

//go:embed clients_schema.sql
var clientsSchemaSQLembedded string

// MigrateClientsTables creates the clients table in the given (tenant) DB.
// It is idempotent: errors for objects that already exist are silently ignored.
func MigrateClientsTables(db *gorm.DB) error {
	if strings.TrimSpace(clientsSchemaSQLembedded) == "" {
		return nil
	}
	log.Println("MIGRATION: Running clients_schema.sql")
	if err := db.Exec(clientsSchemaSQLembedded).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") ||
			strings.Contains(errStr, "SQLSTATE 42P07") ||
			strings.Contains(errStr, "SQLSTATE 42710") {
			log.Println("MIGRATION: clients_schema.sql — objects already exist, continuing")
			return nil
		}
		return nil // Non-fatal: log but allow startup to continue
	}
	log.Println("MIGRATION: Completed clients_schema.sql")
	return nil
}

// EnsureClientsMappingTable creates the tenant_mappings table in the main (global) DB.
// This table lives in the main database and maps tenants to their clients.
func EnsureClientsMappingTable(db *gorm.DB) error {
	sql := `
CREATE TABLE IF NOT EXISTS tenant_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tenant_mappings_tenant ON tenant_mappings(tenant_id);
`
	if err := db.Exec(sql).Error; err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already exists") ||
			strings.Contains(errStr, "duplicate key") {
			return nil
		}
		log.Printf("MIGRATION: tenant_mappings table warning: %v", err)
	}
	return nil
}
