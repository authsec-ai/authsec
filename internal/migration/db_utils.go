package migration

import (
	"fmt"

	"gorm.io/gorm"
)

// Per-workspace databases (template cloning, tenant migration runs) were
// removed with the single-database architecture (AS-094).

// AutoMigrateMigrationLogs ensures the migration_logs table exists in the master DB.
func AutoMigrateMigrationLogs(gormDB *gorm.DB) error {
	if gormDB == nil {
		return fmt.Errorf("GORM DB not initialized")
	}
	return gormDB.AutoMigrate(&MigrationLog{})
}
