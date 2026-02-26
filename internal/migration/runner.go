package migration

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strings"

	"gorm.io/gorm"
)

// MigrationRunner handles SQL migration execution
type MigrationRunner struct {
	db *gorm.DB
}

// NewMigrationRunner creates a new migration runner
func NewMigrationRunner(db *gorm.DB) *MigrationRunner {
	return &MigrationRunner{db: db}
}

// ensureMigrationsTable creates the schema_migrations table if it doesn't exist
func (m *MigrationRunner) ensureMigrationsTable() error {
	// Create the table with basic structure
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
	`
	if err := m.db.Exec(createTableSQL).Error; err != nil {
		return err
	}

	// Check if version column is INTEGER and convert to VARCHAR if needed
	var columnType string
	checkVersionTypeSQL := `
		SELECT data_type FROM information_schema.columns 
		WHERE table_name = 'schema_migrations' AND column_name = 'version'
	`
	if err := m.db.Raw(checkVersionTypeSQL).Scan(&columnType).Error; err == nil {
		if columnType == "integer" {
			log.Printf("Converting schema_migrations.version column from INTEGER to VARCHAR for string migration names")
			// Drop and recreate table with correct column type
			recreateTableSQL := `
				DROP TABLE IF EXISTS schema_migrations;
				CREATE TABLE schema_migrations (
					version VARCHAR(255) PRIMARY KEY,
					applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
				);
			`
			if err := m.db.Exec(recreateTableSQL).Error; err != nil {
				return fmt.Errorf("failed to recreate schema_migrations table: %w", err)
			}
		}
	}

	// Add checksum column if it doesn't exist (for backward compatibility)
	addChecksumSQL := `
		ALTER TABLE schema_migrations 
		ADD COLUMN IF NOT EXISTS checksum VARCHAR(64);
	`
	if err := m.db.Exec(addChecksumSQL).Error; err != nil {
		return err
	}

	// Create index
	createIndexSQL := `
		CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at ON schema_migrations(applied_at);
	`
	return m.db.Exec(createIndexSQL).Error
}

// getMigrationFiles returns sorted list of SQL migration files
func (m *MigrationRunner) getMigrationFiles(migrationsDir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("failed to list migration files: %w", err)
	}

	sort.Strings(files)
	return files, nil
}

// getAppliedMigrations returns list of already applied migration versions
func (m *MigrationRunner) getAppliedMigrations() (map[string]bool, error) {
	if err := m.ensureMigrationsTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure migrations table exists: %w", err)
	}

	var versions []string
	result := m.db.Table("schema_migrations").Pluck("version", &versions)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", result.Error)
	}

	applied := make(map[string]bool)
	for _, version := range versions {
		applied[version] = true
	}

	return applied, nil
}

// extractVersionFromFilename extracts the migration version from filename
func (m *MigrationRunner) extractVersionFromFilename(filename string) string {
	base := filepath.Base(filename)
	// Extract version from filename like "001_initial_schema.sql" -> "001_initial_schema"
	return strings.TrimSuffix(base, ".sql")
}

// calculateChecksum calculates a simple checksum for migration content
func (m *MigrationRunner) calculateChecksum(content string) string {
	// Simple hash implementation - in production, you might want to use SHA256
	hash := 0
	for _, char := range content {
		hash = hash*31 + int(char)
	}
	return fmt.Sprintf("%d", hash)
}

// runMigration executes a single migration file
func (m *MigrationRunner) runMigration(filePath string) error {
	log.Printf("Running migration: %s", filepath.Base(filePath))

	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read migration file %s: %w", filePath, err)
	}

	contentStr := string(content)
	version := m.extractVersionFromFilename(filePath)
	checksum := m.calculateChecksum(contentStr)

	// Execute the migration in a transaction
	return m.db.Transaction(func(tx *gorm.DB) error {
		// Execute the SQL content
		if err := tx.Exec(contentStr).Error; err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", version, err)
		}

		// Record the migration as applied - check if checksum column exists
		var columnExists bool
		checkColumnSQL := `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'schema_migrations' AND column_name = 'checksum'
			)
		`
		if err := tx.Raw(checkColumnSQL).Scan(&columnExists).Error; err != nil {
			return fmt.Errorf("failed to check checksum column existence: %w", err)
		}

		var insertSQL string
		var args []interface{}
		
		if columnExists {
			// Use checksum if column exists
			insertSQL = `
				INSERT INTO schema_migrations (version, applied_at, checksum) 
				VALUES (?, NOW(), ?)
				ON CONFLICT (version) DO UPDATE SET 
					applied_at = NOW(), 
					checksum = EXCLUDED.checksum
			`
			args = []interface{}{version, checksum}
		} else {
			// Skip checksum if column doesn't exist (backward compatibility)
			insertSQL = `
				INSERT INTO schema_migrations (version, applied_at) 
				VALUES (?, NOW())
				ON CONFLICT (version) DO UPDATE SET 
					applied_at = NOW()
			`
			args = []interface{}{version}
		}
		
		if err := tx.Exec(insertSQL, args...).Error; err != nil {
			return fmt.Errorf("failed to record migration %s: %w", version, err)
		}

		log.Printf("Successfully applied migration: %s", version)
		return nil
	})
}

// RunMigrations executes all pending migrations in the specified directory
func (m *MigrationRunner) RunMigrations(migrationsDir string) error {
	log.Printf("Starting migration run from directory: %s", migrationsDir)

	// Get list of migration files
	migrationFiles, err := m.getMigrationFiles(migrationsDir)
	if err != nil {
		return err
	}

	if len(migrationFiles) == 0 {
		log.Printf("No migration files found in %s", migrationsDir)
		return nil
	}

	// Get list of applied migrations
	appliedMigrations, err := m.getAppliedMigrations()
	if err != nil {
		return err
	}

	// Execute pending migrations
	pendingCount := 0
	for _, filePath := range migrationFiles {
		version := m.extractVersionFromFilename(filePath)

		if appliedMigrations[version] {
			log.Printf("Migration %s already applied, skipping", version)
			continue
		}

		if err := m.runMigration(filePath); err != nil {
			return fmt.Errorf("migration %s failed: %w", version, err)
		}
		pendingCount++
	}

	if pendingCount == 0 {
		log.Printf("No pending migrations to apply")
	} else {
		log.Printf("Successfully applied %d migrations", pendingCount)
	}

	return nil
}

// RunMigrationsForTenantDB executes migrations on a specific tenant database
func (m *MigrationRunner) RunMigrationsForTenantDB(tenantDB *gorm.DB, migrationsDir string) error {
	tenantRunner := &MigrationRunner{db: tenantDB}
	return tenantRunner.RunMigrations(migrationsDir)
}

// GetMigrationStatus returns the status of all migrations
func (m *MigrationRunner) GetMigrationStatus(migrationsDir string) ([]MigrationStatus, error) {
	migrationFiles, err := m.getMigrationFiles(migrationsDir)
	if err != nil {
		return nil, err
	}

	appliedMigrations, err := m.getAppliedMigrations()
	if err != nil {
		return nil, err
	}

	var status []MigrationStatus
	for _, filePath := range migrationFiles {
		version := m.extractVersionFromFilename(filePath)
		isApplied := appliedMigrations[version]

		status = append(status, MigrationStatus{
			Version:   version,
			Filename:  filepath.Base(filePath),
			Applied:   isApplied,
			AppliedAt: nil, // Could query this from schema_migrations if needed
		})
	}

	return status, nil
}

// MigrationStatus represents the status of a single migration
type MigrationStatus struct {
	Version   string     `json:"version"`
	Filename  string     `json:"filename"`
	Applied   bool       `json:"applied"`
	AppliedAt *sql.NullTime `json:"applied_at,omitempty"`
}