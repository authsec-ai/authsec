package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/database"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database connection (raw SQL)
var Database *database.DBConnection

// DB is the GORM instance for controllers (migrations disabled)
var DB *gorm.DB

// InitDatabaseWithoutGORM initializes the database connection using native SQL driver
func InitDatabaseWithoutGORM(cfg *Config) {
	if os.Getenv("SKIP_DB_INIT") == "true" {
		log.Println("Skipping database initialization (SKIP_DB_INIT=true)")
		return
	}

	var err error

	// Initialize master database connection
	Database, err = database.InitializeDatabase(
		cfg.DBHost,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
		cfg.DBPort,
	)

	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	log.Println("Database connected successfully (without GORM)")

	// Run SQL migrations using the existing migration system
	runMigrationsNative(Database)
	log.Println("Database migration process completed (some may have failed but service continues)")
	log.Println("Database schema initialization completed successfully")

	// Initialize GORM instance for controllers (with auto-migration disabled)
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		// Disable auto-migration - we use SQL migrations only
		DisableAutomaticPing: false,
	})
	if err != nil {
		log.Fatalf("Failed to initialize GORM: %v", err)
	}

	log.Println("GORM initialized for controllers (AutoMigrate disabled)")

	// Schema sync disabled - use static template from templates/tenant_schema_template.sql
	// To regenerate template, run: ./scripts/generate_tenant_schema_snapshot.sh
	log.Println("Using static tenant schema template (automated sync disabled)")
}

// GetDatabase returns the current database connection
func GetDatabase() *database.DBConnection {
	return Database
}

func GetTenantDatabase(tenantID string) (*database.DBConnection, error) {
	return database.GetTenantDB(tenantID)
}

// GetTenantGORMDB returns a GORM connection for a specific tenant
func GetTenantGORMDB(tenantID string) (*gorm.DB, error) {
	conn, err := database.GetTenantDB(tenantID)
	if err != nil {
		return nil, err
	}

	return gorm.Open(postgres.New(postgres.Config{
		Conn: conn.DB,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}

// RunMigrations runs all pending database migrations using the tracked migration system
func RunMigrations(cfg *Config) error {
	// Initialize database connection if not already done
	if Database == nil {
		var err error
		Database, err = database.InitializeDatabase(
			cfg.DBHost,
			cfg.DBUser,
			cfg.DBPassword,
			cfg.DBName,
			cfg.DBPort,
		)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
	}

	// Run migrations using the native migration system
	runMigrationsNative(Database)
	log.Println("Migration process completed (some migrations may have failed but service continues)")
	return nil
}

// runMigrationsNative runs SQL migration files using native SQL driver
func runMigrationsNative(db *database.DBConnection) {
	// Check if migrations should be skipped
	if os.Getenv("SKIP_MIGRATIONS") == "true" {
		log.Println("Skipping database migrations as requested")
		return
	}

	// Enable required PostgreSQL extensions
	log.Println("Enabling required PostgreSQL extensions...")
	extensions := []string{
		"CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"",
		"CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"",
	}

	for _, ext := range extensions {
		if _, err := db.Exec(ext); err != nil {
			log.Printf("Warning: Failed to enable extension: %v", err)
		}
	}

	// Check if schema_migrations table exists and get its structure
	var tableExists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'public'
			AND table_name = 'schema_migrations'
		)
	`).Scan(&tableExists)
	if err != nil {
		log.Printf("Warning: failed to check if migrations table exists: %v", err)
	}

	if !tableExists {
		// Create migrations table with new structure
		_, err := db.Exec(`
			CREATE TABLE schema_migrations (
				version INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
			)
		`)
		if err != nil {
			log.Printf("Warning: failed to create migrations table: %v", err)
		}
	}

	// Verify migrations directory exists
	// Check current directory first, then parent directory (for tests)
	migrationsDir := "migrations"
	if _, err := os.Stat(migrationsDir); os.IsNotExist(err) {
		migrationsDir = "../migrations"
		if _, err := os.Stat(migrationsDir); os.IsNotExist(err) {
			log.Printf("Warning: migrations directory does not exist in current or parent directory")
			return
		}
		log.Printf("Using migrations directory from parent: %s", migrationsDir)
	}

	// Read migration files from migrations directory
	migrationFiles, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		log.Printf("Warning: failed to read migration files from %s: %v", migrationsDir, err)
		return
	}

	if len(migrationFiles) == 0 {
		log.Printf("Warning: no migration files found in %s directory - this is required for database setup", migrationsDir)
		return
	}

	// Sort migration files by name to ensure proper order
	sort.Strings(migrationFiles)

	log.Printf("Found %d migration files", len(migrationFiles))

	// Apply each migration
	for _, file := range migrationFiles {
		filename := filepath.Base(file)
		// Extract just the numeric prefix from the filename and convert to integer
		parts := strings.SplitN(strings.TrimSuffix(filename, ".sql"), "_", 2)
		versionStr := parts[0]
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			log.Printf("Warning: invalid migration version %s in file %s: %v", versionStr, filename, err)
			continue
		}

		// Extract name from filename (everything after first underscore)
		var name string
		if len(parts) > 1 {
			name = parts[1]
		} else {
			name = versionStr // fallback to version if no underscore
		}

		// Check if migration already applied
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = $1", version).Scan(&count)
		if err != nil {
			log.Printf("Warning: failed to check migration status for %d: %v", version, err)
			continue
		}

		log.Printf("Migration %d check: count=%d, will %s", version, count, map[bool]string{true: "skip", false: "apply"}[count > 0])

		if count > 0 {
			log.Printf("Migration %d already applied, skipping", version)
			continue
		}

		log.Printf("Applying migration: %d", version)

		// Read migration file content
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Warning: failed to read migration file %s: %v", file, err)
			continue
		}

		// Execute migration in a transaction for safety
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Warning: Failed to begin transaction for migration %d: %v", version, err)
			continue // Skip this migration but continue with others
		}

		// Execute migration SQL
		_, err = tx.Exec(string(content))
		if err != nil {
			tx.Rollback()
			log.Printf("Warning: Failed to execute migration %d (%s): %v", version, filename, err)
			log.Printf("Migration %d will be skipped - service will continue with other migrations", version)
			continue // Skip this migration but continue with others
		}

		// Record migration as applied
		_, err = tx.Exec("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", version, name)
		if err != nil {
			tx.Rollback()
			log.Printf("Warning: Failed to record migration %d: %v", version, err)
			continue // Skip recording but migration was applied
		}

		// Commit transaction
		if err = tx.Commit(); err != nil {
			log.Printf("Warning: Failed to commit migration %d: %v", version, err)
			continue // Migration may have been applied but not recorded
		}

		log.Printf("Successfully applied migration: %d", version)
	}

	log.Println("Migration execution completed - service will continue regardless of individual migration failures")
}

// MigrationInfo holds information about an applied migration
type MigrationInfo struct {
	Version   string
	AppliedAt time.Time
}

// GetMigrationStatus returns information about applied migrations
func GetMigrationStatus() ([]MigrationInfo, error) {
	if Database == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := Database.Query(`
		SELECT version, applied_at
		FROM schema_migrations
		ORDER BY applied_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query migration status: %w", err)
	}
	defer rows.Close()

	var migrations []MigrationInfo
	for rows.Next() {
		var migration MigrationInfo
		if err := rows.Scan(&migration.Version, &migration.AppliedAt); err != nil {
			return nil, fmt.Errorf("failed to scan migration info: %w", err)
		}
		migrations = append(migrations, migration)
	}

	return migrations, nil
}
