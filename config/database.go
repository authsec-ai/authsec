package config

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/authsec-ai/authsec/database"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// tenantGORMCache caches per-tenant GORM instances keyed by tenant DB name.
// Guarded by tenantGORMMu. In single-tenant mode the cache is never populated.
var (
	tenantGORMCache = map[string]*gorm.DB{}
	tenantGORMMu    sync.RWMutex
)

// Database connection (raw SQL)
var Database *database.DBConnection

// DB is the GORM instance for controllers (migrations disabled)
var DB *gorm.DB

// InitDatabaseWithoutGORM initializes the database connection using the native SQL driver.
// Migrations are NOT run here; call RunStartupMigrations (in main.go) separately.
func InitDatabaseWithoutGORM(cfg *Config) {
	if os.Getenv("SKIP_DB_INIT") == "true" {
		log.Println("Skipping database initialization (SKIP_DB_INIT=true)")
		return
	}

	var err error

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

	log.Println("Database connected successfully")

	// Initialize GORM instance for controllers (auto-migration disabled)
	sslMode := cfg.DBSSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort, sslMode)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:               logger.Default.LogMode(logger.Silent),
		DisableAutomaticPing: false,
	})
	if err != nil {
		log.Fatalf("Failed to initialize GORM: %v", err)
	}

	log.Println("GORM initialized for controllers (AutoMigrate disabled)")
}

// GetDatabase returns the current raw database connection.
func GetDatabase() *database.DBConnection {
	return Database
}

// GetTenantDatabase returns the raw DB connection for a tenant.
// In single-tenant mode (mt-plugin unavailable or tenant has no dedicated DB) it
// returns the master connection. In multi-tenant mode it opens a connection to the
// provisioned tenant database.
func GetTenantDatabase(tenantID string) (*database.DBConnection, error) {
	if tenantID == "" || MTPluginClient == nil || !MTPluginClient.IsAvailable() {
		return Database, nil
	}
	conn, err := database.GetTenantDB(tenantID)
	if err != nil {
		// Tenant DB not provisioned yet — fall back to master gracefully.
		return Database, nil
	}
	return conn, nil
}

// GetTenantGORMDB returns a GORM DB for a tenant.
// Single-tenant mode: always returns the master DB.
// Multi-tenant mode (mt-plugin available): returns a GORM instance pointed at the
// tenant's dedicated database, creating and caching the connection on first use.
// Falls back to master if the tenant DB has not been provisioned yet.
func GetTenantGORMDB(tenantID string) (*gorm.DB, error) {
	if tenantID == "" || MTPluginClient == nil || !MTPluginClient.IsAvailable() {
		return DB, nil
	}

	// Resolve the tenant DB name from master.
	var dbName string
	if err := DB.Raw(
		"SELECT COALESCE(tenant_db,'') FROM tenants WHERE tenant_id::text = ? OR id::text = ? LIMIT 1",
		tenantID, tenantID,
	).Scan(&dbName).Error; err != nil || dbName == "" {
		return DB, nil
	}

	// Fast path: return cached GORM instance.
	tenantGORMMu.RLock()
	if cached, ok := tenantGORMCache[dbName]; ok {
		tenantGORMMu.RUnlock()
		return cached, nil
	}
	tenantGORMMu.RUnlock()

	// Slow path: open and cache a new GORM instance for this tenant DB.
	cfg := AppConfig
	sslMode := cfg.DBSSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, dbName, cfg.DBPort, sslMode,
	)
	gdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:               logger.Default.LogMode(logger.Silent),
		DisableAutomaticPing: false,
	})
	if err != nil {
		log.Printf("[tenantDB] failed to open GORM for tenant %s (db=%s): %v — using master", tenantID, dbName, err)
		return DB, nil
	}

	tenantGORMMu.Lock()
	tenantGORMCache[dbName] = gdb
	tenantGORMMu.Unlock()

	return gdb, nil
}
