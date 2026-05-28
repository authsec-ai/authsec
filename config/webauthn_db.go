package config

import (
	"fmt"

	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Global DB connection.
//
// Reads DB connection params from environment with fallbacks that match
// config.LoadConfig() so a fresh .env doesn't accidentally produce
// search_path= (which Postgres interprets as "no schemas" and breaks every
// query against tables in the public schema).
func ConnectGlobalDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		getEnv("DB_HOST", "postgres"),
		getEnv("DB_USER", ""),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", "kloudone_db"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_SCHEMA", "public"),
	)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

// Get tenant's DB name from global DB using tenant_id
func GetTenantDBName(globalDB *gorm.DB, tenantID string) (string, error) {
	var tenant sharedmodels.Tenant
	if err := globalDB.Where("workspace_id = ?", tenantID).First(&tenant).Error; err != nil {
		return "", err
	}
	return tenant.TenantDB, nil
}

// Connect to tenant's DB by db name.
// Same env-fallback behaviour as ConnectGlobalDB; only the dbname is overridden.
func ConnectTenantDB(tenantDB string) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		getEnv("DB_HOST", "postgres"),
		getEnv("DB_USER", ""),
		getEnv("DB_PASSWORD", ""),
		tenantDB,
		getEnv("DB_PORT", "5432"),
		getEnv("DB_SCHEMA", "public"),
	)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}
