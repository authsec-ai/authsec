package config

import (
	"fmt"

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

// Phase E/P0-3: GetTenantDBName + ConnectTenantDB (the per-tenant-database
// model) were deleted. AuthSec runs against exactly one PostgreSQL database
// (config.DB / ConnectGlobalDB); there are no per-tenant DBs to resolve.
