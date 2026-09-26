// Package testdb opens a dedicated Postgres database and applies master
// migrations for tests. CI's go test ./... runs before migrations, against an
// empty authsec database, so tests that need the schema must migrate their own.
package testdb

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"

	"github.com/authsec-ai/authsec/internal/migration"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ErrUnreachable means DB_HOST is unset or Postgres refused the connection.
// Callers should skip with a message that CI is expected to run the test.
var ErrUnreachable = errors.New("postgres is not reachable")

var (
	dbNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	mu            sync.Mutex
	cached        = map[string]*gorm.DB{}
)

// Prepare creates dbName if needed, applies master migrations when the users
// table is missing, and returns a GORM handle. recreate drops the database
// first so the current migration files are applied from scratch.
func Prepare(dbName string, recreate bool) (*gorm.DB, error) {
	if !dbNamePattern.MatchString(dbName) {
		return nil, fmt.Errorf("invalid database name %q", dbName)
	}
	mu.Lock()
	defer mu.Unlock()
	if recreate {
		if old, ok := cached[dbName]; ok {
			if sqlDB, err := old.DB(); err == nil {
				_ = sqlDB.Close()
			}
			delete(cached, dbName)
		}
	} else if db, ok := cached[dbName]; ok {
		return db, nil
	}

	admin, err := open("postgres")
	if err != nil {
		return nil, err
	}
	defer admin.Close()

	if recreate {
		_, _ = admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, dbName)
		if _, err := admin.Exec("DROP DATABASE IF EXISTS " + dbName); err != nil {
			return nil, fmt.Errorf("drop database %s: %w", dbName, err)
		}
	}
	var exists bool
	if err := admin.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		if _, err := admin.Exec("CREATE DATABASE " + dbName); err != nil {
			return nil, fmt.Errorf("create database %s: %w", dbName, err)
		}
	}

	gormDB, err := gorm.Open(postgres.Open(dsn(dbName)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, err
	}
	var users bool
	if err := sqlDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users')`).Scan(&users); err != nil {
		return nil, err
	}
	if recreate || !users {
		if err := migrate(gormDB, sqlDB); err != nil {
			return nil, err
		}
	}
	cached[dbName] = gormDB
	return gormDB, nil
}

func migrate(gormDB *gorm.DB, sqlDB *sql.DB) error {
	if err := migration.AutoMigrateMigrationLogs(gormDB); err != nil {
		return fmt.Errorf("migration_logs: %w", err)
	}
	dir, err := MasterMigrationsDir()
	if err != nil {
		return err
	}
	runner := migration.NewMasterMigrationRunner(dir, sqlDB, gormDB)
	if err := runner.RunMigrations(); err != nil {
		return fmt.Errorf("master migrations: %w", err)
	}
	return nil
}

// MasterMigrationsDir is migrations/master, found from this source file so the
// path does not depend on the test's working directory.
func MasterMigrationsDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate testdb source")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "migrations", "master"))
	st, err := os.Stat(filepath.Join(dir, "001_bootstrap.sql"))
	if err != nil || st.IsDir() {
		return "", fmt.Errorf("master migrations not found at %s", dir)
	}
	return dir, nil
}

func open(dbName string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn(dbName))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return db, nil
}

func dsn(dbName string) string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("DB_HOST", "localhost"),
		env("DB_PORT", "5432"),
		env("DB_USER", "postgres"),
		env("DB_PASSWORD", "postgres"),
		dbName,
	)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
