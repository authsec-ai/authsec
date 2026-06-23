package testsupport

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/authsec-ai/authsec/internal/migration"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// RepoRoot walks up from this source file's location to find the repo root
// (the directory containing go.mod). This resolves migrations/ relative to the
// source tree rather than the temp binary path that os.Executable returns
// under `go test` — fixing the MigrationsDir bug in runner.go:425.
func RepoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile = .../authsec/internal/testsupport/bootstrap.go
	// filepath.Dir gives .../testsupport; go up 2 more: testsupport → internal → authsec
	dir := filepath.Dir(thisFile)
	for i := 0; i < 2; i++ {
		dir = filepath.Dir(dir)
	}
	return dir
}

// MigrationsPath returns the absolute path to migrations/<dbType>/.
func MigrationsPath(dbType string) string {
	return filepath.Join(RepoRoot(), "migrations", dbType)
}

// buildBootstrapTemplate creates a Postgres DB named templateName, runs the
// real MasterMigrationRunner against it (exactly as cmd/main.go does on boot),
// then marks it as a TEMPLATE so nothing can connect to or modify it.
func buildBootstrapTemplate(adminDSN, templateName, migrationsDir, host, port string) error {
	// Step 1: open the admin connection and (re)create the template DB.
	adminDB, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return fmt.Errorf("open admin DB: %w", err)
	}
	defer adminDB.Close()

	// Terminate any connections before dropping.
	_, _ = adminDB.Exec(fmt.Sprintf(
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s'`, templateName,
	))
	_, _ = adminDB.Exec(fmt.Sprintf(`UPDATE pg_database SET datistemplate=false WHERE datname='%s'`, templateName))
	_, _ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, templateName))
	if _, err := adminDB.Exec(fmt.Sprintf(`CREATE DATABASE %q`, templateName)); err != nil {
		return fmt.Errorf("create template DB: %w", err)
	}

	// Step 2: connect to the template DB and run migrations.
	tplDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, pgUser, pgPassword, templateName)

	rawDB, err := sql.Open("postgres", tplDSN)
	if err != nil {
		return fmt.Errorf("open template DB: %w", err)
	}
	defer rawDB.Close()

	gormDB, err := gorm.Open(postgres.Open(tplDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("gorm open template: %w", err)
	}

	if err := migration.AutoMigrateMigrationLogs(gormDB); err != nil {
		return fmt.Errorf("auto-migrate migration_logs: %w", err)
	}

	runner := migration.NewMasterMigrationRunner(migrationsDir, rawDB, gormDB)
	if err := runner.RunMigrations(); err != nil {
		return fmt.Errorf("run master migrations: %w", err)
	}

	// Close BOTH connection pools to the template now. Postgres refuses to clone
	// from a template that has any live session: `CREATE DATABASE ... TEMPLATE x`
	// fails with "source database x is being accessed by other users". gormDB
	// opens its own *sql.DB pool that the `defer rawDB.Close()` above does NOT
	// cover, and the clone runs in the caller AFTER this returns — so an idle
	// gorm pool connection left the template permanently un-cloneable. Close both
	// explicitly here, before the clone. (The defers become harmless double-closes.)
	if sqlDB, derr := gormDB.DB(); derr == nil {
		_ = sqlDB.Close()
	}
	_ = rawDB.Close()

	// Step 3: mark as template so `CREATE DATABASE ... TEMPLATE` works.
	if _, err := adminDB.Exec(fmt.Sprintf(`UPDATE pg_database SET datistemplate=true WHERE datname='%s'`, templateName)); err != nil {
		return fmt.Errorf("mark template: %w", err)
	}

	// Belt-and-suspenders: terminate any straggler backends still attached to the
	// template (e.g. a pool connection that hasn't fully torn down) so the
	// immediate clone in the caller doesn't race them.
	_, _ = adminDB.Exec(fmt.Sprintf(
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()`, templateName,
	))
	return nil
}
