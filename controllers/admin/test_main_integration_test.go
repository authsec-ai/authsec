//go:build integration

package admin

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/authsec-ai/authsec/internal/migration"
	"github.com/google/uuid"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// seededWorkspaceID is kept for backward compat — groups_controller_test.go
// calls skipIfNoSeed(t) which skips when this is uuid.Nil.
var seededWorkspaceID uuid.UUID

// gormDBForTest is the shared GORM connection used by roles_scoped_bindings tests.
var gormDBForTest *gorm.DB

func TestMain(m *testing.M) {
	db, terminate, err := startAdminTestPG()
	if err != nil {
		log.Fatalf("admin integration TestMain: %v", err)
	}
	defer terminate()
	gormDBForTest = db
	os.Exit(m.Run())
}

const (
	adminPGUser     = "authtest"
	adminPGPassword = "authtest"
	adminPGDB       = "authtest"
	adminPGImage    = "postgres:16-alpine"
)

func startAdminTestPG() (*gorm.DB, func(), error) {
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, adminPGImage,
		tcpostgres.WithDatabase(adminPGDB),
		tcpostgres.WithUsername(adminPGUser),
		tcpostgres.WithPassword(adminPGPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("start postgres: %w", err)
	}

	host, err := pg.Host(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("get host: %w", err)
	}
	port, err := pg.MappedPort(ctx, "5432")
	if err != nil {
		return nil, nil, fmt.Errorf("get port: %w", err)
	}
	portStr := port.Port()

	adminDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portStr, adminPGUser, adminPGPassword, adminPGDB)

	migrationsDir := adminRepoMigrationsPath("master")
	if err := adminBuildTemplate(adminDSN, "bootstrap_template", migrationsDir, host, portStr); err != nil {
		return nil, nil, fmt.Errorf("build template: %w", err)
	}

	const workingName = "authtest_work"
	adminDB, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("open admin DB for clone: %w", err)
	}
	_, _ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, workingName))
	if _, err := adminDB.Exec(fmt.Sprintf(`CREATE DATABASE %q TEMPLATE %q`, workingName, "bootstrap_template")); err != nil {
		adminDB.Close()
		return nil, nil, fmt.Errorf("clone working DB: %w", err)
	}
	adminDB.Close()

	workDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portStr, adminPGUser, adminPGPassword, workingName)

	db, err := gorm.Open(pgdriver.Open(workDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("gorm open: %w", err)
	}

	terminate := func() { _ = pg.Terminate(ctx) }
	return db, terminate, nil
}

// adminRepoMigrationsPath resolves migrations/<dbType> from this source file's
// location. Up 2 levels from controllers/admin/ reaches the repo root.
func adminRepoMigrationsPath(dbType string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile) // .../authsec/controllers/admin
	for i := 0; i < 2; i++ {
		dir = filepath.Dir(dir)
	}
	return filepath.Join(dir, "migrations", dbType)
}

// adminBuildTemplate creates the bootstrap_template DB and runs the real
// MasterMigrationRunner against it — same as the production startup path.
func adminBuildTemplate(adminDSN, templateName, migrationsDir, host, portStr string) error {
	rawAdmin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return fmt.Errorf("open admin: %w", err)
	}
	defer rawAdmin.Close()

	_, _ = rawAdmin.Exec(fmt.Sprintf(
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='%s'`, templateName))
	_, _ = rawAdmin.Exec(fmt.Sprintf(`UPDATE pg_database SET datistemplate=false WHERE datname='%s'`, templateName))
	_, _ = rawAdmin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, templateName))
	if _, err := rawAdmin.Exec(fmt.Sprintf(`CREATE DATABASE %q`, templateName)); err != nil {
		return fmt.Errorf("create template DB: %w", err)
	}

	tplDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portStr, adminPGUser, adminPGPassword, templateName)
	rawTpl, err := sql.Open("postgres", tplDSN)
	if err != nil {
		return fmt.Errorf("open template DB: %w", err)
	}
	defer rawTpl.Close()

	gormTpl, err := gorm.Open(pgdriver.Open(tplDSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return fmt.Errorf("gorm template: %w", err)
	}
	if err := migration.AutoMigrateMigrationLogs(gormTpl); err != nil {
		return fmt.Errorf("auto-migrate migration_logs: %w", err)
	}
	runner := migration.NewMasterMigrationRunner(migrationsDir, rawTpl, gormTpl)
	if err := runner.RunMigrations(); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	if _, err := rawAdmin.Exec(fmt.Sprintf(`UPDATE pg_database SET datistemplate=true WHERE datname='%s'`, templateName)); err != nil {
		return fmt.Errorf("mark template: %w", err)
	}
	return nil
}
