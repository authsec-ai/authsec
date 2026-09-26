package migration

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// observationModes is the union of the pre-038 list, 038's additions
// (runtime_batch, configuration_snapshot) and 039's observed.
var observationModes = []string{
	"platform_declared",
	"deployment_declared",
	"invocation_declared",
	"framework_dependency",
	"tool_configuration",
	"secret_reference",
	"identity_grant",
	"audit_event",
	"observed",
	"runtime_batch",
	"configuration_snapshot",
}

// collectorRegistryModeCheck is the iga_observations_mode_chk replace from
// 038_trd2_collector_registry.sql (authsec#61). It adds runtime_batch and
// configuration_snapshot and omits observed. Kept here so this test does not
// depend on 038 being on the branch.
const collectorRegistryModeCheck = `
ALTER TABLE public.iga_observations DROP CONSTRAINT IF EXISTS iga_observations_mode_chk;
ALTER TABLE public.iga_observations ADD CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
    'platform_declared',
    'deployment_declared',
    'invocation_declared',
    'framework_dependency',
    'tool_configuration',
    'secret_reference',
    'identity_grant',
    'audit_event',
    'runtime_batch',
    'configuration_snapshot'));
`

const baselineModeCheck = `
ALTER TABLE public.iga_observations DROP CONSTRAINT IF EXISTS iga_observations_mode_chk;
ALTER TABLE public.iga_observations ADD CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
    'platform_declared',
    'deployment_declared',
    'invocation_declared',
    'framework_dependency',
    'tool_configuration',
    'secret_reference',
    'identity_grant',
    'audit_event'));
`

func TestObservationModesAfterMasterMigrations(t *testing.T) {
	gormDB, sqlDB := prepareModesDB(t)
	dir := masterMigrationsDir(t)

	var dirsyncCol int
	require.NoError(t, sqlDB.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'ad_inventory_cursors' AND column_name = 'dirsync_valid'`).Scan(&dirsyncCol))
	require.Equal(t, 0, dirsyncCol, "039 must not create dirsync_valid")

	ws, integ, scan, obj := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	_, err := sqlDB.Exec(`INSERT INTO workspaces (id, name) VALUES ($1, 'modes')`, ws)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, 'ad', 'dc.authsec.test', 'ad-sync:modes', 'active')`, integ, ws)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status)
		VALUES ($1, $2, $3, 'full', 1, 'succeeded')`, scan, ws, integ)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO iga_source_objects
		(id, workspace_id, integration_id, object_type, recognition_key)
		VALUES ($1, $2, $3, 'user', 'mode-fixture')`, obj, ws, integ)
	require.NoError(t, err)

	insertMode := func(mode, key string) error {
		_, err := sqlDB.Exec(`INSERT INTO iga_observations
			(workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
			VALUES ($1, $2, $3, $4, now(), $5)`, ws, obj, scan, mode, key)
		return err
	}

	for _, mode := range observationModes {
		require.NoError(t, insertMode(mode, "after-039-"+mode), "mode %s", mode)
	}

	// 038 after 039 drops observed. Re-applying 039 must put it back without
	// dropping runtime_batch or configuration_snapshot. Existing observed rows
	// are removed first: Postgres will not install a CHECK that current rows violate.
	_, err = sqlDB.Exec(`DELETE FROM iga_observations`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(collectorRegistryModeCheck)
	require.NoError(t, err)
	require.Error(t, insertMode("observed", "clobbered-observed"))
	require.NoError(t, insertMode("runtime_batch", "after-038-runtime_batch"))
	require.NoError(t, insertMode("configuration_snapshot", "after-038-configuration_snapshot"))

	content, err := os.ReadFile(filepath.Join(dir, "039_ad_inventory.sql"))
	require.NoError(t, err)
	runner := NewMasterMigrationRunner(dir, sqlDB, gormDB)
	require.NoError(t, runner.executeSQLContent(string(content)))
	require.NoError(t, runner.executeSQLContent(string(content)), "039 must be re-runnable")
	require.NoError(t, insertMode("observed", "restored-observed"))
	require.NoError(t, insertMode("runtime_batch", "restored-runtime_batch"))
	require.NoError(t, insertMode("configuration_snapshot", "restored-configuration_snapshot"))

	// The other order: baseline, then 038's narrower list, then 039.
	_, err = sqlDB.Exec(`DELETE FROM iga_observations`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(baselineModeCheck)
	require.NoError(t, err)
	_, err = sqlDB.Exec(collectorRegistryModeCheck)
	require.NoError(t, err)
	require.Error(t, insertMode("observed", "before-039-observed"))
	require.NoError(t, runner.executeSQLContent(string(content)))
	for _, mode := range observationModes {
		require.NoError(t, insertMode(mode, "either-order-"+mode), "mode %s", mode)
	}
}

func prepareModesDB(t *testing.T) (*gorm.DB, *sql.DB) {
	t.Helper()
	host := envOr("DB_HOST", "localhost")
	port := envOr("DB_PORT", "5432")
	user := envOr("DB_USER", "postgres")
	password := envOr("DB_PASSWORD", "postgres")
	adminDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable", host, port, user, password)
	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		t.Skipf("Postgres is not reachable (%v). CI sets DB_HOST, DB_PORT, DB_USER, and DB_PASSWORD; this test applies 001 through 039 and must run there.", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.Ping(); err != nil {
		t.Skipf("Postgres is not reachable (%v). CI sets DB_HOST, DB_PORT, DB_USER, and DB_PASSWORD; this test applies 001 through 039 and must run there.", err)
	}
	const name = "authsec_ad_modes_test"
	_, _ = admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name)
	_, err = admin.Exec("DROP DATABASE IF EXISTS " + name)
	require.NoError(t, err)
	_, err = admin.Exec("CREATE DATABASE " + name)
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, name)
	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := gormDB.DB()
	require.NoError(t, err)
	require.NoError(t, AutoMigrateMigrationLogs(gormDB))
	runner := NewMasterMigrationRunner(masterMigrationsDir(t), sqlDB, gormDB)
	require.NoError(t, runner.RunMigrations())
	return gormDB, sqlDB
}

func masterMigrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "001_bootstrap.sql"))
	require.NoError(t, err)
	return dir
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
