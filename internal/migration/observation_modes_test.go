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

// historicalObservationModes are the modes from 001/004.
var historicalObservationModes = []string{
	"platform_declared",
	"deployment_declared",
	"invocation_declared",
	"framework_dependency",
	"tool_configuration",
	"secret_reference",
	"identity_grant",
	"audit_event",
}

// collectorObservationModes are the modes 038 adds.
var collectorObservationModes = []string{
	"runtime_batch",
	"configuration_snapshot",
}

// adObservationMode is the evidence basis 039 keeps on an AD directory read.
const adObservationMode = "observed"

// discoverySourceKinds is 038's discovery_sources_kind_chk list. 039 must not
// narrow it.
var discoverySourceKinds = []string{
	"k8s_webhook", "aws", "azure", "gcp", "vm_sensor", "repo_scan",
	"linux_collector", "k8s_collector", "node_sensor",
}

// scanRunModes is 038's iga_scan_runs_mode_chk list. full and incremental are
// what the AD inventory writes.
var scanRunModes = []string{
	"full", "incremental", "targeted", "runtime_batch", "configuration_snapshot",
}

func TestObservationModesAfterMasterMigrations(t *testing.T) {
	gormDB, sqlDB := prepareModesDB(t)
	dir := masterMigrationsDir(t)

	var dirsyncCol int
	require.NoError(t, sqlDB.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'ad_inventory_cursors' AND column_name = 'dirsync_valid'`).Scan(&dirsyncCol))
	require.Equal(t, 0, dirsyncCol, "039 must not create dirsync_valid")

	assertVocabulary(t, sqlDB, "after-001-039")
	assertScanRunWorkspaceKey(t, sqlDB)

	// Re-apply the real files. 038 then 039, twice, then 039 then 038.
	body038 := readMigration(t, dir, "038_trd2_collector_registry.sql")
	body039 := readMigration(t, dir, "039_ad_inventory.sql")
	runner := NewMasterMigrationRunner(dir, sqlDB, gormDB)
	reapply := func(label string, files ...string) {
		t.Helper()
		for _, body := range files {
			require.NoError(t, runner.executeSQLContent(body), label)
		}
		assertVocabulary(t, sqlDB, label)
		assertScanRunWorkspaceKey(t, sqlDB)
	}
	reapply("038-then-039-1", body038, body039)
	reapply("038-then-039-2", body038, body039)
	reapply("039-then-038", body039, body038)
}

func assertVocabulary(t *testing.T, db *sql.DB, label string) {
	t.Helper()
	ws := uuid.New()
	_, err := db.Exec(`INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "modes-"+label)
	require.NoError(t, err)

	integ := uuid.New()
	_, err = db.Exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, 'ad', 'dc.authsec.test', $3, 'active')`,
		integ, ws, "ad-sync:"+label)
	require.NoError(t, err, "%s: provider ad", label)

	_, err = db.Exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, 'not-a-provider', 'x', $3, 'active')`,
		uuid.New(), ws, "bad:"+label)
	require.Error(t, err, "%s: provider check must reject an unknown provider", label)

	scan := uuid.New()
	_, err = db.Exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status)
		VALUES ($1, $2, $3, 'full', 1, 'succeeded')`, scan, ws, integ)
	require.NoError(t, err)
	obj := uuid.New()
	_, err = db.Exec(`INSERT INTO iga_source_objects
		(id, workspace_id, integration_id, object_type, recognition_key)
		VALUES ($1, $2, $3, 'user', $4)`, obj, ws, integ, "obj-"+label)
	require.NoError(t, err)

	modes := append(append([]string{}, historicalObservationModes...), collectorObservationModes...)
	modes = append(modes, adObservationMode)
	for _, mode := range modes {
		_, err = db.Exec(`INSERT INTO iga_observations
			(workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
			VALUES ($1, $2, $3, $4, now(), $5)`,
			ws, obj, scan, mode, label+"-"+mode)
		require.NoError(t, err, "%s: observation mode %s", label, mode)
	}
	_, err = db.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
		VALUES ($1, $2, $3, 'not_a_mode', now(), $4)`,
		ws, obj, scan, label+"-bogus")
	require.Error(t, err, "%s: observation check must reject an unknown mode", label)

	for _, kind := range discoverySourceKinds {
		_, err = db.Exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name)
			VALUES ($1, $2, $3, $4)`, uuid.New(), ws, kind, label+"-"+kind)
		require.NoError(t, err, "%s: discovery source kind %s", label, kind)
	}
	_, err = db.Exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name)
		VALUES ($1, $2, 'not_a_kind', $3)`, uuid.New(), ws, label+"-bogus-kind")
	require.Error(t, err, "%s: discovery source check must reject an unknown kind", label)

	for i, mode := range scanRunModes {
		_, err = db.Exec(`INSERT INTO iga_scan_runs
			(id, workspace_id, integration_id, mode, generation, status)
			VALUES ($1, $2, $3, $4, $5, 'succeeded')`,
			uuid.New(), ws, integ, mode, i+2)
		require.NoError(t, err, "%s: scan run mode %s", label, mode)
	}
	_, err = db.Exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status)
		VALUES ($1, $2, $3, 'not_a_mode', 99, 'succeeded')`,
		uuid.New(), ws, integ)
	require.Error(t, err, "%s: scan run check must reject an unknown mode", label)
}

func assertScanRunWorkspaceKey(t *testing.T, db *sql.DB) {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*)
		  FROM pg_constraint c
		  JOIN pg_class r ON r.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		 WHERE n.nspname = 'public'
		   AND r.relname = 'iga_scan_runs'
		   AND c.contype IN ('u', 'p')
		   AND (
		     SELECT array_agg(a.attname::text ORDER BY k.ord)
		       FROM unnest(c.conkey) WITH ORDINALITY AS k(num, ord)
		       JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num
		   ) = ARRAY['workspace_id', 'id']::text[]`).Scan(&n))
	require.Equal(t, 1, n, "iga_scan_runs must have a UNIQUE or PK on exactly (workspace_id, id) for ad_inventory_runs_scan_fkey")

	var fkCols string
	require.NoError(t, db.QueryRow(`
		SELECT (
		  SELECT string_agg(a.attname::text, ',' ORDER BY k.ord)
		    FROM unnest(c.confkey) WITH ORDINALITY AS k(num, ord)
		    JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.num
		)
		  FROM pg_constraint c
		 WHERE c.conname = 'ad_inventory_runs_scan_fkey'`).Scan(&fkCols))
	require.Equal(t, "workspace_id,id", fkCols)
}

func readMigration(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return string(b)
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
