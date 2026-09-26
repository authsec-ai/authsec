package collector

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/migration"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestMigration_FreshDatabaseHasCollectorRegistry(t *testing.T) {
	var tables int
	err := db.Raw(`SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN (
			'collector_enrollments','collector_instances','collector_credentials',
			'collector_integrations','collector_batches','collector_snapshots',
			'collector_outbox','workspace_collector_settings')`).Scan(&tables).Error
	if err != nil {
		t.Fatal(err)
	}
	if tables != 8 {
		t.Fatalf("collector tables present: %d", tables)
	}
	var perms int
	err = db.Raw(`SELECT count(*) FROM permissions
		WHERE workspace_id IS NULL AND full_permission_string IN (
			'runtime_policy:read','runtime_policy:write','runtime_policy:approve','runtime_policy:enforce',
			'itdr:triage','itdr:respond')`).Scan(&perms).Error
	if err != nil {
		t.Fatal(err)
	}
	if perms != 6 {
		t.Fatalf("permission seeds %d", perms)
	}
}

func TestMigration_AppliesOnDatabaseAt036WithData(t *testing.T) {
	admin, err := sql.Open("postgres", pg.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	const name = "trd2_at_036"
	_, _ = admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
	_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + name)
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + name)
	})

	dsn := strings.Replace(pg.DSN, "dbname=authtest_work", "dbname="+name, 1)
	gdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	dir := t.TempDir()
	src := testsupport.MigrationsPath("master")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		ver, rest, ok := strings.Cut(e.Name(), "_")
		if !ok || rest == "" {
			continue
		}
		n, err := strconv.Atoi(ver)
		if err != nil || n > 36 {
			continue
		}
		if err := os.Symlink(filepath.Join(src, e.Name()), filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := migration.AutoMigrateMigrationLogs(gdb); err != nil {
		t.Fatal(err)
	}
	runner := migration.NewMasterMigrationRunner(dir, sqlDB, gdb)
	if err := runner.RunMigrations(); err != nil {
		t.Fatalf("migrations through 036: %v", err)
	}

	ws := uuid.New()
	if err := gdb.Exec(`INSERT INTO workspaces
        (id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at)
        VALUES (?,?,NULL,?,'team',?,?,'active',NOW(),NOW())`,
		ws, "pre038", ws, ws.String()+".test", ws.String()+"@test.local").Error; err != nil {
		t.Fatal(err)
	}
	srcRow := models.DiscoverySource{
		ID: uuid.New(), WorkspaceID: ws, Kind: models.DiscoverySourceK8sWebhook,
		DisplayName: "pre-collector", Config: []byte(`{}`), Runtime: []byte(`{}`),
		Enabled: true,
	}
	if err := gdb.Create(&srcRow).Error; err != nil {
		t.Fatal(err)
	}
	agent := models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: ws, Source: models.DiscoverySourceK8sWebhook,
		Fingerprint: "fp-pre", DisplayName: "invoice-worker",
		Metadata: []byte(`{}`), DeploymentOrigin: "unknown", EvidenceMode: "observed",
		Status: "unregistered", RuntimeStatus: "unknown",
	}
	if err := gdb.Create(&agent).Error; err != nil {
		t.Fatal(err)
	}
	integ := models.IGAIntegration{
		ID: uuid.New(), WorkspaceID: ws, Provider: models.ProviderGitHub,
		ProviderHost: "github.example", AppRegistrationID: "app", Status: "active", Version: 1,
		CapabilityProfile: []byte(`{}`), RequestedPermissions: []byte(`{}`), GrantedPermissions: []byte(`{}`),
	}
	if err := gdb.Create(&integ).Error; err != nil {
		t.Fatal(err)
	}
	runID := uuid.New()
	if err := gdb.Exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status, is_authoritative, counters)
		VALUES (?, ?, ?, 'incremental', 1, 'succeeded', false, '{}')`,
		runID, ws, integ.ID).Error; err != nil {
		t.Fatal(err)
	}
	objID := uuid.New()
	if err := gdb.Exec(`INSERT INTO iga_source_objects
		(id, workspace_id, integration_id, object_type, recognition_key, locator, normalized_payload)
		VALUES (?, ?, ?, 'workflow', 'pre-038', '{}', '{}')`,
		objID, ws, integ.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key)
		VALUES (?, ?, ?, 'audit_event', '{}', NOW(), ?)`,
		ws, objID, runID, "pre-038-obs").Error; err != nil {
		t.Fatal(err)
	}
	// 039 may have already widened the check with 'observed' (and any other
	// value). 038 has to apply on top of that without dropping those modes
	// or rejecting the rows.
	if err := gdb.Exec(`ALTER TABLE public.iga_observations DROP CONSTRAINT iga_observations_mode_chk`).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec(`ALTER TABLE public.iga_observations ADD CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
		'platform_declared', 'deployment_declared', 'invocation_declared', 'framework_dependency',
		'tool_configuration', 'secret_reference', 'identity_grant', 'audit_event',
		'observed', 'zz_from_039'))`).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key)
		VALUES (?, ?, ?, 'observed', '{}', NOW(), 'pre-038-observed')`,
		ws, objID, runID).Error; err != nil {
		t.Fatal(err)
	}
	var linuxRejected bool
	if err := gdb.Exec(`INSERT INTO discovery_sources
		(id, workspace_id, kind, display_name, config, runtime)
		VALUES (?, ?, 'linux_collector', 'too-soon', '{}', '{}')`, uuid.New(), ws).Error; err != nil {
		linuxRejected = true
	}
	if !linuxRejected {
		t.Fatal("linux_collector was accepted before migration 038")
	}

	only := t.TempDir()
	mig := filepath.Join(testsupport.MigrationsPath("master"), "038_trd2_collector_registry.sql")
	if err := os.Symlink(mig, filepath.Join(only, "038_trd2_collector_registry.sql")); err != nil {
		t.Fatal(err)
	}
	if err := migration.NewMasterMigrationRunner(only, sqlDB, gdb).RunMigrations(); err != nil {
		t.Fatalf("038 on a database at 036: %v", err)
	}

	var trust string
	if err := gdb.Raw(`SELECT evidence_trust FROM discovered_agents WHERE id = ?`, agent.ID).Scan(&trust).Error; err != nil {
		t.Fatal(err)
	}
	if trust != "unverified_legacy" {
		t.Fatalf("backfill trust %q", trust)
	}
	var gotReceived bool
	if err := gdb.Raw(`SELECT received_at IS NOT NULL FROM iga_observations WHERE dedupe_key = ?`, "pre-038-obs").Scan(&gotReceived).Error; err != nil {
		t.Fatal(err)
	}
	if !gotReceived {
		t.Fatal("received_at was not backfilled")
	}
	if err := gdb.Exec(`INSERT INTO discovery_sources
		(id, workspace_id, kind, display_name, config, runtime)
		VALUES (?, ?, 'linux_collector', 'after-038', '{}', '{}')`, uuid.New(), ws).Error; err != nil {
		t.Fatalf("linux_collector after 038: %v", err)
	}
	if err := gdb.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key, evidence_trust)
		VALUES (?, ?, ?, 'runtime_batch', '{}', NOW(), 'post-038-obs', 'authenticated_collector')`,
		ws, objID, runID).Error; err != nil {
		t.Fatalf("runtime_batch observation: %v", err)
	}
	if err := gdb.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key)
		VALUES (?, ?, ?, 'observed', '{}', NOW(), 'post-038-observed')`,
		ws, objID, runID).Error; err != nil {
		t.Fatalf("observed mode was stripped by 038: %v", err)
	}
	if err := gdb.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key)
		VALUES (?, ?, ?, 'configuration_snapshot', '{}', NOW(), 'post-038-snapshot')`,
		ws, objID, runID).Error; err != nil {
		t.Fatalf("configuration_snapshot observation: %v", err)
	}
	if err := gdb.Exec(`INSERT INTO iga_observations
		(workspace_id, source_object_id, scan_run_id, mode, fact_payload, observed_at, dedupe_key)
		VALUES (?, ?, ?, 'zz_from_039', '{}', NOW(), 'post-038-kept')`,
		ws, objID, runID).Error; err != nil {
		t.Fatalf("038 dropped a mode 039 had already allowed: %v", err)
	}
}
