package integration

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestTRD2ITA9DirectoryPostureMigration is the evidence-path proof for 045.
// It rebuilds private databases so it does not disturb the shared authsec DB
// the rest of the evidence job uses. It skips when IGA_TEST_DSN is unset.
func TestTRD2ITA9DirectoryPostureMigration(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}

	// These subtests apply migration files themselves so each order is explicit.
	t.Run("fresh_without_041", func(t *testing.T) {
		db := openFreshDB(t, dsn, "a9_fresh_045")
		applyMasterWhere(t, db, func(base string) bool { return true })
		applyFile(t, db, masterPath(t, "045_ad_hardening_posture.sql"))
		if n := scalarDB(t, db, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'discovered_agent_workloads'`); n != 1 {
			t.Fatal("real 042 did not apply")
		}
		if n := scalarDB(t, db, `SELECT count(*) FROM pg_constraint WHERE conname = 'ad_directory_posture_run_fkey'`); n != 1 {
			t.Fatalf("posture fk count = %d", n)
		}
		if n := scalarDB(t, db, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'ad_directory_posture' AND column_name = 'protected_users'`); n != 1 {
			t.Fatal("protected_users column missing")
		}
		if n := scalarDB(t, db, `SELECT count(*) FROM pg_constraint WHERE conname = 'ad_inventory_scopes_config_fkey'`); n != 1 {
			t.Fatalf("039 scope fk should still exist before the validate script, count = %d", n)
		}
		if constraintValidated(t, db, "ad_inventory_scopes_config_ws_fkey") {
			t.Fatal("composite fk was validated inside 045")
		}
	})

	t.Run("with_placeholder_041", func(t *testing.T) {
		dir := t.TempDir()
		p041 := filepath.Join(dir, "041_placeholder.sql")
		if err := os.WriteFile(p041, []byte("SELECT 1;\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// A placeholder stands in for 041 so this order does not run the real
		// runtime migration. 042 is the real A5 migration.
		db := openFreshDB(t, dsn, "a9_mid_041")
		applyMasterWhere(t, db, func(base string) bool { return base < "041" })
		applyFile(t, db, p041)
		applyMasterWhere(t, db, func(base string) bool { return base >= "042" })
		if n := scalarDB(t, db, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'discovered_agent_workloads'`); n != 1 {
			t.Fatal("real 042 did not apply after placeholder 041")
		}
		if n := scalarDB(t, db, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'ad_directory_posture'`); n != 1 {
			t.Fatal("045 did not apply after placeholder 041 and real 042")
		}
		if n := scalarDB(t, db, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'ad_directory_posture' AND column_name = 'protected_users'`); n != 1 {
			t.Fatal("protected_users column missing after 041 then 042 and 045")
		}
	})

	t.Run("prod_shaped_at_040", func(t *testing.T) {
		db := openFreshDB(t, dsn, "a9_prod_040")
		applyMasterWhere(t, db, func(base string) bool { return base < "041" })
		seedProdAD(t, db)
		before := adDigest(t, db)
		if n := scalarDB(t, db, `SELECT count(*) FROM sync_configurations WHERE ad_tracking_mode IS DISTINCT FROM 'usn'`); n != 0 {
			t.Fatalf("tracking modes before 045: %d not usn", n)
		}
		applyFile(t, db, masterPath(t, "045_ad_hardening_posture.sql"))
		if got := adDigest(t, db); got != before {
			t.Fatalf("045 changed existing AD rows\nbefore %s\nafter  %s", before, got)
		}
		applyFile(t, db, masterPath(t, "045_ad_hardening_posture.sql"))
		if got := adDigest(t, db); got != before {
			t.Fatalf("second 045 changed existing AD rows\nbefore %s\nafter  %s", before, got)
		}
		if n := scalarDB(t, db, `SELECT count(*) FROM ad_inventory_cursors WHERE tracking_mode IS DISTINCT FROM 'usn'`); n != 0 {
			t.Fatalf("cursor modes after 045: %d not usn", n)
		}

		wsA, wsB, cfgA, cfgB, scopeB, runA, runB := prodIDs(t, db)
		_ = wsB
		err := execErr(db, `INSERT INTO sync_configurations
			(id, workspace_id, client_id, sync_type, config_name, ad_tracking_mode)
			VALUES ($1, $2, $3, 'active_directory', 'dirsync-rejected', 'dirsync')`,
			uuid.New(), wsA, uuid.New())
		wantState(t, err, "23514", "sync_configurations_ad_tracking_mode_chk")

		err = execErr(db, `INSERT INTO ad_inventory_scopes (id, workspace_id, sync_config_id, base_dn)
			VALUES ($1, $2, $3, 'DC=foreign')`, uuid.New(), wsA, cfgB)
		wantState(t, err, "23503", "ad_inventory_scopes_config_ws_fkey")

		err = execErr(db, `INSERT INTO ad_inventory_cursors (workspace_id, scope_id, tracking_mode)
			VALUES ($1, $2, 'usn')`, wsA, scopeB)
		wantState(t, err, "23503", "ad_inventory_cursors_scope_ws_fkey")

		err = execErr(db, `INSERT INTO ad_inventory_runs (id, workspace_id, sync_config_id, status, mode)
			VALUES ($1, $2, $3, 'succeeded', 'full')`, uuid.New(), wsA, cfgB)
		wantState(t, err, "23503", "ad_inventory_runs_config_ws_fkey")

		err = execErr(db, `INSERT INTO ad_directory_instances (id, workspace_id, sync_config_id, forest_id)
			VALUES ($1, $2, $3, 'DC=foreign')`, uuid.New(), wsA, cfgB)
		wantState(t, err, "23503", "ad_directory_instances_config_ws_fkey")

		err = execErr(db, `INSERT INTO ad_directory_posture (workspace_id, run_id, object_guid, account_kind, coverage)
			VALUES ($1, $2, 'foreign-run', 'ad_user', 'complete')`, wsA, runB)
		wantState(t, err, "23503", "ad_directory_posture_run_fkey")

		err = execErr(db, `INSERT INTO ad_directory_posture
			(workspace_id, run_id, object_guid, account_kind, coverage, privileged)
			VALUES ($1, $2, 'neg-priv', 'ad_user', 'partial', false)`, wsA, runA)
		wantState(t, err, "23514", "ad_directory_posture_privileged_chk")

		err = execErr(db, `INSERT INTO ad_directory_posture
			(workspace_id, run_id, object_guid, account_kind, coverage, admin_count_orphan)
			VALUES ($1, $2, 'neg-orphan', 'ad_user', 'partial', true)`, wsA, runA)
		wantState(t, err, "23514", "ad_directory_posture_orphan_chk")

		execDB(t, db, `INSERT INTO ad_directory_posture
			(workspace_id, run_id, object_guid, account_kind, coverage, privileged)
			VALUES ($1, $2, 'partial-null', 'ad_user', 'partial', NULL)`, wsA, runA)
		execDB(t, db, `INSERT INTO ad_directory_posture
			(workspace_id, run_id, object_guid, account_kind, coverage, privileged)
			VALUES ($1, $2, 'partial-true', 'ad_user', 'partial', true)`, wsA, runA)
		execDB(t, db, `INSERT INTO ad_directory_posture
			(workspace_id, run_id, object_guid, account_kind, coverage, privileged, admin_count_orphan)
			VALUES ($1, $2, 'complete-false', 'ad_user', 'complete', false, true)`, wsA, runA)

		assertAutocommit(t, db)
		body, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "validate-045-ad-hardening.sql"))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range sqlStatements(string(body)) {
			assertAutocommit(t, db)
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("validate statement: %v\n%s", err, stmt)
			}
			assertAutocommit(t, db)
		}
		for _, name := range []string{
			"sync_configurations_ad_tracking_mode_chk",
			"ad_inventory_cursors_tracking_mode_chk",
			"ad_inventory_scopes_config_ws_fkey",
			"ad_inventory_runs_config_ws_fkey",
			"ad_directory_instances_config_ws_fkey",
			"ad_inventory_cursors_scope_ws_fkey",
			"ad_directory_posture_run_fkey",
		} {
			if !constraintValidated(t, db, name) {
				t.Fatalf("%s is not validated", name)
			}
		}
		for _, old := range []string{
			"ad_inventory_scopes_config_fkey",
			"ad_inventory_runs_config_fkey",
			"ad_directory_instances_config_fkey",
			"ad_inventory_cursors_scope_fkey",
		} {
			if n := scalarDB(t, db, `SELECT count(*) FROM pg_constraint WHERE conname = $1`, old); n != 0 {
				t.Fatalf("%s still exists after the validate script", old)
			}
		}
		err = execErr(db, `INSERT INTO ad_inventory_scopes (id, workspace_id, sync_config_id, base_dn)
			VALUES ($1, $2, $3, 'DC=foreign-after')`, uuid.New(), wsA, cfgB)
		wantState(t, err, "23503", "ad_inventory_scopes_config_ws_fkey")
		execDB(t, db, `INSERT INTO ad_inventory_scopes (id, workspace_id, sync_config_id, base_dn)
			VALUES ($1, $2, $3, 'DC=same-after')`, uuid.New(), wsA, cfgA)
	})
}

func applyMasterWhere(t *testing.T, db *sql.DB, keep func(base string) bool) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "migrations", "master")
	files, err := filepath.Glob(filepath.Join(dir, "0*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	for _, f := range files {
		if keep(filepath.Base(f)) {
			applyFile(t, db, f)
		}
	}
}

func masterPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "migrations", "master", name)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func seedProdAD(t *testing.T, db *sql.DB) {
	t.Helper()
	wsA, wsB := uuid.New(), uuid.New()
	cfgA, cfgB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	runA, runB := uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, 'ws-a'), ($2, 'ws-b')`, wsA, wsB)
	execDB(t, db, `INSERT INTO sync_configurations
		(id, workspace_id, client_id, sync_type, config_name, ad_tracking_mode)
		VALUES ($1, $2, $3, 'active_directory', 'ad-a', 'usn'),
		       ($4, $5, $6, 'active_directory', 'ad-b', 'usn')`,
		cfgA, wsA, uuid.New(), cfgB, wsB, uuid.New())
	execDB(t, db, `INSERT INTO ad_inventory_scopes (id, workspace_id, sync_config_id, base_dn)
		VALUES ($1, $2, $3, 'DC=a'), ($4, $5, $6, 'DC=b')`,
		scopeA, wsA, cfgA, scopeB, wsB, cfgB)
	execDB(t, db, `INSERT INTO ad_inventory_cursors (workspace_id, scope_id, invocation_id, highest_usn, tracking_mode)
		VALUES ($1, $2, 'dc-a', 42, 'usn')`, wsA, scopeA)
	execDB(t, db, `INSERT INTO ad_inventory_runs (id, workspace_id, sync_config_id, status, mode)
		VALUES ($1, $2, $3, 'succeeded', 'full'), ($4, $5, $6, 'succeeded', 'full')`,
		runA, wsA, cfgA, runB, wsB, cfgB)
	execDB(t, db, `INSERT INTO ad_directory_instances (id, workspace_id, sync_config_id, forest_id, domain_sid)
		VALUES ($1, $2, $3, 'DC=a', 'S-1-5-21-1-2-3')`, uuid.New(), wsA, cfgA)
}

func prodIDs(t *testing.T, db *sql.DB) (wsA, wsB, cfgA, cfgB, scopeB, runA, runB uuid.UUID) {
	t.Helper()
	err := db.QueryRow(`SELECT id FROM workspaces WHERE name = 'ws-a'`).Scan(&wsA)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM workspaces WHERE name = 'ws-b'`).Scan(&wsB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM sync_configurations WHERE config_name = 'ad-a'`).Scan(&cfgA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM sync_configurations WHERE config_name = 'ad-b'`).Scan(&cfgB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM ad_inventory_scopes WHERE base_dn = 'DC=b'`).Scan(&scopeB); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM ad_inventory_runs WHERE sync_config_id = $1`, cfgA).Scan(&runA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM ad_inventory_runs WHERE sync_config_id = $1`, cfgB).Scan(&runB); err != nil {
		t.Fatal(err)
	}
	return wsA, wsB, cfgA, cfgB, scopeB, runA, runB
}

func adDigest(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`
		SELECT line FROM (
			SELECT 'cfg|' || id::text || '|' || workspace_id::text || '|' || ad_tracking_mode || '|' || config_name AS line
			  FROM sync_configurations
			UNION ALL
			SELECT 'scope|' || id::text || '|' || workspace_id::text || '|' || sync_config_id::text || '|' || base_dn
			  FROM ad_inventory_scopes
			UNION ALL
			SELECT 'cur|' || workspace_id::text || '|' || scope_id::text || '|' || tracking_mode || '|' || highest_usn::text
			  FROM ad_inventory_cursors
			UNION ALL
			SELECT 'run|' || id::text || '|' || workspace_id::text || '|' || sync_config_id::text || '|' || status || '|' || mode
			  FROM ad_inventory_runs
			UNION ALL
			SELECT 'inst|' || id::text || '|' || workspace_id::text || '|' || sync_config_id::text || '|' || forest_id || '|' || domain_sid
			  FROM ad_directory_instances
		) q ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func execErr(db *sql.DB, q string, args ...any) error {
	_, err := db.Exec(q, args...)
	return err
}

func wantState(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		t.Fatalf("want %s from %s, got %v", code, constraint, err)
	}
	if string(pe.Code) != code || pe.ConstraintName != constraint {
		t.Fatalf("want %s from %s, got %s from %q: %s", code, constraint, pe.Code, pe.ConstraintName, pe.Message)
	}
}

func assertAutocommit(t *testing.T, db *sql.DB) {
	t.Helper()
	var txid sql.NullInt64
	if err := db.QueryRow(`SELECT txid_current_if_assigned()`).Scan(&txid); err != nil {
		t.Fatal(err)
	}
	if txid.Valid {
		t.Fatalf("connection is inside transaction %d", txid.Int64)
	}
}

func sqlStatements(body string) []string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	var out []string
	for _, part := range strings.Split(b.String(), ";") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
