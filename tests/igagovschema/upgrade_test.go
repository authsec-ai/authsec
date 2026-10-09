package igagovschema_test

// SPEC-iga-phase3-policy.md §6.3, "Upgrade over existing rows (synthetic)":
// a database built to 046 (the chain before Phase 3) is given a workspace, its
// admin role and two legacy selector policies in agent_policies; then 047-056
// are applied by the runner. Every table that existed at 046 must keep its
// exact definition (columns, defaults, constraints, indexes, triggers), the
// legacy rows must be byte-identical, and the admin role must receive the four
// new governance permissions. Also: VerifyPolicySchema refuses the 046 schema
// and accepts the upgraded one.
//
// This is not the production-schema rehearsal (a Stage A exit, §13.1).

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/services"
)

const tableFingerprints = `
SELECT c.relname, md5(
  coalesce((SELECT string_agg(a.attname || ' ' || format_type(a.atttypid, a.atttypmod) || ' ' || a.attnotnull || ' ' ||
                              coalesce(pg_get_expr(d.adbin, d.adrelid), ''), ',' ORDER BY a.attnum)
              FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
             WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), '') || '|' ||
  coalesce((SELECT string_agg(conname || ' ' || pg_get_constraintdef(oid), ',' ORDER BY conname)
              FROM pg_constraint WHERE conrelid = c.oid), '') || '|' ||
  coalesce((SELECT string_agg(pg_get_indexdef(indexrelid), ',' ORDER BY indexrelid::regclass::text)
              FROM pg_index WHERE indrelid = c.oid), '') || '|' ||
  coalesce((SELECT string_agg(pg_get_triggerdef(oid), ',' ORDER BY tgname)
              FROM pg_trigger WHERE tgrelid = c.oid AND NOT tgisinternal), ''))
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'migration_logs'
 ORDER BY 1`

func fingerprints(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(tableFingerprints)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var n, h string
		if err := rows.Scan(&n, &h); err != nil {
			t.Fatal(err)
		}
		out[n] = h
	}
	return out
}

func TestPhase3UpgradeOverExistingRows(t *testing.T) {
	testDB(t) // build the package database first, so test order never matters
	dsn := os.Getenv("TEST_DATABASE_URL")

	// The chain before Phase 3: every master file numbered below 047, with
	// 001 cut at its first Phase 3 section. T3.01 APPENDED 047-056's end
	// state to 001 (bootstrap parity), so what precedes that marker is exactly
	// the 046 end state that scripts/bootstrap-parity-check.sh proved at T3.00.
	stage := t.TempDir()
	files, err := filepath.Glob(filepath.Join(migrationsDir(), "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	staged := 0
	for _, f := range files {
		v, err := strconv.Atoi(strings.SplitN(filepath.Base(f), "_", 2)[0])
		if err != nil || v >= phase3First {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if v == 1 {
			const marker = "-- ---- from 047_"
			i := strings.Index(string(body), marker)
			if i < 0 {
				t.Fatalf("001_bootstrap.sql has no %q section", marker)
			}
			body = body[:i]
		}
		if err := os.WriteFile(filepath.Join(stage, filepath.Base(f)), body, 0o600); err != nil {
			t.Fatal(err)
		}
		staged++
	}
	db, g, err := rebuild(dsn, stage, false)
	if err != nil {
		t.Fatalf("build to 046 (%d files): %v", staged, err)
	}
	defer db.Close()

	// IGA_POLICY must refuse this schema, naming what is missing.
	err = services.VerifyPolicySchema(g)
	if err == nil || !strings.Contains(err.Error(), "iga_gov_policy") || !strings.Contains(err.Error(), services.PolicySchemaHead) {
		t.Fatalf("VerifyPolicySchema at 046 = %v; want a refusal naming iga_gov_policy and head %s", err, services.PolicySchemaHead)
	}

	w := newWorld()
	w.id("ws", "admin", "lp1", "lp2")
	s := &step{t: t, x: db, w: w}
	s.exec(`INSERT INTO workspaces (id, name, workspace_type) VALUES ({ws}, 'p3 upgrade', 'team')`)
	s.exec(`INSERT INTO roles (id, name, workspace_id, is_system) VALUES ({admin}, 'admin', {ws}, true)`)
	s.exec(`INSERT INTO agent_policies (id, workspace_id, name, description, selector, desired_state, on_expiry, duration, created_by)
	        VALUES ({lp1}, {ws}, 'quarantine refunds', 'legacy', '{"labels":{"team":"refunds"}}', 'quarantined', 'quarantine', interval '7 days', 'admin@x'),
	               ({lp2}, {ws}, 'revoke batch', '', '{"labels":{"team":"batch"}}', 'active', 'revoke', NULL, 'admin@x')`)
	if s.err != nil {
		t.Fatalf("legacy rows: %s", describe(s.err))
	}
	legacyRows := `SELECT md5(string_agg(t::text, E'\n' ORDER BY t.id)) FROM agent_policies t WHERE workspace_id = {ws}`
	rowsBefore := s.val(legacyRows)
	before := fingerprints(t, db)

	if err := runRunner(db, g, migrationsDir()); err != nil {
		t.Fatalf("apply 047-056 over 046: %v", err)
	}

	after := fingerprints(t, db)
	for name, h := range before {
		if after[name] != h {
			t.Errorf("existing table %s changed definition across 047-056", name)
		}
	}
	added := 0
	for name := range after {
		if _, ok := before[name]; !ok {
			added++
		}
	}
	// 047-056 add 43 tables; 059_tidy_eval_pruned (fix/p3-tidy) one more.
	if added != 44 {
		t.Errorf("047-059 added %d tables, want 44", added)
	}
	if got := s.val(legacyRows); got != rowsBefore {
		t.Errorf("legacy agent_policies rows changed: %s -> %s", rowsBefore, got)
	}
	s.eq("approve,author,emergency,enforce", `SELECT string_agg(p.action, ',' ORDER BY p.action)
	        FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
	       WHERE rp.role_id = {admin} AND p.workspace_id IS NULL AND p.resource = 'governance'
	         AND p.action IN ('author', 'approve', 'enforce', 'emergency')`)
	for _, b := range s.bad {
		t.Error(b)
	}
	if err := services.VerifyPolicySchema(g); err != nil {
		t.Fatalf("VerifyPolicySchema after 047-056: %v", err)
	}
	t.Logf("upgrade: %d existing tables unchanged, %d added, legacy rows identical, admin bound to 4 governance permissions", len(before), added)
}
