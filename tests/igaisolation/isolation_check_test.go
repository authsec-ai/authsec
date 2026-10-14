// Package igaisolation_test proves scripts/ci-iga-isolation-check.sh both
// ways (fix/p3-tidy item 7): it passes on this tree, and it FAILS on each
// planted violation -- including the ones the old file-name scope could not
// see (a file in internal/igagov, a reader whose file name is not iga_*),
// a write to a read-only shared table and a query split across lines --
// while CTEs, alias.column, function calls and comments stay clean.
package igaisolation_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func script(t *testing.T) (bash, path string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not found")
	}
	path, err = filepath.Abs(filepath.Join("..", "..", "scripts", "ci-iga-isolation-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return bash, path
}

func run(t *testing.T, root string) (int, string) {
	t.Helper()
	bash, path := script(t)
	cmd := exec.Command(bash, path)
	if root != "" {
		cmd.Env = append(os.Environ(), "IGA_ISOLATION_ROOT="+root)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	return code, string(out)
}

func TestIsolationCheckPassesOnThisTree(t *testing.T) {
	if code, out := run(t, ""); code != 0 {
		t.Fatalf("the check fails on this tree (exit %d):\n%s", code, out)
	}
}

func plant(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestIsolationCheckFailsOnPlantedViolations(t *testing.T) {
	const clean = "package igagov\n\nconst ok = `SELECT id FROM iga_gov_policy WHERE workspace_id = $1`\n"
	cases := []struct {
		name, file, body, want string
	}{
		{"IGA package naming a legacy table (not scanned by file name before)",
			"internal/igagov/planted.go", "package igagov\n\nconst q = `SELECT name FROM workspaces WHERE id = $1`\n",
			"internal/igagov/planted.go names non-IGA table 'workspaces'"},
		{"a reader of iga_* whose file name is not iga_* (content scope)",
			"services/role_reader.go", "package services\n\nconst q = `SELECT i.id FROM iga_identity_accounts i JOIN role_bindings rb ON rb.id = i.id`\n",
			"services/role_reader.go names non-IGA table 'role_bindings'"},
		{"a write to a read-only shared table",
			"services/iga_gov_planted.go", "package services\n\nconst q = `UPDATE cloud_connector SET status = 'error' WHERE id = $1`\n",
			"services/iga_gov_planted.go writes 'cloud_connector'"},
		{"a query split across lines",
			"internal/igaread/planted.go", "package igaread\n\nconst q = `SELECT 1\n\t\tFROM\n\t\t\tentitlement_provenance e`\n",
			"internal/igaread/planted.go names non-IGA table 'entitlement_provenance'"},
		{"gorm .Table on a legacy table",
			"internal/igagraph/planted.go", "package igagraph\n\nfunc f(db interface{ Table(string) }) { db.Table(\"agent_policies\") }\n",
			"internal/igagraph/planted.go names non-IGA table 'agent_policies'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := plant(t, map[string]string{"internal/igagov/clean.go": clean, c.file: c.body})
			code, out := run(t, root)
			if code == 0 || !strings.Contains(out, "FAIL: "+c.want) {
				t.Fatalf("exit %d, want a failure naming %q:\n%s", code, c.want, out)
			}
		})
	}

	// Not violations: the file's own CTEs (plain, with a column list, from
	// the igaread builder), alias.column after FROM, function calls,
	// comments, allowlisted reads and an allowlisted write.
	root := plant(t, map[string]string{
		"internal/igagov/clean.go": clean,
		"internal/igaread/ok.go": "package igaread\n\n" +
			"// A comment naming FROM workspaces is prose, not a query.\n" +
			"const a = `WITH lanes(connector_id) AS (VALUES (1)), picked AS MATERIALIZED (SELECT 1) SELECT * FROM lanes JOIN picked ON true`\n" +
			"const b = `SELECT extract(epoch FROM sup.last_confirmed_at) FROM iga_object_support sup, jsonb_each(x) LEFT JOIN LATERAL unnest(y) ON true`\n" +
			"const c = `SELECT u.name FROM iga_gov_owner o JOIN users u ON u.id = o.user_id JOIN cloud_connector c ON true`\n" +
			"func g(u interface{ addWith(string, string) }) { u.addWith(`changes_naming`, `SELECT 1`); _ = `SELECT * FROM changes_naming` }\n",
		"services/cloud_enforcement_binding_service.go": "package services\n\nconst w = `UPDATE cloud_enforcement_binding SET state = 'revoked' FROM iga_gov_artifact a`\n",
	})
	if code, out := run(t, root); code != 0 {
		t.Fatalf("clean tree fails (exit %d):\n%s", code, out)
	}
}
