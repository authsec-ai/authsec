package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestA9Migration045LeavesValidationOutsideTheFile locks the deploy shape:
// 045 adds NOT VALID constraints and does not scan or drop 039's keys.
// The validate script does both, and only after VALIDATE.
func TestA9Migration045LeavesValidationOutsideTheFile(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	body, err := os.ReadFile(filepath.Join(root, "migrations", "master", "045_ad_hardening_posture.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if sqlHasValidate(text) {
		t.Fatal("045 must not VALIDATE CONSTRAINT; that scan belongs in scripts/validate-045-ad-hardening.sql")
	}
	if regexp.MustCompile(`(?m)^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;`).Match(body) {
		t.Fatal("045 manages its own transaction")
	}
	for _, name := range []string{
		"sync_configurations_workspace_id_key",
		"ad_inventory_scopes_workspace_id_key",
		"ad_inventory_runs_workspace_id_key",
		"sync_configurations_ad_tracking_mode_chk",
		"ad_inventory_cursors_tracking_mode_chk",
		"ad_inventory_scopes_config_ws_fkey",
		"ad_inventory_runs_config_ws_fkey",
		"ad_directory_instances_config_ws_fkey",
		"ad_inventory_cursors_scope_ws_fkey",
		"ad_directory_posture_run_fkey",
		"ad_directory_posture",
	} {
		if !strings.Contains(text, name) {
			t.Fatalf("045 does not mention %s", name)
		}
	}
	if strings.Contains(text, "DROP CONSTRAINT") {
		t.Fatal("045 must not drop 039's single-column keys")
	}

	script, err := os.ReadFile(filepath.Join(root, "scripts", "validate-045-ad-hardening.sql"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	validateAt := strings.Index(s, "VALIDATE CONSTRAINT")
	dropAt := strings.Index(s, "DROP CONSTRAINT")
	if validateAt < 0 || dropAt < 0 || validateAt > dropAt {
		t.Fatal("the validate script must VALIDATE before it drops the 039 keys")
	}
	for _, old := range []string{
		"ad_inventory_scopes_config_fkey",
		"ad_inventory_runs_config_fkey",
		"ad_directory_instances_config_fkey",
		"ad_inventory_cursors_scope_fkey",
	} {
		if !strings.Contains(s, "DROP CONSTRAINT IF EXISTS "+old) {
			t.Fatalf("validate script does not drop %s", old)
		}
	}
}

func sqlHasValidate(text string) bool {
	return strings.Contains(strings.ToUpper(stripSQLComments(text)), "VALIDATE CONSTRAINT")
}

func stripSQLComments(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
