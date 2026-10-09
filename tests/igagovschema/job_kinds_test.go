package igagovschema_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	repositories "github.com/authsec-ai/authsec/repository"
)

// TestGovJobKindsMatch052Check: repositories.GovJobKinds is exactly the
// value list of 052's iga_gov_job.kind CHECK, read back from pg_constraint
// of the schema the real migration runner built -- so a kind the database
// accepts is never missing from the Go list (resolve_unknown was), and the
// Go list never names a kind the database refuses.
func TestGovJobKindsMatch052Check(t *testing.T) {
	db, _ := testDB(t)
	var def string
	if err := db.QueryRow(`SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
	                        WHERE c.conrelid = 'iga_gov_job'::regclass AND c.contype = 'c'
	                          AND c.conname = 'iga_gov_job_kind_check'`).Scan(&def); err != nil {
		t.Fatalf("read iga_gov_job_kind_check: %v", err)
	}
	var fromDB []string
	for _, m := range regexp.MustCompile(`'([a-z_]+)'::text`).FindAllStringSubmatch(def, -1) {
		fromDB = append(fromDB, m[1])
	}
	if len(fromDB) == 0 {
		t.Fatalf("no kinds parsed from %s", def)
	}
	fromGo := append([]string(nil), repositories.GovJobKinds...)
	sort.Strings(fromDB)
	sort.Strings(fromGo)
	if strings.Join(fromDB, ",") != strings.Join(fromGo, ",") {
		t.Fatalf("GovJobKinds differs from 052's CHECK:\n  go: %v\n  db: %v", fromGo, fromDB)
	}
}
