// Package igagovschema_test executes the Phase 3 schema proofs of
// SPEC-iga-phase3-policy.md §6.3 against REAL POSTGRES: the DB1-DB143 probe
// table, the "one complete path across two accounts" journey with its
// final-row checkpoint, the synthetic upgrade over existing rows, and the
// T3.02 schema verification (VerifyPolicySchema).
//
// It proves the SCHEMA only -- which states 047-056 accept and which they
// refuse, by constraint or trigger name. No Go service, worker, AWS call or UI
// is exercised; those are proved by §14.
//
// Set TEST_DATABASE_URL to a scratch database whose public schema may be
// dropped and rebuilt:
//
//	TEST_DATABASE_URL="host=localhost port=55433 user=authsec password=... dbname=p3s_test sslmode=disable" \
//	    go test -count=1 -p 1 ./tests/igagovschema/...
//
// The schema is built by the REAL migration runner (internal/migration), as
// cmd/main.go does on boot: GORM creates migration_logs, then every file of
// migrations/master runs in its own transaction, split by the runner's own
// statement splitter -- so a $$ body, trigger or DO block the splitter cut in
// the wrong place fails here, not in production. 047-056 are then applied a
// second time (the §6.1 re-run rule). Unset, the suite skips.
package igagovschema_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/migration"
)

// The Phase 3 block (§6.1). Renumbered from the spec's original 044-053 as a
// unit when 044-046 landed first.
const (
	phase3First = 47
	phase3Last  = 56
)

var (
	buildOnce sync.Once
	buildErr  error
	sharedDB  *sql.DB
	sharedORM *gorm.DB
)

func migrationsDir() string {
	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master"))
	if err != nil {
		panic(err)
	}
	return dir
}

// testDB returns the database rebuilt to 056 (once per package run).
func testDB(t *testing.T) (*sql.DB, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Phase 3 schema probes")
	}
	buildOnce.Do(func() { sharedDB, sharedORM, buildErr = rebuild(dsn, migrationsDir(), true) })
	if buildErr != nil {
		t.Fatalf("build schema: %v", buildErr)
	}
	return sharedDB, sharedORM
}

// rebuild drops public and applies every file in dir with the real runner.
// rerunPhase3 forgets 047-056 in migration_logs and runs the runner again,
// which must succeed and is what "applying 047-056 twice succeeds" means.
func rebuild(dsn, dir string, rerunPhase3 bool) (*sql.DB, *gorm.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, nil, err
	}
	for _, s := range []string{"DROP SCHEMA IF EXISTS public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Exec(s); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", s, err)
		}
	}
	// Its own pool, as cmd/main.go and scripts/bootstrap-parity have it: GORM
	// (pgx) for migration_logs, database/sql (lib/pq) for the files.
	g, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, nil, err
	}
	if err := runRunner(db, g, dir); err != nil {
		return nil, nil, err
	}
	if rerunPhase3 {
		if _, err := db.Exec(`DELETE FROM migration_logs WHERE version BETWEEN $1 AND $2`, phase3First, phase3Last); err != nil {
			return nil, nil, err
		}
		if err := runRunner(db, g, dir); err != nil {
			return nil, nil, fmt.Errorf("second application of 047-056: %w", err)
		}
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM migration_logs WHERE version BETWEEN $1 AND $2 AND success`, phase3First, phase3Last).Scan(&n); err != nil {
			return nil, nil, err
		}
		// The first pass's rows were deleted above, so every row now is the
		// second pass's own record of executing the file again.
		if n != phase3Last-phase3First+1 {
			return nil, nil, fmt.Errorf("expected the second pass to re-execute all of 047-056, found %d migration_logs rows", n)
		}
	}
	return db, g, nil
}

func runRunner(db *sql.DB, g *gorm.DB, dir string) error {
	prev := log.Writer()
	log.SetOutput(io.Discard) // the runner logs every file; keep test output readable
	defer log.SetOutput(prev)
	if err := migration.AutoMigrateMigrationLogs(g); err != nil {
		return err
	}
	if err := migration.NewMasterMigrationRunner(dir, db, g).RunMigrations(); err != nil {
		return err
	}
	var failed int
	if err := db.QueryRow(`SELECT count(*) FROM migration_logs WHERE NOT success`).Scan(&failed); err != nil {
		return err
	}
	if failed > 0 {
		var msg string
		_ = db.QueryRow(`SELECT error_msg FROM migration_logs WHERE NOT success ORDER BY executed_at DESC LIMIT 1`).Scan(&msg)
		return fmt.Errorf("%d failed migration(s): %s", failed, msg)
	}
	return nil
}

/* ------------------------------ named values ------------------------------ */

// world names every fixture value. SQL text refers to them as {name}; the
// substitution renders a uuid as 'uuid'::uuid and a document as its
// 'sha256:...' hash, so probe statements read like the spec's table.
type world struct {
	vals map[string]string
}

func newWorld() *world { return &world{vals: map[string]string{}} }

// id declares fresh uuids.
func (w *world) id(names ...string) {
	for _, n := range names {
		if _, dup := w.vals[n]; dup {
			panic("duplicate fixture name " + n)
		}
		w.vals[n] = "'" + uuid.NewString() + "'::uuid"
	}
}

// doc declares a canonical document; {name} is its hash and {name.c} its text.
func (w *world) doc(name, canonical string) {
	w.vals[name] = "'" + hashOf(canonical) + "'"
	w.vals[name+".c"] = "'" + strings.ReplaceAll(canonical, "'", "''") + "'"
}

func hashOf(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var tokenRE = regexp.MustCompile(`\{([a-zA-Z0-9_.]+)\}`)

func (w *world) sql(q string) string {
	return tokenRE.ReplaceAllStringFunc(q, func(m string) string {
		v, ok := w.vals[m[1:len(m)-1]]
		if !ok {
			panic("unknown fixture token " + m + " in: " + q)
		}
		return v
	})
}

/* -------------------------------- statements ------------------------------ */

// execer is a *sql.Tx or *sql.DB.
type execer interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

// step runs statements in order and keeps the FIRST database error; once an
// error is recorded, later statements are skipped, exactly like a transaction
// that would abort there. Harness problems (a wrong row count in a
// compare-and-swap) are recorded separately and fail the test.
type step struct {
	t   *testing.T
	x   execer
	w   *world
	err error
	bad []string
}

func (s *step) exec(q string) {
	if s.err != nil {
		return
	}
	_, s.err = s.x.Exec(s.w.sql(q))
}

// rows runs a statement that must affect exactly n rows (a compare-and-swap
// that must win, or must lose with 0).
func (s *step) rows(n int64, q string) {
	if s.err != nil {
		return
	}
	res, err := s.x.Exec(s.w.sql(q))
	if err != nil {
		s.err = err
		return
	}
	if got, _ := res.RowsAffected(); got != n {
		s.bad = append(s.bad, fmt.Sprintf("expected %d row(s), got %d: %s", n, got, q))
	}
}

// val reads one value as text ("" for NULL).
func (s *step) val(q string) string {
	var v sql.NullString
	if err := s.x.QueryRow(s.w.sql(q)).Scan(&v); err != nil {
		s.bad = append(s.bad, fmt.Sprintf("query failed: %v: %s", err, q))
		return ""
	}
	return v.String
}

// eq asserts one value.
func (s *step) eq(want, q string) {
	if got := s.val(q); got != want {
		s.bad = append(s.bad, fmt.Sprintf("got %q, want %q: %s", got, want, q))
	}
}

/* --------------------------------- outcomes ------------------------------- */

// outcome is what a probe expects: accepted, or one specific refusal.
type outcome struct {
	accepted bool
	code     string // SQLSTATE
	name     string // constraint / index name, NOT NULL column, generated column, or trigger function
	msg      string // trigger only: a substring of the RAISE message, when one function raises for several reasons
	label    string
}

func accepted() outcome { return outcome{accepted: true, label: "accepted"} }
func checkViolation(c string) outcome {
	return outcome{code: "23514", name: c, label: "CHECK violation " + c}
}
func fkViolation(c string) outcome {
	return outcome{code: "23503", name: c, label: "FK violation " + c}
}
func uniqueViolation(c string) outcome {
	return outcome{code: "23505", name: c, label: "unique violation " + c}
}
func notNullViolation(col string) outcome {
	return outcome{code: "23502", name: col, label: "NOT NULL violation on " + col}
}

// triggerException names the PL/pgSQL function that raised (pq reports it in
// Where: "PL/pgSQL function <fn>() line N at RAISE").
func triggerException(fn string) outcome {
	return outcome{code: "P0001", name: fn, label: "trigger exception in " + fn + "()"}
}
func generatedColumn(col string) outcome {
	return outcome{code: "428C9", name: col, label: "generated-column error on " + col}
}

// match says whether err is exactly the expected refusal.
func (o outcome) match(err error) (bool, string) {
	if o.accepted {
		if err == nil {
			return true, ""
		}
		return false, "refused: " + describe(err)
	}
	if err == nil {
		return false, "accepted, want " + o.label
	}
	var pe *pq.Error
	if !errors.As(err, &pe) {
		return false, "non-PostgreSQL error: " + err.Error()
	}
	if string(pe.Code) != o.code {
		return false, "got " + describe(err)
	}
	switch o.code {
	case "23514", "23503", "23505":
		if pe.Constraint != o.name {
			return false, "got " + describe(err)
		}
	case "23502":
		if pe.Column != o.name {
			return false, "got " + describe(err)
		}
	case "P0001":
		if !strings.Contains(pe.Where, "PL/pgSQL function "+o.name+"(") || !strings.Contains(pe.Message, o.msg) {
			return false, "got " + describe(err)
		}
	case "428C9":
		if !strings.Contains(pe.Message, `"`+o.name+`"`) {
			return false, "got " + describe(err)
		}
	}
	return true, ""
}

func describe(err error) string {
	var pe *pq.Error
	if errors.As(err, &pe) {
		return fmt.Sprintf("SQLSTATE %s constraint=%q column=%q where=%q: %s",
			pe.Code, pe.Constraint, pe.Column, pe.Where, pe.Message)
	}
	return err.Error()
}

// The Phase 3 constraints that are DEFERRABLE INITIALLY DEFERRED. After each
// accepted probe the harness forces them (SET CONSTRAINTS ALL IMMEDIATE, so a
// violation surfaces in THAT probe) and then restores exactly these to
// deferred, leaving every other constraint's mode untouched.
const deferredPhase3 = "iga_gov_policy_current_version_fk, iga_gov_pd_recovered_by_fk, iga_gov_pd_recovers_fk"
