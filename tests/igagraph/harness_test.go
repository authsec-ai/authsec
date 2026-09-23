// Package igagraph_test proves the Phase 2 projection against REAL POSTGRES.
//
// SQLite is not an option here and the spec says so repeatedly: it does not
// enforce partial-index inference, so every ON CONFLICT in the graph
// repository would appear to work and would not. It also does not enforce the
// composite foreign keys, the exactly-one CHECKs, or the legal-pair CHECK --
// which between them are most of what Phase 2 IS.
//
// Set TEST_DATABASE_URL to a database you are willing to have its public
// schema dropped and rebuilt:
//
//	TEST_DATABASE_URL="postgres://authsec:...@localhost:5432/iga_test?sslmode=disable" \
//	    go test ./tests/igagraph/...
//
// When it is unset the suite skips, so `go test ./...` stays green without a
// database.
package igagraph_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// setupSchema rebuilds public and applies EVERY migration in order.
//
// Not just the bootstrap: this suite tests constraints added in 026-033, and a
// harness that stopped at 001 would pass while proving nothing about them.
func setupSchema(t *testing.T) (*sql.DB, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping IGA graph tests")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	for _, stmt := range []string{"DROP SCHEMA IF EXISTS public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("reset schema (%q): %v", stmt, err)
		}
	}

	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master"))
	if err != nil {
		t.Fatalf("resolve migrations dir: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "0*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// One Exec per FILE: lib/pq sends it as a simple query, which
		// PostgreSQL wraps in an implicit transaction -- matching the Go
		// runner, which also runs each file in one transaction. 006 depends on
		// that (CREATE TEMP TABLE ... ON COMMIT DROP).
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(f), err)
		}
	}

	g, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, g
}

/* --------------------------------- fixture -------------------------------- */

type fixture struct {
	t         *testing.T
	db        *sql.DB
	gorm      *gorm.DB
	graph     repositories.IGAGraphRepository
	workspace uuid.UUID
	connector uuid.UUID
	clock     time.Time
}

func newFixture(t *testing.T) *fixture {
	db, g := setupSchema(t)
	f := &fixture{
		t: t, db: db, gorm: g,
		graph:     repositories.NewIGAGraphRepository(),
		workspace: uuid.New(),
		connector: uuid.New(),
		clock:     time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	}
	f.exec(`INSERT INTO workspaces (id, name) VALUES ($1, 'ws')`, f.workspace)
	f.exec(`INSERT INTO cloud_connector
	          (id, workspace_id, provider, scope_kind, scope_id, auth_ref)
	        VALUES ($1, $2, 'aws', 'account', '111111111111', 'vault://a')`,
		f.connector, f.workspace)
	return f
}

// addConnector adds a SECOND connector -- a second AWS account in the same
// workspace, which is the multi-account case §2.12 is about.
func (f *fixture) addConnector(accountID string) uuid.UUID {
	id := uuid.New()
	f.exec(`INSERT INTO cloud_connector
	          (id, workspace_id, provider, scope_kind, scope_id, auth_ref)
	        VALUES ($1, $2, 'aws', 'account', $3, 'vault://b')`,
		id, f.workspace, accountID)
	return id
}

func (f *fixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		f.t.Fatalf("exec %q: %v", q, err)
	}
}

func (f *fixture) scalar(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		f.t.Fatalf("query %q: %v", q, err)
	}
	return n
}

// publishedRun inserts a published run whose coverage report is exactly
// `surfaces`, and returns it.
func (f *fixture) publishedRun(connector uuid.UUID, generation int, surfaces map[string]models.SurfaceCoverage) models.CloudScanRun {
	f.t.Helper()
	cov, err := json.Marshal(models.ScanCoverage{
		Generation: generation, Status: "complete", Surfaces: surfaces,
	})
	if err != nil {
		f.t.Fatalf("encode coverage: %v", err)
	}
	run := models.CloudScanRun{
		ID: uuid.New(), WorkspaceID: f.workspace, ConnectorID: connector,
		Generation: generation, Status: models.CloudScanRunPublished,
		Coverage: cov,
	}
	f.exec(`INSERT INTO cloud_scan_run
	          (id, workspace_id, connector_id, generation, status, published_at, coverage)
	        VALUES ($1,$2,$3,$4,'published', now(), $5)`,
		run.ID, run.WorkspaceID, run.ConnectorID, run.Generation, cov)
	return run
}

/* ------------------------------- fake fencer ------------------------------ */

// okFencer stands in for the job and pipeline leases.
//
// The fences themselves are tested by their own repository tests; here they
// would only add setup noise to every projection test. A fencer that always
// SUCCEEDS is the honest stub -- one that always failed would make every test
// below vacuously pass.
type okFencer struct{}

func (okFencer) AssertOwnedTx(*gorm.DB, uuid.UUID, string, int64) error   { return nil }
func (okFencer) AssertHeldTx(*gorm.DB, uuid.UUID, uuid.UUID, int64) error { return nil }

// project runs ONE full pass -- Project then Reconcile -- in one transaction,
// exactly as ProjectionService does.
func (f *fixture) project(snap *igagraph.Snapshot) error {
	f.t.Helper()
	existing, err := igagraph.LoadExisting(f.t.Context(), f.gorm, f.workspace)
	if err != nil {
		f.t.Fatalf("load existing: %v", err)
	}
	now := func() time.Time { return f.clock }
	p := igagraph.NewProjector(f.graph, okFencer{}, existing,
		uuid.New(), "test-owner", 1, 1, now, igagraph.LastGenerationFor)
	rc := igagraph.NewReconciler(now)

	return f.gorm.Transaction(func(tx *gorm.DB) error {
		if err := p.Project(tx, snap); err != nil {
			return err
		}
		return rc.Reconcile(tx, snap)
	})
}

// mustProject fails the test on any projection error.
func (f *fixture) mustProject(snap *igagraph.Snapshot) {
	f.t.Helper()
	if err := f.project(snap); err != nil {
		f.t.Fatalf("project: %v", err)
	}
}

/* ------------------------------ coverage helpers -------------------------- */

func reached(n int) models.SurfaceCoverage {
	return models.SurfaceCoverage{State: models.CloudCoverageReached, Count: n}
}

func denied() models.SurfaceCoverage {
	return models.SurfaceCoverage{State: models.CloudCoverageDenied, Error: "AccessDenied"}
}

// cleanCoverage is a scan that read everything it meant to, in one region.
func cleanCoverage(region string) map[string]models.SurfaceCoverage {
	return map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:        reached(2),
		models.SurfaceIAMUsers:        reached(1),
		models.SurfaceIAMPolicies:     reached(3),
		"lambda:" + region:            reached(1),
		"ecs:" + region:               reached(0),
		"ec2:" + region:               reached(0),
		"bedrock-agents:" + region:    reached(0),
		"bedrock-agentcore:" + region: reached(0),
		// policy_documents deliberately ABSENT: the permission scanner writes
		// it only when parsing dropped something, so absence means clean.
	}
}
