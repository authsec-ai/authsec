package igagraph_test

// The graph gate and its schema verification (SPEC §2.8, T1.1, B13/B14).
// There is no switch: main installs the gate on, and the schema decides. It
// replaces the graph branch's table probing, which cached a transient database
// error as "absent" for the life of the process and so silently disabled the
// barrier.
//
//	off (tests)                  Phase 1 exactly; claims allowed; no pipeline
//	graph schema absent          claims allowed in Phase 1 (no barrier table:
//	                             nothing can be projecting); /capabilities says so
//	partial, or a database error FAIL CLOSED: no claims; /capabilities misconfigured
//	verified                     pipeline mode
//
// S0_DSN is a database at 026; S1_DSN one at 036.

import (
	"os"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/services"
)

func openAt(t *testing.T, env string) *gorm.DB {
	t.Helper()
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Skipf("%s not set; skipping staged-schema gate", env)
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open %s: %v", env, err)
	}
	return db
}

// The gate against a 026 schema, before the graph's first migration (027, the
// barrier table): verification fails and names what is missing, there is no
// pipeline, and AWS scans still run -- in Phase 1, since with no barrier table
// no process can be projecting. The removed switch's "off" gave the same.
func TestGraphGateScansWithoutGraphBelow027(t *testing.T) {
	db := openAt(t, "S0_DSN")
	gate := services.NewGraphProjectionGate(true, "")
	err := gate.Verify(db)
	if err == nil {
		t.Fatal("the gate verified against a 026 schema")
	}
	mode, reason, _ := gate.Status()
	if mode != services.GraphProjectionMisconfigured {
		t.Errorf("mode = %q, want misconfigured", mode)
	}
	if !strings.Contains(reason, "iga_policy") || !strings.Contains(reason, "036") || !strings.Contains(reason, "without the graph") {
		t.Errorf("the reason must name the missing relations, the head it needs and that scans run without the graph, got %q", reason)
	}
	if !gate.ClaimAllowed() {
		t.Fatal("AWS scans stopped on a database without the graph schema; they must run in Phase 1")
	}
	if gate.PipelineMode() {
		t.Fatal("an unverified gate reported pipeline mode")
	}
	t.Logf("reason: %s", reason)
}

// The gate against 036: verified, pipeline mode, claims allowed.
func TestGraphGateVerifiesAt036(t *testing.T) {
	db := openAt(t, "S1_DSN")
	gate := services.NewGraphProjectionGate(true, "")
	if err := gate.Verify(db); err != nil {
		t.Fatalf("verification failed at 036: %v", err)
	}
	mode, reason, head := gate.Status()
	if mode != services.GraphProjectionOn || reason != "" || head != services.GraphSchemaHead {
		t.Fatalf("status = (%q, %q, %q), want (on, '', %s)", mode, reason, head, services.GraphSchemaHead)
	}
	if !gate.ClaimAllowed() || !gate.PipelineMode() {
		t.Fatal("a verified gate must allow claims in pipeline mode")
	}
}

// B14: a transient error is RETRIED, never cached as an answer. The graph
// branch's sync.Once turned one failed probe into "tables absent" forever.
func TestGraphGateTransientErrorIsNotCached(t *testing.T) {
	good := openAt(t, "S1_DSN")
	// A connection that fails every query: the transient database error a
	// startup check can meet. (GORM pings at open, so an unreachable host
	// cannot be opened at all; a closed pool behaves exactly like one.)
	bad := openAt(t, "S1_DSN")
	sqlDB, err := bad.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	gate := services.NewGraphProjectionGate(true, "")
	if err := gate.Verify(bad); err == nil {
		t.Fatal("verification succeeded against an unreachable database")
	}
	if mode, _, _ := gate.Status(); mode != services.GraphProjectionMisconfigured || gate.ClaimAllowed() {
		t.Fatal("a verification ERROR must fail closed")
	}
	if err := gate.Verify(good); err != nil {
		t.Fatalf("the retry against a healthy 036 database failed: %v", err)
	}
	if !gate.PipelineMode() {
		t.Fatal("the error was cached: the gate never recovered after a successful check")
	}
}

// Off (the process default before main installs the gate, and tests) is
// Phase 1: claims allowed, no pipeline, whatever the schema.
func TestGraphGateOffIsPhaseOne(t *testing.T) {
	gate := services.NewGraphProjectionGate(false, "")
	if mode, _, _ := gate.Status(); mode != services.GraphProjectionOff {
		t.Fatalf("mode = %q, want off", mode)
	}
	if !gate.ClaimAllowed() || gate.PipelineMode() {
		t.Fatal("off must claim in Phase 1 mode, never pipeline mode")
	}
}
