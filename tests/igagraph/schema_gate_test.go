package igagraph_test

// The IGA_GRAPH_PROJECTION switch and its schema verification (SPEC §2.8,
// T1.1, B13/B14). The switch replaces the graph branch's table probing, which
// cached a transient database error as "absent" for the life of the process
// and so silently disabled the barrier.
//
//	off                 Phase 1 exactly; claims allowed; no pipeline
//	on, not verified    FAIL CLOSED: no claims; /capabilities misconfigured
//	on, verified        pipeline mode
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

// Switch ON against a 026 schema: verification fails, the gate FAILS CLOSED,
// and the reason names what is missing.
func TestGraphSwitchFailsClosedBelow036(t *testing.T) {
	db := openAt(t, "S0_DSN")
	gate := services.NewGraphProjectionGate(true, "")
	err := gate.Verify(db)
	if err == nil {
		t.Fatal("the switch verified against a 026 schema")
	}
	mode, reason, _ := gate.Status()
	if mode != services.GraphProjectionMisconfigured {
		t.Errorf("mode = %q, want misconfigured", mode)
	}
	if !strings.Contains(reason, "iga_policy") || !strings.Contains(reason, "036") {
		t.Errorf("the reason must name the missing relations and the head it needs, got %q", reason)
	}
	if gate.ClaimAllowed() {
		t.Fatal("an unverified ON switch allowed scan claims; it must fail closed")
	}
	if gate.PipelineMode() {
		t.Fatal("an unverified switch reported pipeline mode")
	}
	t.Logf("fail-closed reason: %s", reason)
}

// Switch ON against 036: verified, pipeline mode, claims allowed.
func TestGraphSwitchVerifiesAt036(t *testing.T) {
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
		t.Fatal("a verified switch must allow claims in pipeline mode")
	}
}

// B14: a transient error is RETRIED, never cached as an answer. The graph
// branch's sync.Once turned one failed probe into "tables absent" forever.
func TestGraphSwitchTransientErrorIsNotCached(t *testing.T) {
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

// Off is Phase 1: claims allowed, no pipeline, whatever the schema.
func TestGraphSwitchOffIsPhaseOne(t *testing.T) {
	gate := services.NewGraphProjectionGate(false, "")
	if mode, _, _ := gate.Status(); mode != services.GraphProjectionOff {
		t.Fatalf("mode = %q, want off", mode)
	}
	if !gate.ClaimAllowed() || gate.PipelineMode() {
		t.Fatal("off must claim in Phase 1 mode, never pipeline mode")
	}
}

// A typo is neither on nor off: misconfigured, and it never verifies.
func TestGraphSwitchBadValueIsMisconfigured(t *testing.T) {
	t.Setenv(services.GraphProjectionEnv, "yes-please")
	gate := services.GraphProjectionGateFromEnv()
	if mode, reason, _ := gate.Status(); mode != services.GraphProjectionMisconfigured ||
		!strings.Contains(reason, "yes-please") {
		t.Fatalf("status = (%q, %q), want misconfigured naming the value", mode, reason)
	}
	if gate.ClaimAllowed() {
		t.Fatal("an unrecognised switch value allowed claims")
	}
}
