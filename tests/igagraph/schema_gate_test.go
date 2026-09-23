package igagraph_test

// S0/S1/S2 §6.3: 027-034 ship in ONE release, and core reconciliation writes
// 034's table. With 027-033 applied and 034 missing, every reconcile run fails
// with relation "iga_external_principal" does not exist -- a PLAN-time error,
// so it fires even when no row matches. Declining to start is the honest
// failure; starting and failing every pass is not.

import (
	"os"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/services"
)

// openAt connects to a database that a caller has migrated to a chosen head.
// Skips when the DSN is not provided, so the suite stays runnable without the
// staged databases.
func openAt(t *testing.T, env string) *gorm.DB {
	t.Helper()
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Skipf("%s not set; skipping staged-schema gate", env)
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open %s: %v", env, err)
	}
	return db
}

// S0: a database at 026. The projector must DECLINE to start -- not start and
// fail on every pass, which is what makes a plan-time error look like flaky
// infrastructure rather than a missing migration.
func TestSchemaGateRefusesBelow034(t *testing.T) {
	db := openAt(t, "S0_DSN")
	svc := services.NewProjectionService(db, nil, nil, nil, "gate-test", 0)

	err := svc.EnsureSchema()
	if err == nil {
		t.Fatal("projector accepted a database below migration 034; " +
			"core reconciliation writes iga_external_principal and would fail " +
			"at plan time on every pass")
	}
	if !strings.Contains(err.Error(), "034") {
		t.Errorf("the refusal must name the migration it needs, got: %v", err)
	}
	t.Logf("S0 refused, as required: %v", err)
}

// S1/S2: a database at 034. The projector starts.
func TestSchemaGateAcceptsAt034(t *testing.T) {
	db := openAt(t, "S1_DSN")
	svc := services.NewProjectionService(db, nil, nil, nil, "gate-test", 0)

	if err := svc.EnsureSchema(); err != nil {
		t.Fatalf("projector refused a database at 034: %v", err)
	}
	t.Log("S1/S2 accepted at migration head 034")
}
