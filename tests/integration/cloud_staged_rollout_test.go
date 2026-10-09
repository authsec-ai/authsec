package integration

// S0 (§6.3): this binary carries Phase 2, but is deployed while the database
// may still be at 026. The barrier arrives in 027 and the projection job in
// 033; referencing either before then fails at PLAN time, which would stop the
// worker claiming or publishing ANY scan.
//
// Phase 1 breaking during the rollout window is the failure the staged
// sequence exists to prevent, so it is asserted rather than assumed. Point
// S0_DSN at a database migrated to 026 only.

import (
	"os"
	"testing"
	"time"

	repositories "github.com/authsec-ai/authsec/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestS0PhaseOneScanningSurvivesAPrePhase2Schema(t *testing.T) {
	dsn := os.Getenv("S0_DSN")
	if dsn == "" {
		t.Skip("S0_DSN not set; skipping the staged-rollout check")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open S0: %v", err)
	}

	// Precondition: this really is a pre-Phase-2 schema.
	for _, rel := range []string{"iga_pipeline_lease", "iga_projection_job", "iga_external_principal"} {
		if ok, err := repositories.HasRelation(db, rel); err != nil || ok {
			t.Fatalf("S0_DSN must be a database at 026; %s is present (err=%v)", rel, err)
		}
	}

	ws := newWorkspace(t, db, "ws-s0-rollout")
	conn := connectorFor(t, db, ws)
	runs := repositories.NewCloudScanRunRepository(db)

	// THE ASSERTION: a scan can still be enqueued and CLAIMED. Claim's
	// projection predicate names iga_projection_job, so without the
	// relation probe this fails at plan time and no scan ever starts.
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue on a 026 schema: %v", err)
	}
	run, err := runs.Claim("s0-worker", time.Minute, time.Now())
	if err != nil {
		t.Fatalf("claim on a 026 schema: %v", err)
	}
	if run == nil {
		t.Fatal("no run claimed on a 026 schema: Phase 1 scanning is broken during the rollout window")
	}

	// And it can publish, with coverage, without a projection job to enqueue.
	if err := runs.PublishWithCoverage(run.ID, "s0-worker", run.LeaseVersion,
		coverageFor(nil), nil); err != nil {
		t.Fatalf("publish on a 026 schema: %v", err)
	}
	t.Log("S0: a 026 database still enqueues, claims and publishes a scan")
}
