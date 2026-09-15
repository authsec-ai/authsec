package integration

import (
	"context"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Connector-level coverage, against a real database.
//
// The bug this file guards against: scanner.Scan (the IAM read) commits a
// coverage report and advances the generation before the permission and
// workload scans that come after it have even run. Left alone, that report
// is the one that stays -- a denied EKS or Lambda read would never be
// visible in coverage.status, only in a server log. FinalizeCoverage exists
// to replace that premature report with the true, cumulative one, and these
// tests are what prove it actually does.

// coverageFixture onboards a connector and runs the real IAM scan, returning
// everything a test needs to then run permission and workload scans against
// the same snapshot and finalize coverage the way the controller does.
func coverageFixture(
	t *testing.T, db *gorm.DB, ws uuid.UUID, iamFake *fakeIAM,
) (*services.AWSIAMScanner, *services.AWSOnboardingService, *services.IAMSnapshot, uuid.UUID) {
	t.Helper()

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	iamScanner := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake)
	snap, err := iamScanner.Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	return iamScanner, svc, snap, c.ID
}

func connectorCoverage(t *testing.T, db *gorm.DB, ws, connID uuid.UUID) models.ScanCoverage {
	t.Helper()
	c, err := repositories.NewCloudConnectorRepository(db).Get(ws, connID)
	if err != nil {
		t.Fatalf("read back connector: %v", err)
	}
	return models.DecodeScanCoverage(c.Coverage)
}

// The core bug: IAM alone must not decide coverage.status. A fully-readable
// IAM scan next to a denied EKS read and a denied Lambda read must still
// report partial, with both denials individually visible.
func TestCoverageStatusReflectsPermissionAndWorkloadDenialsNotJustIAM(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-coverage-partial")
	defer cleanWorkloadTables(t, db, ws)

	iamFake := populatedIAM()
	iamScanner, svc, snap, connID := coverageFixture(t, db, ws, iamFake)
	if !snap.Coverage.Complete() {
		t.Fatalf("test setup: IAM scan itself must be complete, got %+v", snap.Coverage)
	}

	eksFake := newFakeEKS()
	eksFake.fail["ListClusters"] = denied("eks:ListClusters")
	permScanner := services.NewAWSPermissionScanner(db, svc).
		WithIAMAPI(iamFake).WithEKSAPI(eksFake)
	permSnap, permErr := permScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if permErr != nil {
		t.Fatalf("a denied surface must not fail the whole permission scan: %v", permErr)
	}
	if permSnap.Complete {
		t.Fatal("permission scan must not report complete with EKS denied")
	}

	l, e, c, p := populatedWorkloads()
	l.fail = denied("lambda:ListFunctions")
	workloadScanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p)
	workloadSnap, workloadErr := workloadScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if workloadErr != nil {
		t.Fatalf("a denied surface must not fail the whole workload scan: %v", workloadErr)
	}
	if workloadSnap.Complete {
		t.Fatal("workload scan must not report complete with Lambda denied")
	}

	iamScanner.FinalizeCoverage(ws, connID, snap.Coverage,
		nil, permSnap.Surfaces, nil, workloadSnap.Surfaces)

	final := connectorCoverage(t, db, ws, connID)
	if final.Status != models.ScanStatusPartial {
		t.Fatalf("coverage.status = %q, want %q -- IAM being complete must not paper over "+
			"a denied EKS or Lambda read", final.Status, models.ScanStatusPartial)
	}
	eksSurf, ok := final.Surfaces[models.SurfaceEKSPodIdentity]
	if !ok || eksSurf.State == models.CloudCoverageReached {
		t.Fatalf("eks_pod_identity surface missing or wrongly marked reached: %+v", eksSurf)
	}
	lambdaSurf, ok := final.Surfaces["lambda:us-east-1"]
	if !ok || lambdaSurf.State == models.CloudCoverageReached {
		t.Fatalf("lambda:us-east-1 surface missing or wrongly marked reached: %+v", lambdaSurf)
	}
	// The IAM surfaces this scan DID reach must still be there -- finalizing
	// must merge, not replace.
	if _, ok := final.Surfaces[models.SurfaceIAMRoles]; !ok {
		t.Fatal("finalizing coverage dropped the IAM scan's own surfaces")
	}
	t.Logf("PASS: coverage.status=%q with eks=%s lambda=%s, IAM surfaces preserved",
		final.Status, eksSurf.State, lambdaSurf.State)
}

// The positive case: every surface across all three scans reaches, and the
// connector's final coverage says so, with every surface individually listed.
func TestCoverageStatusCompleteWhenAllThreeScansSucceed(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-coverage-complete")
	defer cleanWorkloadTables(t, db, ws)

	iamFake := populatedIAM()
	iamScanner, svc, snap, connID := coverageFixture(t, db, ws, iamFake)

	roleARN := plainRoleARN
	eksFake := podIdentityEKS(roleARN)
	permScanner := services.NewAWSPermissionScanner(db, svc).
		WithIAMAPI(iamFake).WithEKSAPI(eksFake)
	permSnap, permErr := permScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if permErr != nil {
		t.Fatalf("permission scan: %v", permErr)
	}
	if !permSnap.Complete {
		t.Fatalf("test setup: permission scan should be complete: %+v", permSnap)
	}

	l, e, c, p := populatedWorkloads()
	noSleep := func(context.Context, time.Duration) error { return nil }
	workloadScanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).
		WithActivityAPI(&fakeActivity{services: []iamtypes.ServiceLastAccessed{
			{ServiceName: aws.String("s3"), ServiceNamespace: aws.String("s3")},
		}}, noSleep)
	workloadSnap, workloadErr := workloadScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if workloadErr != nil {
		t.Fatalf("workload scan: %v", workloadErr)
	}
	if !workloadSnap.Complete {
		t.Fatalf("test setup: workload scan should be complete: %+v", workloadSnap)
	}

	iamScanner.FinalizeCoverage(ws, connID, snap.Coverage,
		nil, permSnap.Surfaces, nil, workloadSnap.Surfaces)

	final := connectorCoverage(t, db, ws, connID)
	if final.Status != models.ScanStatusComplete {
		t.Fatalf("coverage.status = %q, want %q: %+v", final.Status, models.ScanStatusComplete, final.Surfaces)
	}
	wantSurfaces := []string{
		models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMAccessKeys, models.SurfaceIAMPolicies,
		models.SurfaceOIDCProviders, models.SurfaceEKSPodIdentity,
		"lambda:us-east-1", "ecs:us-east-1", "ec2:us-east-1",
		"bedrock-agents:us-east-1", "bedrock-agentcore:us-east-1", "activity",
	}
	for _, name := range wantSurfaces {
		s, ok := final.Surfaces[name]
		if !ok {
			t.Errorf("missing surface %q in final coverage", name)
			continue
		}
		if s.State != models.CloudCoverageReached {
			t.Errorf("surface %q state = %q, want reached", name, s.State)
		}
	}
	t.Logf("PASS: coverage.status=complete with %d surfaces recorded, all reached", len(final.Surfaces))
}

// A permission or workload scan that fails outright -- before it produces a
// snapshot at all -- must still leave a visible mark in coverage rather than
// being silently dropped. This is the "failed" case Akash asked to see
// covered separately from a merely denied-but-completed surface.
func TestCoverageRecordsWhollyFailedSubScan(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-coverage-failed")
	defer cleanWorkloadTables(t, db, ws)

	iamFake := populatedIAM()
	iamScanner, svc, snap, connID := coverageFixture(t, db, ws, iamFake)

	permScanner := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(iamFake)
	// nil snapshot is the one guaranteed way to make ScanFromSnapshot fail
	// before it ever constructs a *PermissionSnapshot -- exactly the shape a
	// caller with a genuinely broken connector would see.
	permSnap, permErr := permScanner.ScanFromSnapshot(context.Background(), ws, nil)
	if permErr == nil {
		t.Fatal("test setup: expected the permission scan to fail outright")
	}
	if permSnap != nil {
		t.Fatalf("test setup: expected a nil snapshot on outright failure, got %+v", permSnap)
	}

	l, e, c, p := populatedWorkloads()
	workloadScanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p)
	workloadSnap, workloadErr := workloadScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if workloadErr != nil {
		t.Fatalf("workload scan: %v", workloadErr)
	}

	// Must not panic on a nil Surfaces map from the failed permission scan.
	iamScanner.FinalizeCoverage(ws, connID, snap.Coverage,
		permErr, nil, nil, workloadSnap.Surfaces)

	final := connectorCoverage(t, db, ws, connID)
	if final.Status != models.ScanStatusPartial {
		t.Fatalf("coverage.status = %q, want %q after an outright-failed permission scan",
			final.Status, models.ScanStatusPartial)
	}
	stand, ok := final.Surfaces["permission_scan"]
	if !ok {
		t.Fatal("outright-failed permission scan left no trace in coverage.surfaces at all")
	}
	if stand.State == models.CloudCoverageReached || stand.Error == "" {
		t.Fatalf("permission_scan stand-in surface should record denied+error, got %+v", stand)
	}
	t.Logf("PASS: wholly failed permission scan recorded as %+v, status=%s", stand, final.Status)
}
