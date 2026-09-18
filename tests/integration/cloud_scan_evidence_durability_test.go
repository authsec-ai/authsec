package integration

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// D1/D2 -- coverage must be per-run, and the persisted report is what a reader
// consumes, never a recomputation.
//
// Before this, coverage lived only on cloud_connector, overwritten by every
// scan. A reader asking "was run A complete" after run B published got run B's
// answer -- possibly a worse one -- because there was only ever one answer to
// give. cloud_scan_run.coverage exists so run A's own report survives run B.
func TestPerRunCoverageSurvivesALaterRun(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-per-run-coverage")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	// Run A: complete.
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	runA, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || runA == nil {
		t.Fatalf("claim A: %v %v", runA, err)
	}
	coverageA := models.ScanCoverage{
		Generation: runA.Generation,
		Status:     models.ScanStatusComplete,
		Surfaces: map[string]models.SurfaceCoverage{
			models.SurfaceIAMRoles: {State: models.CloudCoverageReached, Count: 12},
		},
	}
	if err := runs.Publish(runA.ID, "worker-a", runA.LeaseVersion); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if err := runs.SetCoverage(runA.ID, coverageA); err != nil {
		t.Fatalf("set coverage A: %v", err)
	}

	// Run B: partial -- IAM denied this time.
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue B: %v", err)
	}
	runB, err := runs.Claim("worker-b", time.Minute, time.Now())
	if err != nil || runB == nil {
		t.Fatalf("claim B: %v %v", runB, err)
	}
	coverageB := models.ScanCoverage{
		Generation: runB.Generation,
		Status:     models.ScanStatusPartial,
		Surfaces: map[string]models.SurfaceCoverage{
			models.SurfaceIAMRoles: {State: models.CloudCoverageDenied, Error: "throttled"},
		},
	}
	if err := runs.Publish(runB.ID, "worker-b", runB.LeaseVersion); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	if err := runs.SetCoverage(runB.ID, coverageB); err != nil {
		t.Fatalf("set coverage B: %v", err)
	}

	// Run A's own report must still read complete -- run B must not have
	// touched it. This is the property that did not exist when coverage lived
	// only on cloud_connector.
	gotA, err := runs.Get(runA.ID)
	if err != nil {
		t.Fatalf("get A: %v", err)
	}
	decodedA := models.DecodeScanCoverage(gotA.Coverage)
	if !decodedA.Complete() {
		t.Fatalf("run A's persisted coverage reads incomplete after run B published: %+v", decodedA)
	}
	if decodedA.Status != models.ScanStatusComplete {
		t.Fatalf("run A's status = %q, want %q (run B's status must not leak backward)",
			decodedA.Status, models.ScanStatusComplete)
	}

	// And run B's is its own, correctly partial.
	gotB, err := runs.Get(runB.ID)
	if err != nil {
		t.Fatalf("get B: %v", err)
	}
	decodedB := models.DecodeScanCoverage(gotB.Coverage)
	if decodedB.Complete() {
		t.Fatalf("run B's persisted coverage reads complete, want partial (IAM was denied): %+v", decodedB)
	}
}

// SetCoverage is guarded by status = published: a run still queued or running
// has not earned an authoritative report, and a superseded worker's fenced
// Publish call already failed by the time it would try to attach one.
func TestSetCoverageRefusedOnAnUnpublishedRun(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-coverage-guard")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	// Still "running" -- never published.
	err = runs.SetCoverage(run.ID, models.ScanCoverage{Status: models.ScanStatusComplete})
	if err == nil {
		t.Fatal("SetCoverage succeeded on a run that was never published")
	}
}

// D3 -- evidence must outlive the inventory row it was about.
//
// Reconciliation hard-deletes a stale cloud_permission by generation. Before
// this fix, cloud_observation's subject FK was ON DELETE CASCADE, so that
// delete took the observation down with it -- the evidence for why AuthSec
// ever believed the grant existed vanished at the exact moment a reviewer
// would want to ask about it.
func TestObservationSurvivesItsSubjectBeingReconciledAway(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-evidence-outlives-subject")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	identityID := uuid.New()
	if err := db.Exec(`
		INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, last_seen_generation)
		VALUES (?, ?, ?, 'iam_role', ?, 'SharedToolRole', ?)`,
		identityID, ws, conn, "arn:aws:iam::491056652413:role/SharedToolRole-"+identityID.String()[:8], run.Generation,
	).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	permissionID := uuid.New()
	permARN := "arn:aws:iam::491056652413:policy/P02-" + permissionID.String()[:8]
	if err := db.Exec(`
		INSERT INTO cloud_permission
			(id, workspace_id, connector_id, identity_id, effect, actions, scope_kind, native_id, last_seen_generation)
		VALUES (?, ?, ?, ?, 'allow', ARRAY['sts:AssumeRole'], 'account_wide', ?, ?)`,
		permissionID, ws, conn, identityID, permARN, run.Generation,
	).Error; err != nil {
		t.Fatalf("seed permission: %v", err)
	}

	w := services.NewObservationWriter(db, ws, conn, run.ID, run.Generation)
	if err := w.Record(services.PermissionSubject(permissionID), "iam:GetRolePolicy",
		models.SurfaceIAMPolicies, models.CloudCoverageReached, time.Now(), permARN,
		map[string]any{"effect": "allow", "action": "sts:AssumeRole"}); err != nil {
		t.Fatalf("record evidence: %v", err)
	}

	var obsIDStr string
	if err := db.Raw(`SELECT id FROM cloud_observation WHERE permission_id = ?`, permissionID).
		Row().Scan(&obsIDStr); err != nil {
		t.Fatalf("evidence was not written: %v", err)
	}
	obsID, err := uuid.Parse(obsIDStr)
	if err != nil {
		t.Fatalf("observation id %q did not parse: %v", obsIDStr, err)
	}

	// Reconciliation deletes the permission as stale (a generation this
	// connector no longer sees) -- exactly what
	// cloud_permission_repository.ReconcileGeneration does for real.
	grants := repositories.NewCloudPermissionRepository(db)
	edgesRemoved, permsRemoved, _, err := grants.ReconcileGeneration(ws, conn, run.Generation+1)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if permsRemoved != 1 {
		t.Fatalf("reconciliation removed %d permissions, want 1 (test setup problem, not the fix)", permsRemoved)
	}
	_ = edgesRemoved

	// The evidence row must still exist -- CASCADE would have deleted it along
	// with the permission.
	var (
		stillPermissionID *string
		nativeID          string
	)
	err = db.Raw(`SELECT permission_id, subject_native_id FROM cloud_observation WHERE id = ?`, obsID).
		Row().Scan(&stillPermissionID, &nativeID)
	if err != nil {
		t.Fatalf("evidence disappeared when its subject was reconciled away: %v", err)
	}
	if stillPermissionID != nil {
		t.Fatalf("permission_id = %v, want nil (SET NULL should have fired since the row is gone)",
			*stillPermissionID)
	}
	if nativeID != permARN {
		t.Fatalf("subject_native_id = %q, want %q -- evidence must still say what it was about "+
			"after the live FK is nulled", nativeID, permARN)
	}
}
