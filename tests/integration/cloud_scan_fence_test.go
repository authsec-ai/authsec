package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// SPEC §2.10A, part 3. The pipeline barrier stops a NEW scan while a projection
// is pending, and cancelling a superseded scanner's context stops its work
// promptly -- but neither establishes that a superseded worker has stopped
// WRITING. This proves the fence does: an inventory write by a worker that has
// lost its run is refused, in the same transaction as the write, against the
// row Claim bumps on reclaim.
func TestSupersededWorkerInventoryWriteIsRefused(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-fence")
	conn := connectorFor(t, db, ws)
	defer cleanIdentities(t, db, ws)

	runs := scanRuns(t, db)
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runA, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || runA == nil {
		t.Fatalf("claim A: %v %v", runA, err)
	}

	idRepo := repositories.NewCloudIdentityRepository(db)
	fenceA := repositories.ScanFence{
		RunID: runA.ID, Owner: "worker-a", LeaseVersion: runA.LeaseVersion,
	}

	// Worker A, still the owner, writes an identity. This must succeed.
	first := &models.CloudIdentity{
		WorkspaceID: ws, ConnectorID: conn, Kind: "iam_role",
		NativeID: "arn:aws:iam::1234:role/before-reclaim", Name: "before",
		LastSeenGeneration: runA.Generation,
	}
	if _, _, err := idRepo.Fenced(fenceA).UpsertIdentity(first); err != nil {
		t.Fatalf("write under a live lease must succeed: %v", err)
	}

	// Worker B reclaims the SAME run: expire A's lease, then claim. Claim bumps
	// lease_version, which is what makes A's fence stale.
	if err := db.Exec(
		`UPDATE cloud_scan_run SET lease_expires_at = now() - interval '2 minutes' WHERE id = ?`,
		runA.ID).Error; err != nil {
		t.Fatalf("expire A: %v", err)
	}
	runB, err := runs.Claim("worker-b", time.Minute, time.Now())
	if err != nil || runB == nil {
		t.Fatalf("claim B: %v %v", runB, err)
	}
	if runB.ID != runA.ID {
		t.Fatalf("B should have reclaimed A's run, got a different run")
	}
	if runB.LeaseVersion <= runA.LeaseVersion {
		t.Fatalf("reclaim must bump lease_version: A=%d B=%d", runA.LeaseVersion, runB.LeaseVersion)
	}

	// Worker A, now superseded, tries to write again under its STALE fence.
	// This must be refused, and nothing must land.
	orphan := &models.CloudIdentity{
		WorkspaceID: ws, ConnectorID: conn, Kind: "iam_role",
		NativeID: "arn:aws:iam::1234:role/after-reclaim", Name: "after",
		LastSeenGeneration: runA.Generation,
	}
	_, _, err = idRepo.Fenced(fenceA).UpsertIdentity(orphan)
	if !errors.Is(err, repositories.ErrScanFenceLost) {
		t.Fatalf("a superseded worker's write must fail with ErrScanFenceLost, got %v", err)
	}
	var leaked int64
	db.Raw(`SELECT count(*) FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`,
		ws, orphan.NativeID).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("the superseded write LANDED (%d rows); the fence did not hold", leaked)
	}

	// Worker B, the rightful owner, writes under its fresh fence: succeeds.
	fenceB := repositories.ScanFence{
		RunID: runB.ID, Owner: "worker-b", LeaseVersion: runB.LeaseVersion,
	}
	ok := &models.CloudIdentity{
		WorkspaceID: ws, ConnectorID: conn, Kind: "iam_role",
		NativeID: "arn:aws:iam::1234:role/by-owner", Name: "owner",
		LastSeenGeneration: runB.Generation,
	}
	if _, _, err := idRepo.Fenced(fenceB).UpsertIdentity(ok); err != nil {
		t.Fatalf("the current owner's write must succeed: %v", err)
	}

	// And an UNFENCED repository is unchanged by any of this -- the fence is
	// opt-in, so the many existing callers that do not pass one still write.
	plain := &models.CloudIdentity{
		WorkspaceID: ws, ConnectorID: conn, Kind: "iam_role",
		NativeID: "arn:aws:iam::1234:role/unfenced", Name: "plain",
		LastSeenGeneration: runB.Generation,
	}
	if _, _, err := idRepo.UpsertIdentity(plain); err != nil {
		t.Fatalf("an unfenced write must still succeed: %v", err)
	}
}
