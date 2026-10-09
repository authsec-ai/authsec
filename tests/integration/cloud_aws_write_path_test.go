package integration

// Regressions for the write-path defects found in the AWS discovery review.
//
// Every test here follows the same shape: establish a good row, then do the
// thing that used to corrupt or delete it, then assert it survived. They are
// written so that reverting the corresponding fix makes them fail -- a test
// that passes with its fix removed proves nothing, and this suite already has
// one documented instance of exactly that.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Migration 021's three ARN-derived columns must be refreshed on conflict.
//
// They were written on INSERT only, so every resource that existed before 021
// took the conflict path forever and kept is_external = false -- a positive
// claim of locality about what may be a cross-account ARN, with a partial index
// built to query exactly that column.
//
// Driven through the repository because that is where the defect lives.
func TestResourceARNDerivedColumnsAreRefreshedOnConflict(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-resource-refresh")
	defer func() {
		db.Exec(`DELETE FROM cloud_resource WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, ws)
	}()

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	connectorID := conn.ID
	repo := repositories.NewCloudPermissionRepository(db)
	const arn = "arn:aws:s3:::somebody-elses-bucket"

	// Stand in for a pre-021 row: discovered, but with the columns at their
	// NOT NULL defaults because nothing populated them at the time.
	stored, created, err2 := repo.UpsertResource(&models.CloudResource{
		WorkspaceID: ws, ConnectorID: connectorID,
		Kind: "s3_bucket", NativeID: arn, Name: "somebody-elses-bucket",
		ResourceAccount: "", IsExternal: false, ObjectKey: "",
		Sensitivity: models.SensitivityLow, SensitivitySource: models.SensitivityFromHeuristic,
		SensitivityReason: "baseline", LastSeenGeneration: 1,
	})
	if err2 != nil || !created {
		t.Fatalf("test setup: seed insert failed (created=%v): %v", created, err2)
	}

	// Pretend a later ticket raised the verdict from a customer classification.
	// This must survive: sensitivity and its two explaining columns are
	// deliberately NOT refreshed. ('customer_classification' because
	// cloud_resource_sensitivity_source_chk allows exactly four values.)
	if err := db.Exec(
		`UPDATE cloud_resource SET sensitivity = ?, sensitivity_source = ?, sensitivity_reason = ?
		  WHERE id = ?`,
		models.SensitivityHigh, "customer_classification", "classified by the customer", stored.ID,
	).Error; err != nil {
		t.Fatalf("test setup: raising the verdict failed: %v", err)
	}

	// The next scan sees the same ARN and now derives its account correctly.
	if _, _, err := repo.UpsertResource(&models.CloudResource{
		WorkspaceID: ws, ConnectorID: connectorID,
		Kind: "s3_bucket", NativeID: arn, Name: "somebody-elses-bucket",
		ResourceAccount: "999988887777", IsExternal: true, ObjectKey: "",
		Sensitivity: models.SensitivityLow, SensitivitySource: models.SensitivityFromHeuristic,
		SensitivityReason: "rule default", LastSeenGeneration: 2,
	}); err != nil {
		t.Fatalf("rescan upsert: %v", err)
	}

	var got struct {
		ResourceAccount   string
		IsExternal        bool
		Sensitivity       string
		SensitivitySource string
		SensitivityReason string
	}
	db.Raw(`SELECT resource_account, is_external, sensitivity, sensitivity_source, sensitivity_reason
	          FROM cloud_resource WHERE id = ?`, stored.ID).Scan(&got)

	if got.ResourceAccount != "999988887777" || !got.IsExternal {
		t.Fatalf("ARN-derived columns were not refreshed: account=%q is_external=%v",
			got.ResourceAccount, got.IsExternal)
	}
	if got.Sensitivity != models.SensitivityHigh {
		t.Fatalf("sensitivity must not be stamped back down: got %q", got.Sensitivity)
	}
	if got.SensitivitySource != "customer_classification" ||
		got.SensitivityReason != "classified by the customer" {
		t.Fatalf("sensitivity_source/reason must travel with the verdict, not the scan: %q / %q",
			got.SensitivitySource, got.SensitivityReason)
	}
	t.Log("PASS: the three ARN-derived columns refresh; the sensitivity trio does not")
}

// Above activityIdentityCap the activity pass reads a PREFIX of the account and
// must say so, or reconciliation deletes the cloud_usage rows of every identity
// it never looked at -- on the authority of a read that reported "reached".
//
// Identities are inserted directly: the point is the repository count crossing
// the cap, not how they got there.
func TestATruncatedActivityReadBlocksReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-activity-cap")
	defer cleanWorkloadTables(t, db, ws)

	scanner, snap := activityFixture(t, db, ws)

	// Baseline: a normal pass, under the cap, writes usage and reconciles.
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}

	// A usage row from the previous generation. This is the row the bug deleted.
	var idStr string
	db.Raw(`SELECT id::text FROM cloud_identity WHERE workspace_id = ? LIMIT 1`, ws).Scan(&idStr)
	if idStr == "" {
		t.Fatal("test setup: expected the identity scan to have written identities")
	}
	anyIdentity := uuid.MustParse(idStr)
	db.Exec(`INSERT INTO cloud_usage
	           (id, workspace_id, connector_id, identity_id, service, source, last_used_at,
	            last_seen_generation, first_seen_at, last_seen_at, row_updated_at)
	         VALUES (?, ?, ?, ?, 'legacy-service', 'service_last_accessed', NULL, ?, now(), now(), now())`,
		uuid.New(), ws, snap.ConnectorID, anyIdentity, snap.Generation)

	// Push the account over the cap. Names are prefixed so they sort AFTER the
	// fixture's roles under ORDER BY (kind, name, id) -- i.e. into the starved
	// tail, which is the deterministic part of the defect.
	for i := 0; i < 520; i++ {
		db.Exec(`INSERT INTO cloud_identity
		           (id, workspace_id, connector_id, kind, native_id, name, enabled, attrs,
		            last_seen_generation, first_seen_at, last_seen_at, row_updated_at)
		         VALUES (?, ?, ?, 'iam_role', ?, ?, true, '{}', ?, now(), now(), now())`,
			uuid.New(), ws, snap.ConnectorID,
			fmt.Sprintf("arn:aws:iam::429418377036:role/zz-bulk-%04d", i),
			fmt.Sprintf("zz-bulk-%04d", i), snap.Generation)
	}

	var usageBefore int64
	db.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ?`, ws).Scan(&usageBefore)

	snap.Generation++
	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("a truncated activity read must not fail the scan: %v", err)
	}

	if out.UsageComplete {
		t.Fatal("a truncated activity read must not license usage reconciliation")
	}
	if got := out.Surfaces["activity"].State; got != models.CloudCoveragePartial {
		t.Fatalf("truncation is partial, not %q: the read was not denied, it stopped short", got)
	}

	var usageAfter int64
	db.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ?`, ws).Scan(&usageAfter)
	if usageAfter < usageBefore {
		t.Fatalf("a truncated read deleted usage history: %d -> %d", usageBefore, usageAfter)
	}
	t.Logf("PASS: truncation reported partial, %d usage row(s) preserved", usageAfter)
}

// The counterpart: under the cap nothing changes. Without this, "always report
// truncated" would pass the test above and permanently disable reconciliation.
func TestAnUntruncatedActivityReadStillReconciles(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-activity-under-cap")
	defer cleanWorkloadTables(t, db, ws)

	scanner, snap := activityFixture(t, db, ws)

	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := out.Surfaces["activity"].State; got != models.CloudCoverageReached {
		t.Fatalf("an activity read under the cap is reached, got %q", got)
	}
	if !out.UsageComplete {
		t.Fatalf("a clean activity read must still reconcile usage: %v", out.Errors)
	}
	t.Log("PASS: an under-cap activity read still reports reached and complete")
}

// activityFixture wires a workload scanner whose ONLY live surface is activity.
// The compute APIs are left unset so they report not-configured rather than
// denied, which keeps these tests about the activity gate and nothing else.
func activityFixture(t *testing.T, db *gorm.DB, ws uuid.UUID) (*services.AWSWorkloadScanner, *services.IAMSnapshot) {
	t.Helper()
	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).
		Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	used := time.Now().Add(-90 * 24 * time.Hour)
	activity := &fakeActivity{services: []iamtypes.ServiceLastAccessed{{
		ServiceNamespace:           aws.String("s3"),
		ServiceName:                aws.String("Amazon S3"),
		LastAuthenticated:          &used,
		TotalAuthenticatedEntities: aws.Int32(1),
	}}}
	noSleep := func(context.Context, time.Duration) error { return nil }
	l, e, c, p := populatedWorkloads()
	return services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).
		WithActivityAPI(activity, noSleep), snap
}

// awsAttrsOf reads one identity's attrs blob back as AWS attributes, straight
// from the column rather than through the scanner, so the assertion is about
// what is actually stored.
func awsAttrsOf(t *testing.T, db *gorm.DB, ws uuid.UUID, nativeID string) models.AWSIdentityAttrs {
	t.Helper()
	var raw string
	if err := db.Raw(
		`SELECT attrs::text FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`,
		ws, nativeID,
	).Scan(&raw).Error; err != nil {
		t.Fatalf("read attrs for %s: %v", nativeID, err)
	}
	if raw == "" {
		t.Fatalf("no identity row for %s", nativeID)
	}
	var attrs models.AWSIdentityAttrs
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
		t.Fatalf("decode attrs for %s: %v", nativeID, err)
	}
	return attrs
}

// The crash-recovery path B5 exists for, end to end.
//
// A worker dies after commitScan advanced the connector but before Publish.
// The run is re-claimed and keeps its generation; the connector has already
// moved. The old code recomputed connector.ScanGeneration+1 and so stamped
// entity rows one generation AHEAD of the cloud_observation rows the worker was
// writing against run.Generation -- evidence that no longer joins to the
// inventory it explains.
//
// This also pins the side effect of the fix: holding the generation steady
// makes the previous attempt's checkpoints visible, so the resume path that was
// previously unreachable now engages. Assert it engages SAFELY -- nothing the
// first attempt wrote may be lost.
func TestAReclaimedRunKeepsOneGenerationForRowsAndEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-reclaim-generation")
	defer cleanWorkloadTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	runs := repositories.NewCloudScanRunRepository(db)
	if _, err := runs.Enqueue(ws, conn.ID, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	now := time.Now()
	first, err := runs.Claim("worker-a", time.Minute, now)
	if err != nil || first == nil {
		t.Fatalf("first claim: %v %v", first, err)
	}

	fake := populatedIAM()
	// Attempt one: IAM phase completes (so commitScan advances the connector),
	// then the permission phase writes checkpoints, then the worker dies.
	snap1, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake).
		WithGeneration(first.Generation).Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("attempt one iam scan: %v", err)
	}
	if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake).
		ScanFromSnapshot(context.Background(), ws, snap1); err != nil {
		t.Fatalf("attempt one permission scan: %v", err)
	}

	var connGen int
	db.Raw(`SELECT scan_generation FROM cloud_connector WHERE id = ?`, conn.ID).Scan(&connGen)
	if connGen != first.Generation {
		t.Fatalf("test setup: commitScan should have advanced the connector to %d, got %d",
			first.Generation, connGen)
	}
	var permsBefore int64
	db.Raw(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ?`, ws).Scan(&permsBefore)
	if permsBefore == 0 {
		t.Fatal("test setup: attempt one should have written permissions")
	}

	// worker-a never published. Its lease lapses and worker-b takes the run.
	second, err := runs.Claim("worker-b", time.Minute, now.Add(2*time.Minute))
	if err != nil || second == nil {
		t.Fatalf("reclaim: %v %v", second, err)
	}
	if second.Generation != first.Generation {
		t.Fatalf("test setup: a reclaimed run keeps its generation, %d -> %d",
			first.Generation, second.Generation)
	}

	// Attempt two, the way the worker runs it.
	snap2, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake).
		WithGeneration(second.Generation).Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("attempt two iam scan: %v", err)
	}

	// THE defect: the rows and the evidence must agree on which pass wrote them.
	if snap2.Generation != second.Generation {
		t.Fatalf("rows stamped %d while the run's evidence is stamped %d -- "+
			"evidence no longer joins to the inventory it explains",
			snap2.Generation, second.Generation)
	}

	if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake).
		ScanFromSnapshot(context.Background(), ws, snap2); err != nil {
		t.Fatalf("attempt two permission scan: %v", err)
	}

	// The side effect, checked rather than assumed: resume may skip work, but
	// reconciliation at the same generation must not delete what attempt one
	// already wrote.
	var permsAfter int64
	db.Raw(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ?`, ws).Scan(&permsAfter)
	if permsAfter < permsBefore {
		t.Fatalf("the resumed attempt destroyed permissions the first one wrote: %d -> %d",
			permsBefore, permsAfter)
	}
	var orphaned int64
	db.Raw(`SELECT count(*) FROM cloud_permission
	         WHERE workspace_id = ? AND last_seen_generation <> ?`, ws, second.Generation).Scan(&orphaned)
	if orphaned != 0 {
		t.Fatalf("%d permission row(s) carry a generation other than %d",
			orphaned, second.Generation)
	}
	t.Logf("PASS: one generation (%d) across rows and evidence; %d permission(s) preserved",
		second.Generation, permsAfter)
}
