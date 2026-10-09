package integration

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// Pagination and connector scoping, against a real database.
//
// Before this, six of the seven cloud_aws_* list endpoints had no limit at
// all -- every row in the workspace, every time -- and five of them had no
// way to scope to one connected account, so a workspace with two AWS
// connectors got both accounts' rows back mixed together from a single-
// identity-only filter. Both are exercised here against real rows, not
// asserted about the query in the abstract.

// secondAccountVerifier stubs a second AWS account's identity, so a second
// connector can be onboarded into the SAME workspace as populatedIAM's
// account without colliding on (workspace_id, scope_id).
func secondAccountVerifier() *stubVerifier {
	return &stubVerifier{identity: &awsdiscovery.Identity{
		AccountID: "555566667777",
		ARN:       "arn:aws:sts::555566667777:assumed-role/AuthSecCloudDiscovery/authsec-onboarding-def67890",
		UserID:    "AROAEXAMPLEID2:authsec-onboarding-def67890",
	}}
}

// Two connectors, two IAM scans, one workspace. Listing permissions scoped to
// one connector_id must return only that connector's rows.
func TestListPermissionsScopesToOneConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-connector-scoping")
	defer cleanPermissionTables(t, db, ws)

	svcA, _ := newOnboarding(db, okVerifier())
	connA, _, err := svcA.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard account A: %v", err)
	}
	snapA, err := services.NewAWSIAMScanner(db, svcA).WithIAMAPI(populatedIAM()).
		Scan(context.Background(), ws, connA.ID)
	if err != nil {
		t.Fatalf("scan account A: %v", err)
	}
	if _, err := services.NewAWSPermissionScanner(db, svcA).WithIAMAPI(populatedIAM()).
		ScanFromSnapshot(context.Background(), ws, snapA); err != nil {
		t.Fatalf("permission scan account A: %v", err)
	}

	svcB, _ := newOnboarding(db, secondAccountVerifier())
	inputB := singleRegionInput(mustMint(t, ws))
	// singleRegionInput's role ARN names account 429418377036; the onboarding
	// service checks the assumed identity's account against the ARN itself
	// (see TestAWSAccountMismatchIsRefused), so a genuinely second account
	// needs a role ARN naming that same second account.
	inputB.RoleARN = "arn:aws:iam::555566667777:role/AuthSecCloudDiscovery"
	connB, _, err := svcB.Onboard(context.Background(), ws, inputB, "admin")
	if err != nil {
		t.Fatalf("onboard account B: %v", err)
	}
	iamB := manyRolesIAM(3)
	snapB, err := services.NewAWSIAMScanner(db, svcB).WithIAMAPI(iamB).
		Scan(context.Background(), ws, connB.ID)
	if err != nil {
		t.Fatalf("scan account B: %v", err)
	}
	if _, err := services.NewAWSPermissionScanner(db, svcB).WithIAMAPI(iamB).
		ScanFromSnapshot(context.Background(), ws, snapB); err != nil {
		t.Fatalf("permission scan account B: %v", err)
	}

	grants := repositories.NewCloudPermissionRepository(db)

	mixed, mixedTotal, err := grants.ListPermissions(ws, repositories.CloudPermissionFilter{})
	if err != nil {
		t.Fatalf("list unscoped: %v", err)
	}
	if int64(len(mixed)) != mixedTotal {
		t.Fatalf("unscoped page/total mismatch: %d rows, total=%d", len(mixed), mixedTotal)
	}

	onlyA, totalA, err := grants.ListPermissions(ws, repositories.CloudPermissionFilter{ConnectorID: &connA.ID})
	if err != nil {
		t.Fatalf("list scoped to A: %v", err)
	}
	onlyB, totalB, err := grants.ListPermissions(ws, repositories.CloudPermissionFilter{ConnectorID: &connB.ID})
	if err != nil {
		t.Fatalf("list scoped to B: %v", err)
	}

	if totalA == 0 || totalB == 0 {
		t.Fatalf("test setup: both accounts should have written permissions, got A=%d B=%d", totalA, totalB)
	}
	if totalA+totalB != mixedTotal {
		t.Fatalf("scoped totals don't add up to the unscoped total: A=%d + B=%d != mixed=%d",
			totalA, totalB, mixedTotal)
	}
	for _, p := range onlyA {
		if p.ConnectorID != connA.ID {
			t.Fatalf("connector_id=A filter returned a row from connector %s", p.ConnectorID)
		}
	}
	for _, p := range onlyB {
		if p.ConnectorID != connB.ID {
			t.Fatalf("connector_id=B filter returned a row from connector %s", p.ConnectorID)
		}
	}
	t.Logf("PASS: unscoped=%d, connector A=%d, connector B=%d, no cross-account bleed", mixedTotal, totalA, totalB)
}

// A small limit must actually cap the page, while total keeps reporting the
// real row count -- the two numbers a UI paginator needs and previously had
// no way to get for this endpoint.
func TestListPermissionsPaginates(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-pagination")
	defer cleanPermissionTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	iam := manyRolesIAM(5) // one inline policy per role -> 5 permission rows
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iam).Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(iam).
		ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("permission scan: %v", err)
	}

	grants := repositories.NewCloudPermissionRepository(db)

	page1, total, err := grants.ListPermissions(ws, repositories.CloudPermissionFilter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5 (the limit must not affect the reported total)", total)
	}
	if len(page1) != 2 {
		t.Fatalf("page 1 returned %d rows, want exactly 2", len(page1))
	}

	page2, _, err := grants.ListPermissions(ws, repositories.CloudPermissionFilter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page 2 returned %d rows, want exactly 2", len(page2))
	}
	if page1[0].ID == page2[0].ID {
		t.Fatal("page 1 and page 2 returned the same first row -- offset is not advancing")
	}

	page3, _, err := grants.ListPermissions(ws, repositories.CloudPermissionFilter{Limit: 2, Offset: 4})
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("final page returned %d rows, want exactly 1 (5 total, 2 pages of 2 already consumed)", len(page3))
	}

	seen := map[uuid.UUID]bool{}
	for _, p := range append(append(page1, page2...), page3...) {
		if seen[p.ID] {
			t.Fatalf("row %s appeared on more than one page", p.ID)
		}
		seen[p.ID] = true
	}
	t.Logf("PASS: 5 rows paged as 2+2+1, total=5 throughout, no duplicate or missing row")
}
