package integration

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
)

// Scan attempts and checkpoints, against a real database.
//
// There used to be a per-identity policy phase -- roughly seven AWS calls per
// identity -- and a checkpoint let a second attempt skip the identities the
// first one had finished. SPEC T3.1 removed that phase: the whole IAM
// configuration is now a handful of paginated GetAccountAuthorizationDetails
// listings, re-read in full by every attempt. A checkpoint left at the run's
// generation (by an interrupted attempt, or an older binary) must therefore
// change NOTHING: skipping an identity would make this run depend on writes an
// earlier attempt may or may not have made, and would save no AWS call.

// manyRolesIAM builds an account with n roles, each carrying one inline policy
// so the policy phase has real work to do per identity.
func manyRolesIAM(n int) *fakeIAM {
	f := newFakeIAM()
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	for i := 0; i < n; i++ {
		// Zero-padded so lexical ARN order is stable and predictable, which is
		// the order the resume cursor walks.
		name := fmt.Sprintf("role-%03d", i)
		arn := "arn:aws:iam::429418377036:role/" + name
		f.roles = append(f.roles, iamtypes.Role{
			Arn: aws.String(arn), RoleName: aws.String(name),
			RoleId:                   aws.String(fmt.Sprintf("AROARESUME%03d", i)),
			CreateDate:               ago(time.Duration(i) * time.Hour),
			AssumeRolePolicyDocument: aws.String(url.QueryEscape(trust)),
		})
		f.inlineRolePolicies[name] = map[string]string{
			"inline-one": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		}
	}
	return f
}

// resumeFixture onboards a connector and returns the two scanners that make up
// the chain, sharing one fake IAM so call counts are observable.
func resumeFixture(
	t *testing.T, ws uuid.UUID, fake *fakeIAM,
) (*services.AWSIAMScanner, *services.AWSPermissionScanner, uuid.UUID) {
	t.Helper()

	db := igaDB(t)
	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	return services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake),
		services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake),
		c.ID
}

// A checkpoint at the run's generation makes the next attempt skip nothing:
// every identity is listed, handed over and written, and the checkpoint is
// cleared once the attempt completes.
func TestLeftoverCheckpointSkipsNoIdentity(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-resume")
	defer cleanWorkloadTables(t, db, ws)

	const roleCount = 20
	fake := manyRolesIAM(roleCount)
	iamScanner, permScanner, connectorID := resumeFixture(t, ws, fake)

	// The state an interrupted attempt of the OLD per-identity phase left
	// behind: a checkpoint naming the eighth role, and no advanced
	// scan_generation (commitScan never ran).
	checkpoints := repositories.NewCloudScanCheckpointRepository(db)
	pendingGeneration := 1
	cursor := fmt.Sprintf("arn:aws:iam::429418377036:role/role-%03d", 7)
	if err := checkpoints.Advance(
		ws, connectorID, pendingGeneration,
		models.ScanPhaseIdentityPolicies, cursor, 8,
	); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}

	snap, err := iamScanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	if snap.Generation != pendingGeneration {
		t.Fatalf("the attempt must use generation %d, got %d", pendingGeneration, snap.Generation)
	}
	if got := len(snap.Policies); got != roleCount {
		t.Fatalf("policies handed over for %d identities, want all %d: a leftover checkpoint skipped some",
			got, roleCount)
	}
	if n := snap.Coverage.Counters["identities_resumed_past"]; n != 0 {
		t.Fatalf("identities_resumed_past = %d, want 0", n)
	}
	// One listing page per filter at this size; no per-identity policy call
	// exists any more to count.
	if got := fake.calls["GetAccountAuthorizationDetails:Role"]; got != 1 {
		t.Fatalf("Role listing calls = %d, want 1", got)
	}
	if left, err := checkpoints.HasAny(ws, connectorID, pendingGeneration); err != nil || left {
		t.Fatalf("checkpoint left behind after a complete attempt: %v (err %v)", left, err)
	}

	if _, err := permScanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	var policies, perms int64
	db.Raw(`SELECT count(*) FROM cloud_policy WHERE workspace_id = ? AND last_seen_generation = ?`,
		ws, pendingGeneration).Scan(&policies)
	db.Raw(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ?`, ws).Scan(&perms)
	if policies != roleCount || perms != roleCount {
		t.Fatalf("cloud_policy = %d, cloud_permission = %d at the run's generation, want %d each",
			policies, perms, roleCount)
	}
	t.Logf("PASS: all %d identities read and written despite a checkpoint at role-007", roleCount)
}

// A fresh connector has no checkpoint, so a first scan must fetch everything
// rather than mistaking an absent cursor for "already done".
func TestFirstScanFetchesEverything(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-resume-fresh")
	defer cleanWorkloadTables(t, db, ws)

	fake := manyRolesIAM(5)
	iamScanner, _, connectorID := resumeFixture(t, ws, fake)

	snap, err := iamScanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(snap.Policies) != 5 {
		t.Fatalf("a first scan must fetch every identity's policies, got %d", len(snap.Policies))
	}
	if snap.Coverage.Counters["identities_resumed_past"] != 0 {
		t.Fatal("a first scan must not report skipping anything")
	}
	t.Log("PASS: first scan fetched all 5 identities, skipped nothing")
}
