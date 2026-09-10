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

// Scan resume, against a real database.
//
// The phase that matters is the per-identity policy fetch: roughly seven AWS
// calls per identity, so on hundreds of roles it dominates the scan and is
// where an interruption is most likely to land. Resume has to make a second
// attempt skip the identities the first one finished -- without making any AWS
// call for them at all, which is the only saving that counts.

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

// A scan interrupted part-way through the policy phase must, on the next
// attempt, skip the identities it already finished and make no AWS call for
// them.
func TestScanResumesPastIdentitiesAlreadyDone(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-resume")
	defer cleanWorkloadTables(t, db, ws)

	const roleCount = 20
	fake := manyRolesIAM(roleCount)
	iamScanner, permScanner, connectorID := resumeFixture(t, ws, fake)

	// ---- attempt one, interrupted -----------------------------------------
	//
	// A process that dies mid-scan leaves two things behind: rows for the
	// identities it finished, and a checkpoint naming the last of them. It does
	// NOT leave an advanced scan_generation, because commitScan never ran.
	//
	// That state is seeded directly here rather than by running and truncating a
	// real scan, because a Scan() call that returns at all advances the
	// generation -- see the note at the bottom of this file on why the live
	// chain cannot yet produce this state on its own.
	const finishedInAttemptOne = 8
	checkpoints := repositories.NewCloudScanCheckpointRepository(db)
	pendingGeneration := 1
	cursor := fmt.Sprintf("arn:aws:iam::429418377036:role/role-%03d", finishedInAttemptOne-1)
	if err := checkpoints.Advance(
		ws, connectorID, pendingGeneration,
		models.ScanPhaseIdentityPolicies, cursor, finishedInAttemptOne,
	); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	t.Logf("PASS: interrupted attempt left a checkpoint at %s", cursor)

	// ---- attempt two, resuming --------------------------------------------
	resumed, err := iamScanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("attempt two identity scan: %v", err)
	}
	if resumed.Generation != pendingGeneration {
		t.Fatalf("a resumed attempt must reuse generation %d, got %d",
			pendingGeneration, resumed.Generation)
	}
	t.Logf("PASS: attempt two reused generation %d instead of starting a new one", resumed.Generation)

	// The saving that matters: no policy call for the identities already done.
	if got := len(resumed.Policies); got != roleCount-finishedInAttemptOne {
		t.Fatalf("expected policies for %d remaining identities, got %d",
			roleCount-finishedInAttemptOne, got)
	}
	callsMade := fake.calls["GetRolePolicy"]
	if callsMade != roleCount-finishedInAttemptOne {
		t.Fatalf("expected %d GetRolePolicy calls on resume, saw %d -- resume is not skipping AWS calls",
			roleCount-finishedInAttemptOne, callsMade)
	}
	if resumed.Coverage.Counters["identities_resumed_past"] != finishedInAttemptOne {
		t.Fatalf("the scan report must say how many were skipped, got %v",
			resumed.Coverage.Counters["identities_resumed_past"])
	}
	t.Logf("PASS: %d AWS policy calls made instead of %d — %d identities skipped entirely",
		callsMade, roleCount, finishedInAttemptOne)

	// ---- a finished generation's checkpoint must not affect the next scan --
	if _, err := permScanner.ScanFromSnapshot(context.Background(), ws, resumed); err != nil {
		t.Fatalf("attempt two permission scan: %v", err)
	}

	// The checkpoint for a finished generation is INERT rather than cleared: the
	// identity scan clears it on completion, and then the permission scan writes
	// its own cursor again on the way past. What has to hold is that the next
	// scan -- which runs at generation+1 -- does not resume from it, or a
	// completed account would never be re-read.
	fake.calls["GetRolePolicy"] = 0
	fresh, err := iamScanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("next scan: %v", err)
	}
	if fresh.Generation == resumed.Generation {
		t.Fatalf("a scan after a completed one must advance the generation, still %d", fresh.Generation)
	}
	if fresh.Coverage.Counters["identities_resumed_past"] != 0 {
		t.Fatalf("the next scan must not resume from a finished generation, skipped %v",
			fresh.Coverage.Counters["identities_resumed_past"])
	}
	if got := fake.calls["GetRolePolicy"]; got != roleCount {
		t.Fatalf("the next scan must re-read every identity, made %d of %d calls", got, roleCount)
	}
	t.Logf("PASS: next scan advanced to generation %d and re-read all %d identities",
		fresh.Generation, roleCount)

	// Every identity ends up with its permissions, across the two attempts --
	// the point of the whole exercise.
	perms, err := repositories.NewCloudPermissionRepository(db).ListPermissions(ws, nil)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	if len(perms) == 0 {
		t.Fatal("the resumed identities must have their permissions written")
	}
	t.Logf("PASS: %d permission rows present after the resumed attempt", len(perms))
}

// KNOWN LIMITATION, proven by the shape of the test above.
//
// The checkpoint mechanism works, but the live scan chain cannot yet produce the
// state it resumes from. AWSIAMScanner.Scan calls commitScan on every path --
// complete AND partial -- so any Scan() that returns advances
// scan_generation. The next scan therefore computes a NEW generation, finds no
// checkpoint at it, and re-fetches everything.
//
// Meanwhile the cursor is advanced by AWSPermissionScanner, which runs after the
// identity scan has already committed. So the only interruption that would leave
// a usable checkpoint -- the process dying inside the policy fetch -- happens
// before any checkpoint has been written at all.
//
// Closing this needs the generation to stop advancing until the whole chain
// finishes, which changes reconciliation timing for all three scanners and the
// expectations in TestIAMRepeatScanUpdatesRatherThanDuplicating. That is a
// deliberate design decision, not a local fix, so it is recorded here rather
// than made quietly.

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
