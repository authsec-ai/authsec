package integration

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"gorm.io/gorm"
)

// What a policy statement's NARROWING half does between AWS and the database.
//
// The parser learning to keep Condition, NotAction and NotResource is only half
// a fix: the repository rejected statements without Action, and its conflict
// clause did not refresh any of the new columns. A parser test cannot see
// either, which is why these go through a real scan into a real database.

const constrainedRoleARN = "arn:aws:iam::429418377036:role/constrained"

func iamWithConstrainedPolicies(inline map[string]string) *fakeIAM {
	f := newFakeIAM()
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	f.roles = []iamtypes.Role{{
		Arn: aws.String(constrainedRoleARN), RoleName: aws.String("constrained"),
		RoleId: aws.String("AROAEXAMPLECONS"), Path: aws.String("/"),
		CreateDate:               ago(10 * 24 * time.Hour),
		AssumeRolePolicyDocument: aws.String(url.QueryEscape(trust)),
	}}
	f.inlineRolePolicies["constrained"] = inline
	return f
}

// permissionsFor returns this workspace's permission rows keyed by native id.
func permissionsFor(t *testing.T, db *gorm.DB, ws any) map[string]models.CloudPermission {
	t.Helper()
	var rows []models.CloudPermission
	if err := db.Where("workspace_id = ?", ws).Find(&rows).Error; err != nil {
		t.Fatalf("read permissions: %v", err)
	}
	out := map[string]models.CloudPermission{}
	for _, r := range rows {
		out[r.NativeID] = r
	}
	return out
}

func TestNotActionStatementReachesTheDatabase(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-constraint-notaction")
	defer cleanPermissionTables(t, db, ws)

	// A Deny written with NotAction. The parser keeps it; the repository used
	// to reject it with "native_id, effect, scope_kind and actions are
	// required", so the Deny was lost after the parser fix.
	fake := iamWithConstrainedPolicies(map[string]string{
		"deny-all-but-read": `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Deny","NotAction":["s3:GetObject"],"Resource":"*"}]}`,
	})

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake).Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake).
		ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("permission scan: %v", err)
	}

	rows := permissionsFor(t, db, ws)
	if len(rows) != 1 {
		t.Fatalf("expected the Deny to be stored, got %d rows", len(rows))
	}
	for id, r := range rows {
		if r.Effect != "deny" {
			t.Errorf("%s: effect = %q, want deny", id, r.Effect)
		}
		if len(r.NotActions) != 1 || r.NotActions[0] != "s3:GetObject" {
			t.Errorf("%s: not_actions = %v, want [s3:GetObject]", id, r.NotActions)
		}
		if r.ConstraintState != models.ConstraintNegated {
			t.Errorf("%s: constraint_state = %q, want negated", id, r.ConstraintState)
		}
	}
}

func TestAddingAConditionInAWSUpdatesTheStoredRow(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-constraint-rescan")
	defer cleanPermissionTables(t, db, ws)

	const plain = `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}`
	const gated = `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalTag/Team":"operations"}}}]}`

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	scan := func(doc string) {
		t.Helper()
		fake := iamWithConstrainedPolicies(map[string]string{"reports": doc})
		snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake).Scan(context.Background(), ws, c.ID)
		if err != nil {
			t.Fatalf("identity scan: %v", err)
		}
		if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake).
			ScanFromSnapshot(context.Background(), ws, snap); err != nil {
			t.Fatalf("permission scan: %v", err)
		}
	}

	scan(plain)
	before := permissionsFor(t, db, ws)
	if len(before) != 1 {
		t.Fatalf("expected 1 row after first scan, got %d", len(before))
	}
	for _, r := range before {
		if r.ConstraintState != models.ConstraintUnconstrained {
			t.Fatalf("first scan: constraint_state = %q, want unconstrained", r.ConstraintState)
		}
	}

	// The customer adds a condition in AWS. The statement keeps its position,
	// so the row's natural key is unchanged and the rescan takes the conflict
	// path -- the exact path whose update clause omitted these columns.
	scan(gated)

	after := permissionsFor(t, db, ws)
	if len(after) != 1 {
		t.Fatalf("expected 1 row after rescan, got %d -- the rescan duplicated", len(after))
	}
	for id, r := range after {
		if r.Condition == nil {
			t.Fatalf("%s: condition is NULL after rescan -- a now-gated grant still reads as unconditional", id)
		}
		if r.ConstraintState != models.ConstraintConditional {
			t.Errorf("%s: constraint_state = %q, want conditional", id, r.ConstraintState)
		}
	}
}

func TestRemovingAConditionInAWSClearsTheStoredRow(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-constraint-cleared")
	defer cleanPermissionTables(t, db, ws)

	const gated = `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalTag/Team":"operations"}}}]}`
	const plain = `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}`

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	scan := func(doc string) {
		t.Helper()
		fake := iamWithConstrainedPolicies(map[string]string{"reports": doc})
		snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake).Scan(context.Background(), ws, c.ID)
		if err != nil {
			t.Fatalf("identity scan: %v", err)
		}
		if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake).
			ScanFromSnapshot(context.Background(), ws, snap); err != nil {
			t.Fatalf("permission scan: %v", err)
		}
	}

	scan(gated)
	scan(plain)

	for id, r := range permissionsFor(t, db, ws) {
		if r.Condition != nil {
			t.Errorf("%s: condition still set after the customer removed it", id)
		}
		if r.ConstraintState != models.ConstraintUnconstrained {
			t.Errorf("%s: constraint_state = %q, want unconstrained", id, r.ConstraintState)
		}
	}
}

// --- a run that could not read everything must not delete anything ---------

func TestMalformedTrustPolicyDoesNotDeleteExistingEdges(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-malformed-trust")
	defer cleanPermissionTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	good := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	broken := `{"Version":"2012-10-17","Statement":[{"Effect":`

	// EKS must SUCCEED here. With it denied the scan is incomplete for an
	// unrelated reason, reconciliation never runs, and the test would pass
	// without exercising the thing it is about.
	scan := func(trust string) *services.PermissionSnapshot {
		t.Helper()
		f := newFakeIAM()
		f.roles = []iamtypes.Role{{
			Arn: aws.String(constrainedRoleARN), RoleName: aws.String("constrained"),
			RoleId: aws.String("AROAEXAMPLECONS"), Path: aws.String("/"),
			CreateDate:               ago(10 * 24 * time.Hour),
			AssumeRolePolicyDocument: aws.String(url.QueryEscape(trust)),
		}}
		snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(f).Scan(context.Background(), ws, c.ID)
		if err != nil {
			t.Fatalf("identity scan: %v", err)
		}
		permSnap, err := services.NewAWSPermissionScanner(db, svc).
			WithIAMAPI(f).WithEKSAPI(newFakeEKS()).
			ScanFromSnapshot(context.Background(), ws, snap)
		if err != nil {
			t.Fatalf("permission scan: %v", err)
		}
		return permSnap
	}

	first := scan(good)
	if !first.Complete {
		t.Fatalf("test setup: the first scan must be Complete, or reconciliation never runs: %+v", first.Surfaces)
	}
	if first.EdgesWritten == 0 {
		t.Fatal("expected a trust edge from the first scan")
	}
	var before int64
	db.Raw(`SELECT count(*) FROM cloud_assume_edge WHERE workspace_id = ?`, ws).Scan(&before)
	if before == 0 {
		t.Fatal("expected assume edges to be stored")
	}

	// The document becomes unreadable. AWS did not remove the trust; we simply
	// cannot parse what it returned. Every other surface succeeds, so without
	// the parse-failure gate this run reports Complete and reconciliation
	// deletes the previous generation's edges.
	second := scan(broken)
	if second.ParseFailures == 0 {
		t.Fatal("expected a parse failure to be counted")
	}
	if second.Complete {
		t.Error("scan reported Complete despite a parse failure -- this is what licenses deletion")
	}

	var after int64
	db.Raw(`SELECT count(*) FROM cloud_assume_edge WHERE workspace_id = ?`, ws).Scan(&after)
	if after != before {
		t.Fatalf("assume edges went from %d to %d: a document we could not parse deleted real edges", before, after)
	}
}

func TestSkippedStatementDoesNotRenumberItsNeighbours(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-statement-identity")
	defer cleanPermissionTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	// Statement 0 has no Effect and cannot be used. Statement 1 is fine and
	// must keep index 1 -- numbering the compacted slice would call it #s0 and
	// silently repoint whatever #s0 used to mean.
	doc := `{"Version":"2012-10-17","Statement":[` +
		`{"Action":"s3:GetObject","Resource":"*"},` +
		`{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`

	f := iamWithConstrainedPolicies(map[string]string{"mixed": doc})
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(f).Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	if _, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(f).
		ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("permission scan: %v", err)
	}

	rows := permissionsFor(t, db, ws)
	if _, ok := rows["inline:mixed#s1"]; !ok {
		keys := make([]string, 0, len(rows))
		for k := range rows {
			keys = append(keys, k)
		}
		t.Fatalf("expected the usable statement to keep index 1, got %v", keys)
	}
}

func TestUnusableStatementDoesNotDeleteItsPreviousPermission(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-skipped-statement")
	defer cleanPermissionTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	// Same statement, before and after it loses its Effect in AWS. The second
	// form parses fine as a document -- so ParseFailures stays zero -- but the
	// statement itself cannot be used, and its permission row from the previous
	// generation would be the one reconciliation removes.
	usable := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}`
	unusable := `{"Version":"2012-10-17","Statement":[` +
		`{"Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}`

	scan := func(doc string) *services.PermissionSnapshot {
		t.Helper()
		f := iamWithConstrainedPolicies(map[string]string{"reports": doc})
		snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(f).Scan(context.Background(), ws, c.ID)
		if err != nil {
			t.Fatalf("identity scan: %v", err)
		}
		permSnap, err := services.NewAWSPermissionScanner(db, svc).
			WithIAMAPI(f).WithEKSAPI(newFakeEKS()).
			ScanFromSnapshot(context.Background(), ws, snap)
		if err != nil {
			t.Fatalf("permission scan: %v", err)
		}
		return permSnap
	}

	first := scan(usable)
	if !first.Complete {
		t.Fatalf("test setup: first scan must be Complete or reconciliation never runs: %+v", first.Surfaces)
	}
	var before int64
	db.Raw(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ?`, ws).Scan(&before)
	if before == 0 {
		t.Fatal("expected a permission row from the first scan")
	}

	second := scan(unusable)
	if second.ParseFailures != 0 {
		t.Fatalf("the document parses; only the statement is unusable (ParseFailures=%d)", second.ParseFailures)
	}
	if second.StatementsSkipped == 0 {
		t.Fatal("expected the unusable statement to be counted as skipped")
	}
	if second.Complete {
		t.Error("scan reported Complete with a skipped statement -- this is what licenses deletion")
	}

	var after int64
	db.Raw(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ?`, ws).Scan(&after)
	if after != before {
		t.Fatalf("permissions went from %d to %d: a statement we could not read deleted a real grant", before, after)
	}
}
