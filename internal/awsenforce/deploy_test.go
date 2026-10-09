package awsenforce_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// T3.10 (SPEC-iga-phase3-policy.md §3.5, §3.6, §4.4, §8.1, §8.5; A11): the
// AWS side of a deployment without a database -- session naming, request
// resolution and hashing after ${deployment_id} substitution, the response
// kinds (an error without a definitive AWS answer is never "an answer"), the
// discovery-role read into igagov.LiveRead, version-selector resolution, and
// forced writes on ineligible roles refused by the enforcement role's
// template policy (the fake simulates the REAL template, so editing it
// changes the result as it would in AWS).

const sqsOnly = `{"Version":"2012-10-17","Statement":[{"Sid":"AuthSecAllowAllExceptRemoved","Effect":"Allow","NotAction":["sqs:*"],"Resource":"*"}]}`

func TestP3T310DeploymentSessionName(t *testing.T) {
	id := uuid.MustParse("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
	if got := awsenforce.DeploymentSessionName(id); got != "authsec-enforce-0f1e2d3c4b5a6978" {
		t.Fatalf("session name %q", got)
	}
	if awsenforce.DeploymentSessionName(id) == awsenforce.SelfTestSessionName(id) {
		t.Fatal("a deployment session must never be named like a self-test session")
	}
}

func TestP3T310NewRequestSubstitutesAndHashes(t *testing.T) {
	op := igagov.Op{Op: igagov.OpCreatePolicy, PolicyARN: "arn:aws:iam::429418377036:policy/authsec/AuthSecBoundary-AROAX",
		PolicyName: "AuthSecBoundary-AROAX", Path: "/authsec/", DocumentHash: "sha256:" + strings.Repeat("a", 64),
		Tags: map[string]string{igagov.TagChange: igagov.DeploymentPlaceholder, igagov.TagControl: "ctl"}}
	d1, d2 := uuid.New(), uuid.New()
	r1, err := awsenforce.NewRequest(op, d1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Tags[igagov.TagChange] != d1.String() || r1.Tags[igagov.TagControl] != "ctl" {
		t.Fatalf("tags %v", r1.Tags)
	}
	r2, _ := awsenforce.NewRequest(op, d2, "", "")
	h1, _ := r1.Hash()
	h1b, _ := r1.Hash()
	h2, _ := r2.Hash()
	if !strings.HasPrefix(h1, "sha256:") || h1 != h1b || h1 == h2 {
		t.Fatalf("request hash must be stable per deployment and differ across deployments: %s %s %s", h1, h1b, h2)
	}
	// The op itself is not modified (the plan is immutable).
	if op.Tags[igagov.TagChange] != igagov.DeploymentPlaceholder {
		t.Fatal("NewRequest modified the plan's op")
	}
	// Refusals: a placeholder outside a tag value, a selector without a
	// version, a version for another op, a step on another role.
	bad := op
	bad.PolicyName = "x-" + igagov.DeploymentPlaceholder
	if _, err := awsenforce.NewRequest(bad, d1, "", ""); !errors.Is(err, awsenforce.ErrUnresolvedOp) {
		t.Fatalf("placeholder in a name: %v", err)
	}
	sel := igagov.Op{Op: igagov.OpDeletePolicyVersion, PolicyARN: op.PolicyARN, Select: igagov.SelectOldestNonDefault, IfVersionsAtLeast: 5}
	if _, err := awsenforce.NewRequest(sel, d1, "", ""); !errors.Is(err, awsenforce.ErrUnresolvedOp) {
		t.Fatalf("unresolved selector: %v", err)
	}
	rv, err := awsenforce.NewRequest(sel, d1, "v2", "")
	if err != nil || rv.VersionID != "v2" {
		t.Fatalf("resolved selector: %+v %v", rv, err)
	}
	if _, err := awsenforce.NewRequest(op, d1, "v2", ""); !errors.Is(err, awsenforce.ErrUnresolvedOp) {
		t.Fatalf("version on CreatePolicy: %v", err)
	}
	other := igagov.Op{Op: igagov.OpPutRolePermissionsBoundary, RoleARN: "arn:aws:iam::1:role/x", PolicyARN: op.PolicyARN}
	if _, err := awsenforce.NewRequest(other, d1, "", "x"); !errors.Is(err, awsenforce.ErrUnresolvedOp) {
		t.Fatalf("another role's step: %v", err)
	}
	if _, err := awsenforce.NewRequest(igagov.Op{Op: igagov.OpCreateRole}, d1, "", ""); !errors.Is(err, awsenforce.ErrUnresolvedOp) {
		t.Fatalf("a dedicated-identity step: %v", err)
	}
}

// fix/p3-tidy: a role op must name exactly the control's role, a policy op
// none; anything else is ErrOpRoleMismatch before a request exists.
func TestP3TidyNewRequestChecksTheControlsRole(t *testing.T) {
	d := uuid.New()
	arn := "arn:aws:iam::429418377036:policy/authsec/AuthSecBoundary-AROAX"
	for _, op := range []igagov.Op{
		{Op: igagov.OpPutRolePermissionsBoundary, RoleName: "AppRole", PolicyARN: arn},
		{Op: igagov.OpDeleteRolePermissionsBoundary, RoleName: "AppRole"},
	} {
		if r, err := awsenforce.NewRequest(op, d, "", "AppRole"); err != nil || r.RoleName != "AppRole" {
			t.Fatalf("%s on the control's role: %+v %v", op.Op, r, err)
		}
		for _, control := range []string{"OtherRole", "approle", ""} {
			if _, err := awsenforce.NewRequest(op, d, "", control); !errors.Is(err, awsenforce.ErrOpRoleMismatch) {
				t.Fatalf("%s naming AppRole for control role %q: %v, want ErrOpRoleMismatch", op.Op, control, err)
			}
		}
		empty := op
		empty.RoleName = ""
		if _, err := awsenforce.NewRequest(empty, d, "", "AppRole"); !errors.Is(err, awsenforce.ErrOpRoleMismatch) {
			t.Fatalf("%s naming no role: %v, want ErrOpRoleMismatch", op.Op, err)
		}
	}
	pol := igagov.Op{Op: igagov.OpDeletePolicy, PolicyARN: arn, RoleName: "AppRole"}
	if _, err := awsenforce.NewRequest(pol, d, "", "AppRole"); !errors.Is(err, awsenforce.ErrOpRoleMismatch) {
		t.Fatalf("a policy op naming a role: %v, want ErrOpRoleMismatch", err)
	}
}

func TestP3T310ClassifyCallError(t *testing.T) {
	resp500 := &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 503}},
		Err:      enforcetest.APIError("ServiceUnavailable", "down")}, RequestID: "req-503"}
	cases := []struct {
		name string
		err  error
		kind igagov.ResponseKind
		code string
	}{
		{"ok", nil, igagov.RespOK, ""},
		{"access denied", enforcetest.APIError("AccessDenied", "no"), igagov.RespError, "AccessDenied"},
		{"throttled", enforcetest.APIError("Throttling", "slow down"), igagov.RespError, "Throttling"},
		{"service failure", enforcetest.APIError("ServiceFailure", "oops"), igagov.RespNoAnswer, "ServiceFailure"},
		{"5xx", resp500, igagov.RespNoAnswer, "ServiceUnavailable"},
		{"timeout", context.DeadlineExceeded, igagov.RespNoAnswer, ""},
		{"connection reset", errors.New("read tcp: connection reset by peer"), igagov.RespNoAnswer, ""},
	}
	for _, c := range cases {
		got := awsenforce.ClassifyCallError(c.err)
		if got.Kind != c.kind || got.ErrorCode != c.code {
			t.Errorf("%s: kind %v code %q, want %v %q", c.name, got.Kind, got.ErrorCode, c.kind, c.code)
		}
	}
	if got := awsenforce.ClassifyCallError(resp500); got.RequestID != "req-503" {
		t.Errorf("request id of an error: %q", got.RequestID)
	}
}

// A fake account with a role that has permission policies, an inline
// policy, an AuthSec boundary, and a second role using that boundary.
func readFixture(t *testing.T) (*enforcetest.FakeAWS, string) {
	t.Helper()
	f := newFake(t)
	r := f.AddRole("RefundTaskRole", "/app/", map[string]string{"team": "refunds"})
	r.Inline["inline-sqs"] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}`
	cust := f.AddPolicy("/", "RefundAccess", nil, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	f.AttachPermissions("RefundTaskRole", cust.ARN)
	b := f.AddPolicy("/authsec/", "AuthSecBoundary-"+r.RoleID, map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue}, sqsOnly)
	f.SetBoundary("RefundTaskRole", b.ARN)
	f.AddRole("ReportsRole", "/", nil)
	f.AttachPermissions("ReportsRole", b.ARN)
	return f, b.ARN
}

func TestP3T310ReadForPlanFromDiscovery(t *testing.T) {
	f, boundary := readFixture(t)
	missing := f.PolicyARN("/authsec/", "AuthSecBoundary-gone")
	plan := igagov.Plan{Ops: []igagov.Op{{Op: igagov.OpDeletePolicy, PolicyARN: missing}}}
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	live, detail, err := awsenforce.ReadForPlan(context.Background(), f.Discovery(), "RefundTaskRole", plan, now)
	if err != nil {
		t.Fatal(err)
	}
	r := live.Role
	if r == nil || r.RoleID != enforcetest.FakeRoleID("RefundTaskRole") || r.Path != "/app/" || r.AccountID != acct ||
		r.BoundaryARN != boundary || r.Tags["team"] != "refunds" || len(r.ManagedPolicies) != 1 || len(r.InlinePolicies) != 1 ||
		!strings.HasPrefix(r.ManagedPolicies[0].DocumentHash, "sha256:") || r.TrustPolicyHash == "" {
		t.Fatalf("role read: %+v", r)
	}
	p := live.Policies[boundary]
	if p == nil || p.VersionCount != 1 || p.Tags[igagov.TagManagedBy] != igagov.TagManagedByValue || detail.DefaultVersion[boundary] != "v1" {
		t.Fatalf("boundary read: %+v %v", p, detail)
	}
	usages := map[string]string{}
	for _, e := range p.AttachmentSet {
		usages[e.Name] = e.Usage
	}
	if usages["RefundTaskRole"] != igagov.UsageBoundary || usages["ReportsRole"] != igagov.UsagePermissions {
		t.Fatalf("attachment set must cover every usage type: %+v", p.AttachmentSet)
	}
	if v, ok := live.Policies[missing]; !ok || v != nil {
		t.Fatalf("NoSuchEntity must be a nil entry: %v %v", v, ok)
	}
	// The read is what the compiler's artifact_state is built from.
	st, err := igagov.ArtifactState(live)
	if err != nil || st.BoundaryARN == nil || *st.BoundaryARN != boundary || len(st.AttachmentSet) != 2 {
		t.Fatalf("artifact_state: %+v %v", st, err)
	}
	// A gone role reads as nil (the classifier reports role_gone).
	gone, _, err := awsenforce.ReadForPlan(context.Background(), f.Discovery(), "NoSuchRole", plan, now)
	if err != nil || gone.Role != nil {
		t.Fatalf("gone role: %+v %v", gone.Role, err)
	}
	// A read failure is an error, never a silent absence.
	f.ReadFail["iam:ListEntitiesForPolicy"] = enforcetest.APIError("AccessDenied", "no")
	if _, _, err := awsenforce.ReadForPlan(context.Background(), f.Discovery(), "RefundTaskRole", plan, now); err == nil {
		t.Fatal("a failed read must not produce a LiveRead")
	}
}

func TestP3T310ResolveVersionSelector(t *testing.T) {
	f := newFake(t)
	docs := []string{}
	for _, s := range []string{"ec2", "sns", "sqs", "kms", "ecr"} {
		docs = append(docs, strings.Replace(sqsOnly, "sqs:*", s+":*", 1))
	}
	m := f.AddPolicy("/authsec/", "AuthSecBoundary-AROAV", nil, docs...)
	ctx := context.Background()
	oldest := igagov.Op{Op: igagov.OpDeletePolicyVersion, PolicyARN: m.ARN, Select: igagov.SelectOldestNonDefault, IfVersionsAtLeast: 5}
	got, err := awsenforce.ResolveVersionSelector(ctx, f.Discovery(), oldest)
	if err != nil || len(got) != 1 || got[0].VersionID != "v1" || got[0].Document != docs[0] {
		t.Fatalf("oldest non-default of 5: %+v %v", got, err)
	}
	all := igagov.Op{Op: igagov.OpDeletePolicyVersion, PolicyARN: m.ARN, Select: igagov.SelectAllNonDefault}
	got, _ = awsenforce.ResolveVersionSelector(ctx, f.Discovery(), all)
	if len(got) != 4 || got[0].VersionID != "v1" || got[3].VersionID != "v4" {
		t.Fatalf("all non-default: %+v", got)
	}
	// After one prune there are 4 versions: the condition makes a re-sent
	// prune a no-op.
	if err := f.DeletePolicyVersion(ctx, m.ARN, "v1"); err != nil {
		t.Fatal(err)
	}
	if got, _ = awsenforce.ResolveVersionSelector(ctx, f.Discovery(), oldest); len(got) != 0 {
		t.Fatalf("prune with 4 versions: %+v", got)
	}
	// A deleted policy has nothing to delete.
	gone := igagov.Op{Op: igagov.OpDeletePolicyVersion, PolicyARN: f.PolicyARN("/authsec/", "nope"), Select: igagov.SelectAllNonDefault}
	if got, err = awsenforce.ResolveVersionSelector(ctx, f.Discovery(), gone); err != nil || len(got) != 0 {
		t.Fatalf("gone policy: %+v %v", got, err)
	}
}

// A11 at the AWS boundary: whatever AuthSec's own eligibility check says, the
// enforcement role's template refuses to put or remove a boundary on a
// service-linked role, a role tagged ManagedBy=AuthSec and a role tagged
// authsec:protected=true; the refusal is a definitive answer the §8.5 table
// classifies as terminal, and nothing in the account changes. Editing the
// template (dropping the deny) changes the answer, as it would in AWS.
func TestP3T310ForcedWritesRefusedByTemplateA11(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	b := f.AddPolicy("/authsec/", "AuthSecBoundary-forced", map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue}, sqsOnly)
	roles := []*enforcetest.Role{
		f.AddRole("AWSServiceRoleForECS", "/aws-service-role/ecs.amazonaws.com/", nil),
		f.AddRole("PaymentsDiscovery", "/", map[string]string{"ManagedBy": "AuthSec"}),
		f.AddRole("LedgerRole", "/", map[string]string{"authsec:protected": "true"}),
	}
	iam, _, err := f.AssumeEnforcement(ctx, awsenforce.AssumeInput{RoleARN: f.RoleARN, ExternalID: extID, Region: "us-east-1",
		SessionName: awsenforce.DeploymentSessionName(uuid.New())})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		for _, op := range []igagov.Op{
			{Op: igagov.OpDeleteRolePermissionsBoundary, RoleName: r.Name},
			{Op: igagov.OpPutRolePermissionsBoundary, RoleName: r.Name, PolicyARN: b.ARN},
		} {
			// Detach: a boundary from before the role became ineligible.
			// Attach: a role without one.
			before, after := b.ARN, igagov.ValueNone
			if op.Op == igagov.OpPutRolePermissionsBoundary {
				before, after = "", b.ARN
			}
			f.SetBoundary(r.Name, before)
			req, err := awsenforce.NewRequest(op, uuid.New(), "", r.Name)
			if err != nil {
				t.Fatal(err)
			}
			resp := awsenforce.Send(ctx, iam, req, "")
			if resp.Kind != igagov.RespError || resp.ErrorCode != "AccessDenied" {
				t.Fatalf("%s %s: %+v, want AccessDenied", op.Op, r.Name, resp)
			}
			fb := before
			if fb == "" {
				fb = igagov.ValueNone
			}
			plan := igagov.Plan{Ops: []igagov.Op{op}, Facts: []igagov.Fact{{Key: igagov.FactRoleBoundary, Kind: igagov.FactRoleBoundary,
				Before: fb, After: after}}}
			live, _, _ := awsenforce.ReadForPlan(ctx, f.Discovery(), r.Name, plan, time.Now())
			if oc := igagov.ClassifyOpResponse(plan, 0, resp.Kind, resp.ErrorCode, live); oc.Outcome != igagov.OutcomeTerminal {
				t.Fatalf("%s %s classified %+v, want terminal", op.Op, r.Name, oc)
			}
			if f.BoundaryOf(r.Name) != before {
				t.Fatalf("%s %s changed the role", op.Op, r.Name)
			}
		}
	}
	// The template decides: without ProtectTaggedRoles, the protected role
	// can be changed (which is why the template is the guard of last resort).
	if !f.RemoveStatement("ProtectTaggedRoles") {
		t.Fatal("template has no ProtectTaggedRoles statement")
	}
	f.SetBoundary("LedgerRole", b.ARN)
	req, _ := awsenforce.NewRequest(igagov.Op{Op: igagov.OpDeleteRolePermissionsBoundary, RoleName: "LedgerRole"}, uuid.New(), "", "LedgerRole")
	if resp := awsenforce.Send(ctx, iam, req, ""); resp.Kind != igagov.RespOK || f.BoundaryOf("LedgerRole") != "" {
		t.Fatalf("after editing the template: %+v", resp)
	}
}

// Send records the request id of an answer and passes the document body.
func TestP3T310SendRecordsRequestIDAndDocument(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	iam, _, err := f.AssumeEnforcement(ctx, awsenforce.AssumeInput{RoleARN: f.RoleARN, ExternalID: extID, Region: "us-east-1",
		SessionName: "authsec-enforce-0000000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	_, h, _ := igagov.CanonicalDocument(sqsOnly)
	req, err := awsenforce.NewRequest(igagov.Op{Op: igagov.OpCreatePolicy, PolicyName: "AuthSecBoundary-AROAS", Path: "/authsec/",
		PolicyARN: f.PolicyARN("/authsec/", "AuthSecBoundary-AROAS"), DocumentHash: h}, uuid.New(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	resp := awsenforce.Send(ctx, iam, req, sqsOnly)
	if resp.Kind != igagov.RespOK || !strings.HasPrefix(resp.RequestID, "fake-req-") {
		t.Fatalf("send: %+v", resp)
	}
	if _, _, doc, _, ok := f.PolicyState(req.PolicyARN); !ok || doc != sqsOnly {
		t.Fatalf("document sent: %q", doc)
	}
	// The same request again is EntityAlreadyExists: a definitive answer.
	if again := awsenforce.Send(ctx, iam, req, sqsOnly); again.Kind != igagov.RespError || again.ErrorCode != "EntityAlreadyExists" {
		t.Fatalf("second create: %+v", again)
	}
}
