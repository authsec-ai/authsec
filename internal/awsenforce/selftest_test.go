package awsenforce_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
)

// T3.09 (§3.6, A22): the self-test's per-capability classification, run
// against a fake account whose every IAM decision simulates the enforcement
// role's REAL policy from the embedded template. Mutating the template (or
// removing a statement, as a customer editing the stack would) changes the
// result the way AWS would.
//
// Safeguards (mutation-checked): State() requiring every capability ok;
// refuses_foreign_boundary counting an ACCEPTED foreign boundary as a
// failure; cleanup after a failed probe.

const (
	acct   = "429418377036"
	suffix = "x7k2m9qp"
	extID  = "enf0123456789abcdef01234567.sigsigsigsigsigsigsigsigsigsigsi"
)

func newFake(t *testing.T) *enforcetest.FakeAWS {
	t.Helper()
	f, err := enforcetest.NewFakeAWSFromTemplate(awsdiscovery.EnforcementCloudFormationTemplate, acct, suffix, extID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func run(f *enforcetest.FakeAWS, bindingID uuid.UUID) awsenforce.Report {
	clock := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	return awsenforce.RunSelfTest(context.Background(), f, awsenforce.SelfTestInput{
		BindingID: bindingID, AccountID: acct, Partition: "aws", RoleARN: f.RoleARN,
		SelfTestRoleARN: f.SelfTestRoleARN(suffix), ExternalID: extID, Region: "us-east-1",
		Now: func() time.Time { clock = clock.Add(time.Second); return clock }, RunID: "run00001",
	})
}

func statuses(r awsenforce.Report) map[string]string {
	out := map[string]string{}
	for c, res := range r.Capabilities {
		s := res.Status
		if res.ErrorCode != "" && res.Status != awsenforce.StatusOK {
			s += ":" + res.ErrorCode
		}
		out[c] = s
	}
	return out
}

func wantStatuses(t *testing.T, r awsenforce.Report, want map[string]string) {
	t.Helper()
	got := statuses(r)
	for _, c := range awsenforce.Capabilities {
		if got[c] != want[c] {
			t.Errorf("%s = %q, want %q (all: %v)", c, got[c], want[c], got)
		}
	}
	if len(got) != len(awsenforce.Capabilities) {
		t.Errorf("report has %d capabilities, want %d: %v", len(got), len(awsenforce.Capabilities), got)
	}
}

// The template as shipped: every capability ok, verified, nothing left behind.
func TestP3EnfSelfTestAllOKIsVerified(t *testing.T) {
	f := newFake(t)
	id := uuid.New()
	r := run(f, id)
	wantStatuses(t, r, map[string]string{
		"assume": "ok", "create_policy": "ok", "version_management": "ok", "attach_boundary": "ok",
		"refuses_foreign_boundary": "ok", "detach_boundary": "ok", "delete_policy": "ok",
	})
	if r.State() != awsenforce.StateVerified || len(r.Failing()) != 0 || r.LeakedPolicyARN != "" {
		t.Fatalf("state %s failing %v leaked %q, want verified", r.State(), r.Failing(), r.LeakedPolicyARN)
	}
	if len(f.Policies) != 0 {
		t.Fatalf("policies left behind: %v", f.Policies)
	}
	for _, r := range f.Roles {
		if r.Boundary != "" {
			t.Fatalf("role %s left with boundary %s", r.Name, r.Boundary)
		}
	}
	// The self-test touched only the self-test role and its own policy.
	for _, call := range f.Calls {
		if strings.Contains(call, ":role/") && !strings.Contains(call, ":role/AuthSecEnforcementSelfTest-"+suffix) {
			t.Errorf("the self-test touched another role: %s", call)
		}
		if strings.Contains(call, ":policy/") && !strings.Contains(call, ":policy/authsec/AuthSecSelfTest-"+id.String()) {
			t.Errorf("the self-test touched another policy: %s", call)
		}
	}
	if len(f.Assumes) != 1 || f.Assumes[0].SessionName != awsenforce.SelfTestSessionName(id) ||
		!strings.HasPrefix(f.Assumes[0].SessionName, "authsec-enforce-selftest-") {
		t.Fatalf("assumes = %+v", f.Assumes)
	}
}

// A22: the stack without DeleteRolePermissionsBoundary -> partial,
// detach_boundary: denied; the test policy cannot be deleted while attached.
func TestP3EnfSelfTestDetachRemovedIsPartial(t *testing.T) {
	f := newFake(t)
	if !f.RemoveStatement("DetachOnlyAuthSecBoundaries") {
		t.Fatal("no DetachOnlyAuthSecBoundaries statement in the template")
	}
	r := run(f, uuid.New())
	wantStatuses(t, r, map[string]string{
		"assume": "ok", "create_policy": "ok", "version_management": "ok", "attach_boundary": "ok",
		"refuses_foreign_boundary": "ok", "detach_boundary": "denied:AccessDenied", "delete_policy": "error:DeleteConflict",
	})
	if r.State() != awsenforce.StatePartial {
		t.Fatalf("state %s, want partial", r.State())
	}
	if f := r.Failing(); len(f) != 2 || f[0] != "detach_boundary: denied (AccessDenied)" {
		t.Fatalf("failing = %v", f)
	}
	if r.LeakedPolicyARN == "" {
		t.Fatal("the undeletable test policy is not reported")
	}
}

// The attach condition removed: AWS accepts a foreign boundary, which the
// self-test must report as a failure, not as "denied", and it puts the test
// boundary back so detach_boundary still probes an AuthSec boundary.
func TestP3EnfSelfTestForeignBoundaryAccepted(t *testing.T) {
	f := newFake(t)
	for i, st := range f.Policy.Statements {
		if st.Sid == "AttachOnlyAuthSecBoundaries" {
			f.Policy.Statements[i].Condition = nil
		}
	}
	r := run(f, uuid.New())
	wantStatuses(t, r, map[string]string{
		"assume": "ok", "create_policy": "ok", "version_management": "ok", "attach_boundary": "ok",
		"refuses_foreign_boundary": "error:" + awsenforce.ErrorCodeForeignBoundaryAccepted,
		"detach_boundary":          "ok", "delete_policy": "ok",
	})
	if r.State() != awsenforce.StatePartial {
		t.Fatalf("state %s, want partial", r.State())
	}
}

// Assume refused (wrong ExternalId): error, every other capability untested,
// no IAM call made.
func TestP3EnfSelfTestAssumeFailsIsError(t *testing.T) {
	f := newFake(t)
	f.ExternalID = "enfsomethingelse.0000000000000000000000000000000000"
	r := run(f, uuid.New())
	if r.State() != awsenforce.StateError || statuses(r)["assume"] != "denied:AccessDenied" {
		t.Fatalf("state %s statuses %v, want error with assume denied", r.State(), statuses(r))
	}
	for _, c := range awsenforce.Capabilities[1:] {
		if r.Capabilities[c].Status != awsenforce.StatusUntested {
			t.Errorf("%s = %s, want untested", c, r.Capabilities[c].Status)
		}
	}
	if len(f.Calls) != 0 {
		t.Fatalf("IAM was called without a session: %v", f.Calls)
	}
}

// Policy writes removed: create denied, everything that needs the policy
// untested, the foreign-boundary probe still runs.
func TestP3EnfSelfTestCreateDeniedLeavesDependentsUntested(t *testing.T) {
	f := newFake(t)
	f.RemoveStatement("ManageAuthSecPolicies")
	r := run(f, uuid.New())
	wantStatuses(t, r, map[string]string{
		"assume": "ok", "create_policy": "denied:AccessDenied", "version_management": "untested",
		"attach_boundary": "untested", "refuses_foreign_boundary": "ok", "detach_boundary": "untested",
		"delete_policy": "untested",
	})
	if r.State() != awsenforce.StatePartial {
		t.Fatalf("state %s, want partial", r.State())
	}
}

// An AWS error that is not a denial is `error` with its code; the session
// landing in another account is `error` too.
func TestP3EnfSelfTestErrorsAndAccountMismatch(t *testing.T) {
	f := newFake(t)
	f.Fail["iam:CreatePolicyVersion"] = enforcetest.APIError("LimitExceeded", "too many versions")
	r := run(f, uuid.New())
	if got := statuses(r)["version_management"]; got != "error:LimitExceeded" || r.State() != awsenforce.StatePartial {
		t.Fatalf("version_management = %q state %s", got, r.State())
	}
	g := newFake(t)
	g.Account = "111111111111"
	r = awsenforce.RunSelfTest(context.Background(), g, awsenforce.SelfTestInput{
		BindingID: uuid.New(), AccountID: acct, RoleARN: g.RoleARN, SelfTestRoleARN: g.SelfTestRoleARN(suffix),
		ExternalID: extID, Region: "us-east-1",
	})
	if r.State() != awsenforce.StateError || r.Capabilities["assume"].ErrorCode != "AccountMismatch" {
		t.Fatalf("account mismatch: %v", statuses(r))
	}
}

// A report missing a capability is never verified.
func TestP3EnfReportStateRule(t *testing.T) {
	ok := awsenforce.CapabilityResult{Status: awsenforce.StatusOK}
	r := awsenforce.Report{Capabilities: map[string]awsenforce.CapabilityResult{}}
	for _, c := range awsenforce.Capabilities {
		r.Capabilities[c] = ok
	}
	if r.State() != awsenforce.StateVerified {
		t.Fatal("all ok is not verified")
	}
	delete(r.Capabilities, awsenforce.CapDeletePolicy)
	if r.State() != awsenforce.StatePartial {
		t.Fatal("a missing capability counted as ok")
	}
	r.Capabilities[awsenforce.CapDeletePolicy] = awsenforce.CapabilityResult{Status: awsenforce.StatusUntested}
	if r.State() != awsenforce.StatePartial {
		t.Fatal("untested counted as ok")
	}
	r.Capabilities[awsenforce.CapAssume] = awsenforce.CapabilityResult{Status: awsenforce.StatusDenied}
	if r.State() != awsenforce.StateError {
		t.Fatal("assume not ok is not error")
	}
}
