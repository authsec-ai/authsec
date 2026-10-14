package integration

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/services"
)

// fix/p3-tidy item 1 (§8.5 "at most 5 attempts within 15 minutes"): the
// retry cap counts only the retryable answers inside the window. Two
// throttled answers 16 minutes ago no longer count, so a fresh throttling
// episode gets its own budget; inside the window the cap still fails the op.
// Real executor, attempt log and PostgreSQL; the clock of both is moved.
func TestP3TidyRetryCapCountsOnlyTheWindow(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("WindowRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())

	at := time.Now().Add(-16 * time.Minute)
	clock := func() time.Time { return at }
	attempts := services.NewIGAGovAttemptLog(l.db).WithClock(clock)
	exec := services.NewIGAGovAWSExecutor(l.db, attempts, l.access).WithSleep(noSleep).WithClock(clock)
	exec.MaxOpAttempts = 2
	l.fake.Fail["iam:PutRolePermissionsBoundary"] = enforcetest.APIError("Throttling", "Rate exceeded")
	defer delete(l.fake.Fail, "iam:PutRolePermissionsBoundary")

	// Two throttled answers, 16 minutes ago: the cap (2) is reached then.
	for i := 0; i < 2; i++ {
		if out, err := l.execute(exec, run, dep); err != nil || out.Result != services.DeployRetryLater || out.Reason != services.DeployReasonThrottled {
			t.Fatalf("old episode, try %d: %+v %v", i, out, err)
		}
	}
	// Now: both are outside the 15-minute window, so the op is tried again.
	at = time.Now()
	out, err := l.execute(exec, run, dep)
	if err != nil || out.Result != services.DeployRetryLater || out.Reason != services.DeployReasonThrottled {
		t.Fatalf("after the window: %+v %v, want retry_later (answers older than 15 min do not count)", out, err)
	}
	// Inside the window the cap still holds: one more retryable answer,
	// then the op fails as exhausted without being sent again.
	if out, err := l.execute(exec, run, dep); err != nil || out.Result != services.DeployRetryLater {
		t.Fatalf("second try in the window: %+v %v", out, err)
	}
	puts := l.calls("iam:PutRolePermissionsBoundary", x.name)
	if out, err := l.execute(exec, run, dep); err != nil || out.Result != services.DeployFailed || out.Reason != services.DeployReasonRetriesExhausted {
		t.Fatalf("exhausted in the window: %+v %v", out, err)
	}
	if got := l.calls("iam:PutRolePermissionsBoundary", x.name); got != puts {
		t.Fatalf("an exhausted op was sent again: %d calls, want %d", got, puts)
	}
	retryable := 0
	for _, a := range l.attemptRows(dep) {
		if a.Outcome != nil && *a.Outcome == "retryable" {
			retryable++
		}
	}
	if retryable != 4 {
		t.Fatalf("%d retryable attempts recorded, want 4 (2 old + 2 in the window)", retryable)
	}
}

// fix/p3-tidy item 1: IAM's LimitExceeded is an account quota (HTTP 409),
// not a rate limit. The op fails terminally (quota_exceeded) after ONE
// attempt; it is never handed back for a retry.
func TestP3TidyQuotaLimitExceededIsTerminal(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("QuotaRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())
	l.fake.Fail["iam:CreatePolicy"] = enforcetest.APIError("LimitExceeded", "Cannot exceed quota for PoliciesPerAccount: 1500")
	defer delete(l.fake.Fail, "iam:CreatePolicy")
	out, err := l.execute(l.exec, run, dep)
	if err != nil || out.Result != services.DeployFailed || out.Reason != "quota_exceeded" || out.RetryAfter != 0 {
		t.Fatalf("LimitExceeded: %+v %v, want failed quota_exceeded (terminal, no retry)", out, err)
	}
	ats := l.attemptRows(dep)
	if len(ats) != 1 || ats[0].Outcome == nil || *ats[0].Outcome != "terminal" || ats[0].ErrorCode != "LimitExceeded" {
		t.Fatalf("attempts %+v, want one terminal LimitExceeded attempt", ats)
	}
	if l.calls("iam:PutRolePermissionsBoundary", x.name) != 0 {
		t.Fatal("the boundary was attached after the policy could not be created")
	}
}

// fix/p3-tidy item 1: an op's role name is checked against the control's
// role before anything is prepared or sent. A stored plan compiled for
// role A but stored under role B's control (its PutRolePermissionsBoundary
// names A) is refused as a terminal op_role_mismatch: no attempt row, no AWS
// call, role A untouched.
func TestP3TidyOpRoleMismatchIsRefused(t *testing.T) {
	l := newX3Lab(t)
	a := l.role("PlannedRole", "/", nil)
	b := l.role("ControlRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), a, "sqs")
	s := l.store(b, tp.Apply, *tp.Undo)
	dep := l.deploy(b, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())
	calls := len(l.fake.Calls)
	out, err := l.execute(l.exec, run, dep)
	if err != nil || out.Result != services.DeployRefused || out.Reason != services.DeployReasonOpRoleMismatch {
		t.Fatalf("op naming another role: %+v %v, want refused op_role_mismatch", out, err)
	}
	if len(l.fake.Calls) != calls || len(l.attemptRows(dep)) != 0 {
		t.Fatalf("a refused plan reached AWS or the attempt log: calls %v, attempts %+v", l.fake.Calls[calls:], l.attemptRows(dep))
	}
	if got := l.fake.BoundaryOf(a.name); got != "" {
		t.Fatalf("role %s got boundary %q", a.name, got)
	}
}
