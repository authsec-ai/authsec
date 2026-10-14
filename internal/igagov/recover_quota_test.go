package igagov

import "testing"

// §8.5 retryable vs terminal, precisely (fix/p3-tidy): only IAM's RATE
// limits are retryable; LimitExceeded is an account quota (HTTP 409,
// "beyond the current AWS account limits") and is terminal on every op.
func TestClassifyThrottleVersusQuota(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	ap, u := tp.Apply, *tp.Undo
	empty := s.readFor(roleID, ap)
	for _, code := range []string{"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException"} {
		for i := range ap.Ops {
			if got := ClassifyOpResponse(ap, i, RespError, code, empty); got.Outcome != OutcomeRetryable || got.Reason != "throttled" {
				t.Errorf("%s on apply op %d (%s): %+v, want retryable throttled", code, i, ap.Ops[i].Op, got)
			}
		}
		if !IsIAMThrottle(code) {
			t.Errorf("IsIAMThrottle(%s) = false", code)
		}
	}
	// LimitExceeded: terminal on CreatePolicy (policy-count quota) and
	// PutRolePermissionsBoundary; never retryable on any undo op (where the
	// recognition column may still find the op already done).
	for i := range ap.Ops {
		if got := ClassifyOpResponse(ap, i, RespError, "LimitExceeded", empty); got.Outcome != OutcomeTerminal || got.Reason != "quota_exceeded" {
			t.Errorf("LimitExceeded on apply op %d (%s): %+v, want terminal quota_exceeded", i, ap.Ops[i].Op, got)
		}
	}
	for i := range u.Ops {
		if got := ClassifyOpResponse(u, i, RespError, "LimitExceeded", s.readFor(roleID, u)); got.Outcome == OutcomeRetryable {
			t.Errorf("LimitExceeded on undo op %d (%s): %+v, want never retryable", i, u.Ops[i].Op, got)
		}
	}
	for _, code := range []string{"LimitExceeded", "LimitExceededException", "ConcurrentModification", "AccessDenied", ""} {
		if IsIAMThrottle(code) {
			t.Errorf("IsIAMThrottle(%q) = true, want false (not a rate limit)", code)
		}
	}
}
