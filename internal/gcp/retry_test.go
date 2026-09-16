package gcp

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Retry's contract is as much about what it REFUSES to retry as about what it
// retries. A permission denial retried five times is still a permission denial,
// and the quota spent finding that out belongs to the surfaces that could have
// been read instead.

// fastRetries removes the real backoff sleeps so an exhaustion test costs
// milliseconds instead of ten seconds. The delay CURVE is still tested
// directly, by TestRetryDelay_*, which calls retryDelay without sleeping.
func fastRetries(t *testing.T) {
	t.Helper()
	orig := retrySleep
	retrySleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { retrySleep = orig })
}

func googleErr(code int) error {
	return &googleapi.Error{Code: code, Message: "synthetic"}
}

func googleErrWithHeader(code int, key, value string) error {
	h := http.Header{}
	h.Set(key, value)
	return &googleapi.Error{Code: code, Message: "synthetic", Header: h}
}

func TestRetry_TransientThenSuccess(t *testing.T) {
	fastRetries(t)
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"429 too many requests", googleErr(http.StatusTooManyRequests)},
		{"500 internal", googleErr(http.StatusInternalServerError)},
		{"502 bad gateway", googleErr(http.StatusBadGateway)},
		{"503 unavailable", googleErr(http.StatusServiceUnavailable)},
		{"504 gateway timeout", googleErr(http.StatusGatewayTimeout)},
		{"grpc RESOURCE_EXHAUSTED", status.Error(codes.ResourceExhausted, "quota")},
		{"grpc UNAVAILABLE", status.Error(codes.Unavailable, "try later")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := Retry(context.Background(), func() error {
				calls++
				if calls == 1 {
					return tc.err
				}
				return nil
			})
			if err != nil {
				t.Fatalf("expected recovery, got %v", err)
			}
			if calls != 2 {
				t.Fatalf("expected 2 calls, got %d", calls)
			}
		})
	}
}

// The allow-list half: a permanent failure must cost exactly one call.
func TestRetry_PermanentFailuresAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"400 invalid argument", googleErr(http.StatusBadRequest)},
		{"401 unauthenticated", googleErr(http.StatusUnauthorized)},
		{"403 permission denied", googleErr(http.StatusForbidden)},
		{"404 not found", googleErr(http.StatusNotFound)},
		{"409 conflict", googleErr(http.StatusConflict)},
		{"412 precondition failed", googleErr(http.StatusPreconditionFailed)},
		{"grpc PERMISSION_DENIED", status.Error(codes.PermissionDenied, "nope")},
		{"a plain error nobody classified", errors.New("something unexpected")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := Retry(context.Background(), func() error {
				calls++
				return tc.err
			})
			if err == nil {
				t.Fatal("expected the error to propagate")
			}
			if calls != 1 {
				t.Fatalf("a permanent failure was retried: %d calls", calls)
			}
		})
	}
}

// A constraint is the customer's own deliberate policy. It will refuse
// identically every time and retrying is pure waste.
func TestRetry_ConstraintsAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
	}{
		{"vpc service controls", "Request is prohibited by organization's policy: vpcServiceControlsUniqueIdentifier"},
		{"org policy constraint", "denied by constraints/iam.disableServiceAccountKeyCreation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := Retry(context.Background(), func() error {
				calls++
				return errors.New(tc.msg)
			})
			if err == nil {
				t.Fatal("expected the error to propagate")
			}
			if calls != 1 {
				t.Fatalf("a constrained read was retried: %d calls", calls)
			}
		})
	}
}

// When retries run out on a throttle, the caller has to be able to tell that
// apart from a denial -- it is the difference between "ask GCP again later" and
// "ask the customer to grant a role", and between two different coverage
// states.
func TestRetry_ExhaustedThrottleIsClassifiable(t *testing.T) {
	fastRetries(t)
	calls := 0
	err := Retry(context.Background(), func() error {
		calls++
		return googleErr(http.StatusTooManyRequests)
	})
	if err == nil {
		t.Fatal("expected failure after the budget ran out")
	}
	if !IsThrottle(err) {
		t.Fatalf("an exhausted throttle was not classifiable as one: %v", err)
	}
	if !errors.Is(err, ErrThrottled) {
		t.Fatalf("expected ErrThrottled in the chain, got %v", err)
	}
	if calls != retryMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", retryMaxAttempts, calls)
	}
}

// A 500 that never recovers is a failure, but it is NOT a throttle -- saying it
// was would tell an operator to wait for quota that was never the problem.
func TestRetry_ExhaustedServerErrorIsNotAThrottle(t *testing.T) {
	fastRetries(t)
	err := Retry(context.Background(), func() error {
		return googleErr(http.StatusInternalServerError)
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if IsThrottle(err) {
		t.Fatalf("a 500 was misreported as a throttle: %v", err)
	}
}

func TestRetry_StopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	err := Retry(ctx, func() error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("a cancelled scan still called GCP %d times", calls)
	}
}

// A phase whose deadline expires mid-retry must stop calling GCP rather than
// working through the rest of its budget.
func TestRetry_StopsWhenDeadlineExpiresMidBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	calls := 0
	err := Retry(ctx, func() error {
		calls++
		return googleErr(http.StatusTooManyRequests)
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if calls >= retryMaxAttempts {
		t.Fatalf("the deadline did not cut the retry short: %d calls", calls)
	}
}

/* ------------------------------- Retry-After -------------------------------- */

func TestRetryAfter_SecondsFormIsHonoured(t *testing.T) {
	d, ok := retryAfter(googleErrWithHeader(http.StatusTooManyRequests, "Retry-After", "7"))
	if !ok {
		t.Fatal("Retry-After in seconds was not read")
	}
	if d != 7*time.Second {
		t.Fatalf("got %v, want 7s", d)
	}
}

func TestRetryAfter_HTTPDateFormIsHonoured(t *testing.T) {
	when := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	d, ok := retryAfter(googleErrWithHeader(http.StatusTooManyRequests, "Retry-After", when))
	if !ok {
		t.Fatal("Retry-After as an HTTP date was not read")
	}
	if d <= 0 || d > 6*time.Second {
		t.Fatalf("got %v, want something just under 5s", d)
	}
}

// GCP is entitled to say "come back in an hour". A scan holding a credential
// and a database connection is not entitled to sleep for one.
func TestRetryDelay_RetryAfterIsCapped(t *testing.T) {
	err := googleErrWithHeader(http.StatusTooManyRequests, "Retry-After", "3600")
	if d := retryDelay(err, 1); d > retryMaxRetryAfter {
		t.Fatalf("delay %v exceeded the cap %v", d, retryMaxRetryAfter)
	}
}

func TestRetryDelay_GrowsAndIsCapped(t *testing.T) {
	plain := googleErr(http.StatusTooManyRequests)
	// Jitter is +/-20%, so compare generously: the point is the curve grows and
	// then stops, not that any single draw hits an exact value.
	early := retryDelay(plain, 1)
	late := retryDelay(plain, 4)
	if late <= early {
		t.Fatalf("backoff did not grow: attempt 1 = %v, attempt 4 = %v", early, late)
	}
	ceiling := time.Duration(float64(retryMaxDelay) * 1.2)
	for attempt := 1; attempt <= 12; attempt++ {
		if d := retryDelay(plain, attempt); d > ceiling {
			t.Fatalf("attempt %d delay %v exceeded the jittered ceiling %v", attempt, d, ceiling)
		}
	}
}

func TestRetryDelay_IsJittered(t *testing.T) {
	// Lockstep retries across a fan-out reproduce the burst that caused the
	// throttle, so identical inputs must not produce identical delays.
	plain := googleErr(http.StatusTooManyRequests)
	seen := map[time.Duration]bool{}
	for i := 0; i < 20; i++ {
		seen[retryDelay(plain, 3)] = true
	}
	if len(seen) == 1 {
		t.Fatal("every delay was identical; the jitter is not applied")
	}
}
