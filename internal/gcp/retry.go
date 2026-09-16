package gcp

import (
	"context"
	"errors"
	"math"
	mrand "math/rand"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

/* retry.go is the bounded retry for GCP discovery reads.

   WHY THIS EXISTS AT ALL. The typed clients auth.go builds -- iam.NewService,
   cloudasset.NewService, cloudresourcemanager.NewService -- carry no retry
   policy, so a single 429 during a scan currently ends that surface's read.
   The AWS path leans on the AWS SDK's own retryer
   (internal/awsdiscovery/onboarding.go:179-180); google.golang.org/api's REST
   clients have no equivalent for these methods, so it is written here.

   WHAT IS DELIBERATELY NOT RETRIED. A 403, a 400 or a 404 is not a transient
   failure -- it is a FACT about what this reader can reach, and the place for
   it is coverage, not a retry loop. Retrying a permission denial nine times
   turns a clean "denied" report into the same clean "denied" report thirty
   seconds later, and burns quota that the surfaces which CAN be read still
   need. The classifier below is therefore an allow-list of transient codes
   rather than a deny-list of permanent ones: a status nobody has thought about
   is treated as permanent, which fails toward reporting rather than toward
   hammering.

   WHY THE COVERAGE SEMANTICS MATTER MORE THAN THE RETRY. If retries run out,
   the caller must record the surface as throttled -- never reached. A surface
   that was rate-limited into silence and a surface that is genuinely empty are
   indistinguishable by row count, and only one of them means the estate is
   clean. IsThrottle exists so the caller can tell them apart. */

// Retry policy defaults.
//
// Deliberately modest. This is a scan, not a user-facing request: it is better
// to give a surface up and report it throttled -- which blocks reconciliation
// and keeps the previous inventory -- than to spend a scan window retrying one
// call while every other surface waits behind it.
const (
	// retryMaxAttempts includes the first try, so this is four retries.
	retryMaxAttempts = 5
	// retryBaseDelay is the first backoff.
	retryBaseDelay = 1 * time.Second
	// retryMaxDelay caps the curve. Growth is 1.6x, matching the shape already
	// used for WIF verification in services/gcp_oauth_provision_service.go, so
	// the two places in this codebase that wait on GCP wait in the same shape.
	retryMaxDelay = 16 * time.Second
	// retryMaxRetryAfter bounds what a Retry-After header can ask for. GCP is
	// entitled to say "come back in an hour"; a scan is not entitled to sleep
	// for an hour holding a credential and a database connection.
	retryMaxRetryAfter = 30 * time.Second
)

// ErrThrottled means GCP rate-limited a read and it did not recover within the
// retry budget.
//
// Named rather than passed through raw so the scanner can map it to
// CloudCoverageThrottled without parsing provider text, mirroring
// awsdiscovery.ErrThrottled. The provider's own message is wrapped, not
// discarded: coverage records it, and a throttle message names a quota rather
// than anything from the customer's estate.
var ErrThrottled = errors.New("gcp: rate limited")

// retrySleep waits between attempts, or returns early if the context ends.
//
// A seam rather than an inline time.After so tests can exercise the exhaustion
// paths without sleeping through the real curve -- the same reason
// awsdiscovery.ActivityReader has WithSleep. Production never replaces it.
var retrySleep = func(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// Retry runs op until it succeeds, fails permanently, or the budget runs out.
//
// The returned error is op's own last error, except when the failure was a
// throttle that never recovered -- then it wraps ErrThrottled so the caller can
// classify it with IsThrottle. A cancelled context returns ctx.Err()
// immediately; a scan phase that has run out of time must not keep calling GCP.
func Retry(ctx context.Context, op func() error) error {
	var lastErr error

	for attempt := 1; attempt <= retryMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = op()
		if lastErr == nil {
			return nil
		}
		if !isRetryable(lastErr) {
			return lastErr
		}
		if attempt == retryMaxAttempts {
			break
		}

		if err := retrySleep(ctx, retryDelay(lastErr, attempt)); err != nil {
			return err
		}
	}

	// The budget is gone. A throttle that never recovered is reported as a
	// throttle, because the caller's next decision -- whether this surface may
	// be reconciled against -- depends on knowing the read was cut short rather
	// than completed.
	if isRateLimit(lastErr) {
		return errors.Join(ErrThrottled, lastErr)
	}
	return lastErr
}

// IsThrottle reports whether err is a rate-limit that exhausted its retries.
//
// The scanner uses this to choose CloudCoverageThrottled over
// CloudCoverageDenied. The two look identical in row count and mean opposite
// things about whether the customer needs to grant something.
func IsThrottle(err error) bool {
	return errors.Is(err, ErrThrottled) || isRateLimit(err)
}

// isRetryable is an ALLOW-LIST. Anything not named here is permanent.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	// A constrained read -- VPC Service Controls, an org policy -- is a
	// deliberate decision by the customer. It will refuse identically every
	// time, and asking again is pure waste.
	if ClassifyConstraint(err) != nil {
		return false
	}
	if isRateLimit(err) {
		return true
	}

	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case http.StatusInternalServerError, // 500
			http.StatusBadGateway,         // 502
			http.StatusServiceUnavailable, // 503
			http.StatusGatewayTimeout:     // 504
			return true
		default:
			// 400, 401, 403, 404, 409, 412 and everything else: a fact about
			// this reader or this request, not a blip.
			return false
		}
	}

	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Unavailable, codes.Internal, codes.DeadlineExceeded:
			return true
		}
	}
	return false
}

// isRateLimit covers both the REST and gRPC spellings of "too many requests".
func isRateLimit(err error) bool {
	if err == nil {
		return false
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) && gerr.Code == http.StatusTooManyRequests {
		return true
	}
	if s, ok := status.FromError(err); ok && s.Code() == codes.ResourceExhausted {
		return true
	}
	return false
}

// retryDelay is the wait before the next attempt.
//
// A Retry-After from the provider wins over the computed curve, bounded by
// retryMaxRetryAfter: GCP knows when its own quota window refills and a guess
// derived from attempt count does not.
func retryDelay(err error, attempt int) time.Duration {
	if d, ok := retryAfter(err); ok {
		if d > retryMaxRetryAfter {
			d = retryMaxRetryAfter
		}
		if d > 0 {
			return d
		}
	}

	d := float64(retryBaseDelay) * math.Pow(1.6, float64(attempt-1))
	if d > float64(retryMaxDelay) {
		d = float64(retryMaxDelay)
	}
	// Jitter so that a fan-out across many projects, which all started
	// together, does not retry in lockstep and reproduce the burst that caused
	// the throttle. math/rand is deliberate: this is scheduling, not a security
	// decision, and nothing about the delay needs to be unpredictable.
	jitter := 1 + (mrand.Float64()*0.4 - 0.2) // [0.8, 1.2)
	return time.Duration(d * jitter)
}

// retryAfter reads a Retry-After header off a googleapi error, in either of the
// two forms RFC 9110 allows.
func retryAfter(err error) (time.Duration, bool) {
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) || gerr.Header == nil {
		return 0, false
	}
	raw := gerr.Header.Get("Retry-After")
	if raw == "" {
		return 0, false
	}
	if secs, convErr := strconv.Atoi(raw); convErr == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, convErr := http.ParseTime(raw); convErr == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}
