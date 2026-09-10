package azureonboard

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Retrying the refusals Microsoft expects a client to retry.
//
// Both planes throttle, and neither is optional to handle. ARM applies a
// per-subscription read budget and answers 429 with a Retry-After the moment it
// is exceeded; Graph does the same per-tenant. Discovery is exactly the shape of
// traffic that hits those limits -- every subscription in every tenant, every
// user in every directory, in a burst -- so a 429 is a normal event on a healthy
// system, not an error worth surfacing to an operator.
//
// This lives in the transport rather than at the call sites because there are
// nine of them across three files, and a tenth added later would silently miss
// out. A RoundTripper cannot be forgotten.
//
// What it deliberately does NOT do: retry a 403, a 401 or a 400. Those are
// answers, not congestion. Retrying them turns one clear refusal into four
// identical ones and delays the error the operator needs to read.
const (
	// Four attempts total: the original plus three retries. Past that, a
	// service that is still throttling is not going to stop inside one request.
	retryMaxAttempts = 4

	// Never honour a Retry-After longer than this in one wait. ARM has been
	// observed asking for minutes; an HTTP handler cannot sit there. Waiting the
	// cap and retrying is strictly better than sleeping past the deadline, and
	// if the service is still throttling the attempt costs one round trip.
	retryMaxWait = 20 * time.Second

	// Backoff when the response carries no Retry-After: 0.5s, 1s, 2s.
	retryBaseWait = 500 * time.Millisecond

	// A caller with no deadline still gets one. This transport sleeps between
	// attempts, and an unbounded sleep inside a handler is a hang.
	retryNoDeadlineBudget = 2 * time.Minute
)

// retryTransport retries throttling and transient gateway failures.
type retryTransport struct {
	base http.RoundTripper

	// sleep is injectable so tests do not actually wait. Returns the context's
	// error if the wait is cut short.
	sleep func(ctx context.Context, d time.Duration) error
}

// newRetryClient builds the HTTP client every call in this package goes through.
//
// Client.Timeout is deliberately NOT set: it bounds the whole exchange including
// this transport's waits, which would make a Retry-After of 20s consume the
// entire budget and leave nothing for the retry it was asking for. The bound
// comes from the caller's context instead -- which is where it belongs, since
// only the caller knows whether it is serving a browser or a background sweep --
// with ResponseHeaderTimeout catching a server that accepts a connection and
// then says nothing.
func newRetryClient() *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = requestTimeout

	return &http.Client{Transport: &retryTransport{base: base}}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, retryNoDeadlineBudget)
		defer cancel()
		req = req.Clone(ctx)
	}

	// A body that cannot be rewound cannot be replayed, and sending a
	// half-consumed one is worse than not retrying. Go populates GetBody for
	// every body this package creates (bytes.Reader, strings.Reader,
	// url.Values.Encode), so this is a guard, not a common path.
	replayable := req.Body == nil || req.GetBody != nil

	for attempt := 0; ; attempt++ {
		// A RoundTripper must not modify the request it was handed, so a retry
		// sends a clone carrying a fresh body. GetBody is nil for a request with
		// no body at all -- every GET in this package -- which is replayable
		// precisely because there is nothing to rewind.
		attemptReq := req
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			attemptReq = req.Clone(req.Context())
			attemptReq.Body = body
		}

		resp, err := t.base.RoundTrip(attemptReq)

		// A transport error is not retried. It has already consumed
		// ResponseHeaderTimeout, the cause is usually DNS or TLS rather than
		// congestion, and the caller's message for it is clearer than a retry
		// loop's.
		if err != nil {
			return nil, err
		}

		last := attempt >= retryMaxAttempts-1
		if last || !replayable || !retryableStatus(resp.StatusCode) {
			return resp, nil
		}

		wait := retryWait(resp.Header, attempt)

		// Sleeping past the deadline accomplishes nothing except turning a
		// usable 429 -- which names its own cause -- into a context error that
		// does not. Hand back the response instead.
		if deadline, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(deadline) {
			return resp, nil
		}

		drain(resp)
		if err := t.wait(ctx, wait); err != nil {
			return nil, err
		}
	}
}

func (t *retryTransport) wait(ctx context.Context, d time.Duration) error {
	if t.sleep != nil {
		return t.sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryableStatus is the set worth sending again.
//
// 429 is the throttle. 502/503/504 are an ARM or Graph front end that never
// reached the service, so the request had no effect and replaying it is safe --
// which is the only reason a non-idempotent POST may be retried here at all.
// 500 is excluded on purpose: it can mean the request WAS applied and the reply
// was lost, and replaying it would be a second write.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryWait prefers what the service asked for over what we would guess.
func retryWait(h http.Header, attempt int) time.Duration {
	if d, ok := retryAfter(h); ok {
		if d > retryMaxWait {
			return retryMaxWait
		}
		if d > 0 {
			return d
		}
	}
	backoff := retryBaseWait << attempt
	if backoff > retryMaxWait {
		return retryMaxWait
	}
	return backoff
}

// retryAfter reads Retry-After in both forms RFC 9110 allows: delay-seconds, and
// an HTTP-date. ARM sends the former; some Graph front ends send the latter.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// drain returns the connection to the pool. Closing without reading leaves it
// unusable, so a retry would open a new one every time.
func drain(resp *http.Response) {
	if resp.Body == nil {
		return
	}
	_, _ = copyDiscard(resp.Body, 64<<10)
	_ = resp.Body.Close()
}

// errBodyTooLarge is never returned to a caller; it only stops copyDiscard.
var errBodyTooLarge = errors.New("response body exceeded drain limit")

func copyDiscard(r interface{ Read([]byte) (int, error) }, limit int64) (int64, error) {
	buf := make([]byte, 4096)
	var n int64
	for n < limit {
		read, err := r.Read(buf)
		n += int64(read)
		if err != nil {
			return n, err
		}
	}
	return n, errBodyTooLarge
}
