package azureonboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A recording client: the transport under test, with the wait replaced so the
// tests assert what it WOULD have slept rather than sleeping it.
type recordedWaits struct {
	mu   sync.Mutex
	list []time.Duration
}

func (r *recordedWaits) add(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, d)
}

func (r *recordedWaits) all() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.list...)
}

func testClient() (*http.Client, *recordedWaits) {
	waits := &recordedWaits{}
	tr := &retryTransport{
		base: http.DefaultTransport,
		sleep: func(ctx context.Context, d time.Duration) error {
			waits.add(d)
			return ctx.Err()
		},
	}
	return &http.Client{Transport: tr}, waits
}

// statusSequence answers with each status in turn, repeating the last forever.
func statusSequence(t *testing.T, header string, codes ...int) (*httptest.Server, *int32Counter) {
	t.Helper()
	calls := &int32Counter{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.next()
		code := codes[len(codes)-1]
		if n < len(codes) {
			code = codes[n]
		}
		if header != "" && code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", header)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":{"code":"Throttled"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

type int32Counter struct {
	mu sync.Mutex
	n  int
}

func (c *int32Counter) next() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.n
	c.n++
	return v
}

func (c *int32Counter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestRetry_HonoursRetryAfterThenSucceeds(t *testing.T) {
	srv, calls := statusSequence(t, "2", http.StatusTooManyRequests, http.StatusOK)
	client, waits := testClient()

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := calls.total(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if got := waits.all(); len(got) != 1 || got[0] != 2*time.Second {
		t.Fatalf("waits = %v, want [2s] -- Retry-After must be preferred over backoff", got)
	}
}

func TestRetry_BacksOffWhenNoRetryAfter(t *testing.T) {
	srv, calls := statusSequence(t, "", http.StatusTooManyRequests)
	client, waits := testClient()

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.total(); got != retryMaxAttempts {
		t.Fatalf("attempts = %d, want %d", got, retryMaxAttempts)
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}
	got := waits.all()
	if len(got) != len(want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("waits = %v, want %v (exponential)", got, want)
		}
	}
}

func TestRetry_GivesUpAndReturnsTheThrottle(t *testing.T) {
	srv, calls := statusSequence(t, "1", http.StatusTooManyRequests)
	client, _ := testClient()

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// The 429 itself must come back. A context error or a synthetic failure
	// would hide the one thing that names the cause.
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 handed back after exhausting retries", resp.StatusCode)
	}
	if got := calls.total(); got != retryMaxAttempts {
		t.Fatalf("attempts = %d, want %d", got, retryMaxAttempts)
	}
}

func TestRetry_LeavesRefusalsAlone(t *testing.T) {
	// 403 and 400 are answers, not congestion. Retrying them delays the error
	// the operator needs to read and multiplies the audit log entry.
	for _, code := range []int{
		http.StatusForbidden,
		http.StatusUnauthorized,
		http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusInternalServerError, // may mean the write WAS applied
	} {
		srv, calls := statusSequence(t, "", code)
		client, waits := testClient()

		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("%d: get: %v", code, err)
		}
		resp.Body.Close()

		if got := calls.total(); got != 1 {
			t.Errorf("status %d: attempts = %d, want 1", code, got)
		}
		if got := waits.all(); len(got) != 0 {
			t.Errorf("status %d: slept %v, want none", code, got)
		}
	}
}

func TestRetry_RetriesGatewayFailures(t *testing.T) {
	// 502/503/504 mean the request never reached the service, so it had no
	// effect and replaying it is safe.
	for _, code := range []int{
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		srv, calls := statusSequence(t, "", code, http.StatusOK)
		client, _ := testClient()

		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("%d: get: %v", code, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d: final = %d, want 200", code, resp.StatusCode)
		}
		if got := calls.total(); got != 2 {
			t.Errorf("status %d: attempts = %d, want 2", code, got)
		}
	}
}

func TestRetry_CapsAnAbsurdRetryAfter(t *testing.T) {
	// ARM has been observed asking for minutes. An HTTP handler cannot wait
	// that long, and waiting the cap then retrying costs one round trip.
	srv, _ := statusSequence(t, "600", http.StatusTooManyRequests, http.StatusOK)
	client, waits := testClient()

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	got := waits.all()
	if len(got) != 1 || got[0] != retryMaxWait {
		t.Fatalf("waits = %v, want [%v]", got, retryMaxWait)
	}
}

func TestRetry_StopsRatherThanSleepingPastTheDeadline(t *testing.T) {
	srv, calls := statusSequence(t, "30", http.StatusTooManyRequests)
	client, waits := testClient()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	// Sleeping past the deadline turns a 429 that names its own cause into a
	// context error that does not.
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want the 429 handed back", resp.StatusCode)
	}
	if got := waits.all(); len(got) != 0 {
		t.Fatalf("slept %v, want none -- the wait exceeded the remaining budget", got)
	}
	if got := calls.total(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestRetry_ReplaysTheRequestBody(t *testing.T) {
	// A form POST is how every token call is made. A retry that sent an empty
	// or half-consumed body would fail with an opaque invalid_request.
	var seen []string
	var mu sync.Mutex
	calls := &int32Counter{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, string(body))
		mu.Unlock()

		if calls.next() == 0 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, _ := testClient()
	const form = "grant_type=refresh_token&refresh_token=abc"

	resp, err := client.Post(srv.URL, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(seen))
	}
	for i, body := range seen {
		if body != form {
			t.Fatalf("attempt %d body = %q, want %q", i+1, body, form)
		}
	}
}

func TestRetry_DoesNotReplayAnUnrewindableBody(t *testing.T) {
	// io.Reader with no known length gets no GetBody, so it cannot be replayed.
	// Sending a half-consumed body is worse than not retrying.
	srv, calls := statusSequence(t, "1", http.StatusTooManyRequests)
	client, _ := testClient()

	req, err := http.NewRequest(http.MethodPost, srv.URL, unrewindable{strings.NewReader("x=1")})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.total(); got != 1 {
		t.Fatalf("attempts = %d, want 1 -- an unrewindable body must not be replayed", got)
	}
}

// unrewindable hides the concrete reader type so net/http cannot derive GetBody.
type unrewindable struct{ r io.Reader }

func (u unrewindable) Read(p []byte) (int, error) { return u.r.Read(p) }

func TestRetryAfter_ParsesBothForms(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   time.Duration
		ok     bool
	}{
		{"absent", "", 0, false},
		{"seconds", "5", 5 * time.Second, true},
		{"zero", "0", 0, true},
		{"negative is not a wait", "-1", 0, false},
		{"garbage", "soon", 0, false},
		{"http date in the past", "Mon, 02 Jan 2006 15:04:05 GMT", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.header != "" {
				h.Set("Retry-After", tc.header)
			}
			got, ok := retryAfter(h)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("wait = %v, want %v", got, tc.want)
			}
		})
	}

	// A future HTTP-date resolves to a positive wait. Compared loosely because
	// the clock moves between formatting and parsing.
	h := http.Header{}
	h.Set("Retry-After", time.Now().Add(30*time.Second).UTC().Format(http.TimeFormat))
	got, ok := retryAfter(h)
	if !ok || got <= 25*time.Second || got > 31*time.Second {
		t.Fatalf("future date wait = %v (ok=%v), want ~30s", got, ok)
	}
}

func TestRetry_TransportErrorIsNotRetried(t *testing.T) {
	// Nothing was refused -- the request never completed. Retrying it burns the
	// caller's budget on a cause that is usually DNS or TLS.
	attempts := &int32Counter{}
	tr := &retryTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts.next()
			return nil, errors.New("dial tcp: no such host")
		}),
		sleep: func(context.Context, time.Duration) error { return nil },
	}
	client := &http.Client{Transport: tr}

	if _, err := client.Get("http://example.invalid"); err == nil {
		t.Fatal("want an error")
	}
	if got := attempts.total(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
