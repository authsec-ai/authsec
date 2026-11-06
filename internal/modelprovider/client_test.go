package modelprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAdminKey = "sk-admin-TESTKEY-0123456789abcdefghijklmnop"

// fake is a provider server that only knows the documented read endpoints
// and fails the test on any other method or path.
type fake struct {
	t       *testing.T
	mu      sync.Mutex
	allowed map[string]bool
	routes  map[string]func(w http.ResponseWriter, r *http.Request)
	seen    []string
}

func newFake(t *testing.T, allowed ...string) *fake {
	f := &fake{t: t, allowed: map[string]bool{}, routes: map[string]func(http.ResponseWriter, *http.Request){}}
	for _, a := range allowed {
		f.allowed[a] = true
	}
	return f
}

func (f *fake) handle(path string, h func(w http.ResponseWriter, r *http.Request)) {
	f.routes[path] = h
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if r.Method != http.MethodGet {
		f.t.Errorf("non-GET request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !f.allowed[r.URL.Path] {
		f.t.Errorf("request to an endpoint outside the read list: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if strings.Contains(r.URL.RawQuery, testAdminKey) {
		f.t.Errorf("admin key in a URL")
	}
	h := f.routes[r.URL.Path]
	if h == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h(w, r)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func noSleep(c Client) {
	switch x := c.(type) {
	case *openAIClient:
		x.h.sleep = func(context.Context, time.Duration) error { return nil }
	case *anthropicClient:
		x.h.sleep = func(context.Context, time.Duration) error { return nil }
	}
}

func openAIOK(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+testAdminKey {
		t.Errorf("Authorization header: %q", got)
	}
}

func TestOpenAIClientReadsPagesAggregatesAndStaysReadOnly(t *testing.T) {
	f := newFake(t, "/v1/organization/projects", "/v1/organization/projects/proj_a/api_keys",
		"/v1/organization/projects/proj_b/api_keys", "/v1/organization/usage/completions",
		"/v1/organization/usage/embeddings", "/v1/organization/audit_logs")
	var hits429 int32
	f.handle("/v1/organization/projects", func(w http.ResponseWriter, r *http.Request) {
		openAIOK(t, r)
		w.Header().Set("openai-organization", "org-acme")
		if r.URL.Query().Get("limit") == "1" {
			writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "proj_a", "name": "Support"}}, "has_more": true, "last_id": "proj_a"})
			return
		}
		if r.URL.Query().Get("after") == "" {
			writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "proj_a", "name": "Support"}}, "has_more": true, "last_id": "proj_a"})
			return
		}
		writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "proj_b", "name": "Billing"}}, "has_more": false, "last_id": "proj_b"})
	})
	f.handle("/v1/organization/projects/proj_a/api_keys", func(w http.ResponseWriter, r *http.Request) {
		// First call is rate limited once: retried.
		if atomic.AddInt32(&hits429, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
			return
		}
		if r.URL.Query().Get("after") == "" {
			writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "key_1", "name": "support-bot", "redacted_value": "sk-...abcd",
				"created_at": 1700000000, "last_used_at": 1730000000,
				"owner": map[string]any{"type": "service_account", "service_account": map[string]any{"id": "svc_1", "name": "support-bot-sa"}}}},
				"has_more": true, "last_id": "key_1"})
			return
		}
		writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "key_2", "name": "laptop", "created_at": 1700000001,
			"owner": map[string]any{"type": "user", "user": map[string]any{"id": "user_1", "name": "Dev One", "email": "dev@example.com"}}}},
			"has_more": false, "last_id": "key_2"})
	})
	f.handle("/v1/organization/projects/proj_b/api_keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "key_3", "name": "billing", "expires_at": 1000}}, "has_more": false, "last_id": "key_3"})
	})
	bucket := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	usage := func(model string, in, out, reqs int64, page2 bool) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("bucket_width") != "1h" || strings.Join(q["group_by"], ",") != "api_key_id,project_id,model" {
				t.Errorf("usage query: %s", r.URL.RawQuery)
			}
			res := func(key string) map[string]any {
				return map[string]any{"api_key_id": key, "project_id": "proj_a", "model": model,
					"input_tokens": in, "output_tokens": out, "input_cached_tokens": 1, "num_model_requests": reqs}
			}
			if page2 && q.Get("page") == "" {
				writeJSON(w, map[string]any{"data": []any{map[string]any{"start_time": bucket.Unix(), "results": []any{res("key_1")}}},
					"has_more": true, "next_page": "p2"})
				return
			}
			writeJSON(w, map[string]any{"data": []any{map[string]any{"start_time": bucket.Add(time.Hour).Unix(),
				"results": []any{res("key_1"), map[string]any{"api_key_id": nil, "project_id": nil, "model": model, "input_tokens": 0, "output_tokens": 0, "num_model_requests": 0}}}},
				"has_more": false, "next_page": nil})
		}
	}
	f.handle("/v1/organization/usage/completions", usage("gpt-5", 100, 50, 2, true))
	// Embeddings on the same model and hour add into the same row.
	f.handle("/v1/organization/usage/embeddings", usage("gpt-5", 10, 0, 1, false))
	f.handle("/v1/organization/audit_logs", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query()["event_types[]"]; strings.Join(got, ",") != "api_key.created,api_key.deleted" {
			t.Errorf("audit event types: %v", got)
		}
		writeJSON(w, map[string]any{"data": []any{
			map[string]any{"id": "audit_1", "type": "api_key.deleted", "effective_at": 1730000500, "project": map[string]any{"id": "proj_a"},
				"api_key.deleted": map[string]any{"id": "key_9"}},
		}, "has_more": false, "last_id": "audit_1"})
	})
	srv := httptest.NewServer(f)
	defer srv.Close()
	defer OverrideBaseURLsForTest(srv.URL+"/v1", srv.URL+"/v1")()

	c, err := New(OpenAI, testAdminKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	noSleep(c)
	ctx := context.Background()
	org, err := c.Validate(ctx)
	if err != nil || org.ID != "org-acme" {
		t.Fatalf("validate: %+v %v", org, err)
	}
	keys, truncated, err := c.ListKeys(ctx, 100)
	if err != nil || truncated {
		t.Fatalf("keys: %v %v", err, truncated)
	}
	if len(keys) != 3 || keys[0].ID != "key_1" || keys[0].OwnerType != "service_account" || keys[0].OwnerName != "support-bot-sa" ||
		keys[0].ProjectName != "Support" || keys[0].LastUsedAt == nil || keys[1].OwnerType != "user" || keys[2].ProjectID != "proj_b" ||
		keys[2].Status != "expired" {
		t.Fatalf("keys: %+v", keys)
	}
	if hits429 < 2 {
		t.Errorf("429 not retried: %d", hits429)
	}
	if _, truncated, err := c.ListKeys(ctx, 2); err != nil || !truncated {
		t.Errorf("max 2 keys: truncated=%v err=%v", truncated, err)
	}
	rows, err := c.Usage(ctx, bucket, bucket.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// key_1 at 10:00 (completions page 1 only), key_1 at 11:00 (completions
	// + embeddings); the all-zero key-less row is dropped.
	if len(rows) != 2 {
		t.Fatalf("usage rows: %+v", rows)
	}
	var h11 *UsageRow
	for i := range rows {
		if rows[i].BucketStart.Equal(bucket.Add(time.Hour)) {
			h11 = &rows[i]
		}
	}
	if h11 == nil || h11.KeyID != "key_1" || *h11.Requests != 3 || h11.InputTokens != 110 || h11.OutputTokens != 50 || h11.CachedInputTokens != 2 {
		t.Fatalf("aggregated 11:00 row: %+v", h11)
	}
	evs, err := c.KeyEvents(ctx, bucket)
	if err != nil || len(evs) != 1 || evs[0].KeyID != "key_9" || evs[0].Type != "api_key.deleted" {
		t.Fatalf("events: %+v %v", evs, err)
	}
}

func TestAnthropicClientReadsKeysAndUsage(t *testing.T) {
	f := newFake(t, "/v1/organizations/me", "/v1/organizations/workspaces", "/v1/organizations/api_keys",
		"/v1/organizations/usage_report/messages")
	check := func(r *http.Request) {
		if r.Header.Get("x-api-key") != testAdminKey || r.Header.Get("anthropic-version") != AnthropicVersion {
			t.Errorf("headers: x-api-key set=%v version=%q", r.Header.Get("x-api-key") != "", r.Header.Get("anthropic-version"))
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header sent to Anthropic")
		}
	}
	f.handle("/v1/organizations/me", func(w http.ResponseWriter, r *http.Request) {
		check(r)
		writeJSON(w, map[string]any{"id": "org-uuid-1", "name": "Acme", "type": "organization"})
	})
	f.handle("/v1/organizations/workspaces", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "wrkspc_1", "name": "Agents"}}, "has_more": false, "last_id": "wrkspc_1"})
	})
	f.handle("/v1/organizations/api_keys", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after_id") == "" {
			writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "apikey_1", "name": "triage-agent", "status": "active",
				"created_at": "2026-01-02T03:04:05.123Z", "partial_key_hint": "sk-ant-api03-R2D...igAA",
				"scope":     map[string]any{"type": "workspace", "workspace_id": "wrkspc_1"},
				"principal": map[string]any{"type": "service_account_actor", "service_account_id": "svac_1"}}},
				"has_more": true, "last_id": "apikey_1"})
			return
		}
		writeJSON(w, map[string]any{"data": []any{map[string]any{"id": "apikey_2", "name": "old", "status": "archived",
			"created_by": map[string]any{"type": "user", "id": "user_1"}}}, "has_more": false, "last_id": "apikey_2"})
	})
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	f.handle("/v1/organizations/usage_report/messages", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("bucket_width") != "1h" || strings.Join(q["group_by[]"], ",") != "api_key_id,workspace_id,model" ||
			q.Get("starting_at") != start.Format(time.RFC3339) {
			t.Errorf("usage query: %s", r.URL.RawQuery)
		}
		b := func(at time.Time, results ...any) map[string]any {
			return map[string]any{"starting_at": at.Format(time.RFC3339), "ending_at": at.Add(time.Hour).Format(time.RFC3339), "results": results}
		}
		res := map[string]any{"api_key_id": "apikey_1", "workspace_id": "wrkspc_1", "model": "claude-opus-5-5",
			"uncached_input_tokens": 100, "cache_read_input_tokens": 20, "output_tokens": 7,
			"cache_creation": map[string]any{"ephemeral_1h_input_tokens": 3, "ephemeral_5m_input_tokens": 4}}
		if q.Get("page") == "" {
			writeJSON(w, map[string]any{"data": []any{b(start, res)}, "has_more": true, "next_page": "page_2"})
			return
		}
		console := map[string]any{"api_key_id": nil, "workspace_id": nil, "model": "claude-opus-5-5", "uncached_input_tokens": 5, "output_tokens": 1}
		writeJSON(w, map[string]any{"data": []any{b(start.Add(time.Hour), res, console), b(start.Add(2 * time.Hour))}, "has_more": false, "next_page": nil})
	})
	srv := httptest.NewServer(f)
	defer srv.Close()
	defer OverrideBaseURLsForTest(srv.URL+"/v1", srv.URL+"/v1")()
	c, err := New(Anthropic, testAdminKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	org, err := c.Validate(ctx)
	if err != nil || org.ID != "org-uuid-1" || org.Name != "Acme" {
		t.Fatalf("validate: %+v %v", org, err)
	}
	keys, _, err := c.ListKeys(ctx, 100)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys: %+v %v", keys, err)
	}
	if k := keys[0]; k.ProjectID != "wrkspc_1" || k.ProjectName != "Agents" || k.OwnerType != "service_account" || k.OwnerID != "svac_1" || k.CreatedAt == nil {
		t.Fatalf("key 1: %+v", k)
	}
	if k := keys[1]; k.Status != "archived" || k.OwnerType != "user" {
		t.Fatalf("key 2: %+v", k)
	}
	rows, err := c.Usage(ctx, start, start.Add(3*time.Hour))
	if err != nil || len(rows) != 3 {
		t.Fatalf("usage: %+v %v", rows, err)
	}
	if r := rows[0]; r.Requests != nil || r.InputTokens != 127 || r.CachedInputTokens != 20 || r.OutputTokens != 7 || r.KeyID != "apikey_1" {
		t.Fatalf("usage row: %+v", r)
	}
	if r := rows[2]; r.KeyID != "" || r.InputTokens != 5 {
		t.Fatalf("console row: %+v", r)
	}
	if evs, err := c.KeyEvents(ctx, start); evs != nil || err != nil {
		t.Fatalf("anthropic events: %v %v", evs, err)
	}
}

func TestProviderRefusesKeyIs401AuthErrorWithoutTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// A provider echoing part of the key must not reach the message.
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided: ` + testAdminKey + `"}}`))
	}))
	defer srv.Close()
	defer OverrideBaseURLsForTest(srv.URL, srv.URL)()
	for _, p := range []string{OpenAI, Anthropic} {
		c, _ := New(p, testAdminKey, srv.Client())
		_, err := c.Validate(context.Background())
		if !IsAuth(err) {
			t.Fatalf("%s: want auth error, got %v", p, err)
		}
		if strings.Contains(err.Error(), "TESTKEY") || strings.Contains(err.Error(), testAdminKey) {
			t.Fatalf("%s: error carries the key: %v", p, err)
		}
	}
}

func TestRateLimitGivesUpAfterRetries(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	defer OverrideBaseURLsForTest(srv.URL, srv.URL)()
	c, _ := New(OpenAI, testAdminKey, srv.Client())
	var waits []time.Duration
	c.(*openAIClient).h.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	_, err := c.Validate(context.Background())
	var pe *Error
	if err == nil || IsAuth(err) || !asErr(err, &pe) || pe.Status != http.StatusTooManyRequests {
		t.Fatalf("want 429 error, got %v", err)
	}
	if n != maxRetries+1 || len(waits) != maxRetries || waits[0] != 2*time.Second || waits[3] != 16*time.Second {
		t.Fatalf("attempts %d, waits %v", n, waits)
	}
	if backoff(0, "120") != maxRetryWait || backoff(1, "3") != 3*time.Second {
		t.Fatal("Retry-After not honoured / capped")
	}
}

func asErr(err error, pe **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*pe = e
	}
	return ok
}

// A redirect is never followed: the key header would go to another host.
func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&leaked, 1)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer srv.Close()
	defer OverrideBaseURLsForTest(srv.URL, srv.URL)()
	c, _ := New(Anthropic, testAdminKey, nil)
	if _, err := c.Validate(context.Background()); err == nil {
		t.Fatal("a redirect was accepted")
	}
	if leaked != 0 {
		t.Fatal("the redirect target was called")
	}
}

func TestScrub(t *testing.T) {
	if s := Scrub("bad key sk-ant-admin01-abcdef123 here"); strings.Contains(s, "abcdef123") {
		t.Fatal(s)
	}
}
