package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The GitHub transport is the part that can be verified without a tenant:
// pagination, throttling on both status codes, conditional requests and the
// distinction between "denied", "absent" and "rate limited". Endpoint SHAPES
// still need the Stage-0 spike; this covers the machinery around them.

func testProvider(base string) *GitHubProvider {
	return &GitHubProvider{
		BaseURL:      base,
		HTTP:         &http.Client{Timeout: 5 * time.Second},
		APIVersion:   "2022-11-28",
		MaxRetries:   3,
		etags:        map[string]string{},
		cachedBodies: map[string][]byte{},
		blobs:        map[string][]byte{},
		TokenFn: func(context.Context, ProviderContext) (string, error) {
			return "test-token", nil
		},
	}
}

func TestGitHubPaginationFollowsLinkHeader(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch page {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(`<%s/installation/repositories?page=2>; rel="next"`, srv.URL))
			fmt.Fprint(w, `{"repositories":[{"id":1,"node_id":"R_1","full_name":"acme/one","default_branch":"main"}]}`)
		case "2":
			// Last page: no Link header, so pagination must stop here.
			fmt.Fprint(w, `{"repositories":[{"id":2,"node_id":"R_2","full_name":"acme/two","default_branch":"dev"}]}`)
		default:
			t.Errorf("unexpected page %q — pagination did not stop", page)
		}
	}))
	defer srv.Close()

	scopes, err := testProvider(srv.URL).ListScopes(context.Background(), ProviderContext{})
	if err != nil {
		t.Fatalf("list scopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 repositories across 2 pages, got %d", len(scopes))
	}
	// The immutable node id must be the identity, not the renameable full name.
	if scopes[0].NativeID != "R_1" || scopes[0].DisplayName != "acme/one" {
		t.Fatalf("recognition key should be the node id: %+v", scopes[0])
	}
	if scopes[1].DefaultBranch != "dev" {
		t.Fatalf("default branch not carried through: %+v", scopes[1])
	}
	t.Log("PASS: Link-header pagination walked both pages and stopped")
}

func TestGitHubRateLimitOn403AndRetryAfter(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			// A 403 WITH remaining=0 is a rate limit, not a permission problem.
			// Treating it as denial would turn a pause into a false "no access".
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"repositories":[]}`)
	}))
	defer srv.Close()

	if _, err := testProvider(srv.URL).ListScopes(context.Background(), ProviderContext{}); err != nil {
		t.Fatalf("a throttled 403 should be retried, not returned: %v", err)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Fatal("expected a retry after the 403 rate limit")
	}
	t.Log("PASS: 403 + remaining=0 treated as throttle and retried")
}

func TestGitHubRateLimitOn429(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"repositories":[]}`)
	}))
	defer srv.Close()

	if _, err := testProvider(srv.URL).ListScopes(context.Background(), ProviderContext{}); err != nil {
		t.Fatalf("429 should be retried: %v", err)
	}
	t.Log("PASS: 429 retried after Retry-After")
}

func TestGitHubPermissionDeniedIsNotAThrottle(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		// 403 with quota REMAINING is a real permission denial. Retrying it
		// would waste the budget and hide the actual cause from coverage.
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"Resource not accessible by integration"}`)
	}))
	defer srv.Close()

	_, err := testProvider(srv.URL).ListScopes(context.Background(), ProviderContext{})
	if err == nil {
		t.Fatal("expected a permission error")
	}
	ge, ok := err.(*ghError)
	if !ok || !ge.IsPermissionDenied() {
		t.Fatalf("expected a permission-denied ghError, got %T %v", err, err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("a permission denial must not be retried, saw %d calls", n)
	}
	t.Log("PASS: 403 with quota left is denial, returned immediately and distinctly")
}

func TestGitHubConditionalRequestSavesQuota(t *testing.T) {
	var full, notModified int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"v1"` {
			atomic.AddInt32(&notModified, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&full, 1)
		w.Header().Set("ETag", `W/"v1"`)
		fmt.Fprint(w, `{"repositories":[{"id":1,"node_id":"R_1","full_name":"acme/one"}]}`)
	}))
	defer srv.Close()

	p := testProvider(srv.URL)
	if _, err := p.ListScopes(context.Background(), ProviderContext{}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Same provider instance: the cached ETag must be replayed.
	if _, err := p.ListScopes(context.Background(), ProviderContext{}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if atomic.LoadInt32(&full) != 1 || atomic.LoadInt32(&notModified) != 1 {
		t.Fatalf("expected 1 full + 1 not-modified, got %d + %d", full, notModified)
	}
	t.Log("PASS: ETag replayed; unchanged page returned 304 and cost no quota")
}

func TestGitHubTreeTruncationIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tree":[{"path":"a.json","type":"blob","sha":"s1","size":3},
		                        {"path":"dir","type":"tree","sha":"s2"}],"truncated":true}`)
	}))
	defer srv.Close()

	entries, truncated, err := testProvider(srv.URL).ListTree(context.Background(),
		ProviderContext{}, ProviderScope{DisplayName: "acme/one", DefaultBranch: "main"})
	if err != nil {
		t.Fatalf("list tree: %v", err)
	}
	if !truncated {
		t.Fatal("truncation must be surfaced; hiding it manufactures a false complete count")
	}
	// Only blobs are fetchable; a tree entry is not a file.
	if len(entries) != 1 || entries[0].SHA != "s1" {
		t.Fatalf("expected only the blob entry, got %+v", entries)
	}
	t.Log("PASS: truncation reported and non-blob entries excluded")
}

func TestGitHubAbsentIsNotDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	defer srv.Close()

	// A 404 on an optional capability means "not available here", which must
	// not be reported as an error that fails the scan.
	objs, err := testProvider(srv.URL).ListNativeAgents(context.Background(),
		ProviderContext{}, ProviderScope{DisplayName: "acme/one"})
	if err != nil {
		t.Fatalf("absent capability should not error: %v", err)
	}
	if len(objs) != 0 {
		t.Fatal("expected no objects")
	}
	t.Log("PASS: 404 on an optional capability yields absence, not failure")
}

func TestGitHubCapabilityProbeClassifiesGrants(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusOK, "complete_for_selected_scope"},
		{http.StatusForbidden, "not_configured"},
		{http.StatusNotFound, "unsupported"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Remaining quota, so a 403 here is denial rather than throttling.
			w.Header().Set("X-RateLimit-Remaining", "100")
			w.WriteHeader(tc.status)
			fmt.Fprint(w, `{}`)
		}))
		caps, err := testProvider(srv.URL).Capabilities(context.Background(), ProviderContext{})
		srv.Close()
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if got := caps["repository"]; got != tc.want {
			t.Fatalf("status %d: expected %q, got %q", tc.status, tc.want, got)
		}
	}
	t.Log("PASS: capability probe maps 200/403/404 to complete/not_configured/unsupported")
}

func TestParseCodeownersPreservesOrder(t *testing.T) {
	rules := ParseCodeowners(`
# comment
*           @acme/platform
/docs/      @acme/docs
agent.json  @alice @acme/agents
`)
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d: %+v", len(rules), rules)
	}
	// Last match wins, so agent.json must beat the catch-all.
	owners := MatchCodeowners(rules, "agent.json")
	if len(owners) != 2 || owners[0] != "@alice" {
		t.Fatalf("last-match-wins failed: %v", owners)
	}
	if got := MatchCodeowners(rules, "src/main.go"); len(got) != 1 || got[0] != "@acme/platform" {
		t.Fatalf("catch-all should own unmatched paths: %v", got)
	}
	if got := MatchCodeowners(rules, "docs/readme.md"); len(got) != 1 || got[0] != "@acme/docs" {
		t.Fatalf("directory pattern should cover contents: %v", got)
	}
	t.Log("PASS: CODEOWNERS order preserved, last match wins, directory patterns cover contents")
}

func TestRateLimitPausePrefersRetryAfter(t *testing.T) {
	reset := strconv.FormatInt(time.Now().Add(2*time.Hour).Unix(), 10)
	resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
	resp.Header.Set("Retry-After", "7")
	resp.Header.Set("X-RateLimit-Remaining", "0")
	resp.Header.Set("X-RateLimit-Reset", reset)

	// Retry-After must win: honouring the two-hour reset instead would stall a
	// scan for hours when the server asked for seconds.
	d, throttled := rateLimitPause(resp, 0)
	if !throttled || d != 7*time.Second {
		t.Fatalf("expected a 7s pause from Retry-After, got %v (throttled=%v)", d, throttled)
	}
	t.Log("PASS: Retry-After takes precedence over x-ratelimit-reset")
}

// A blob read must never be answered with "unexpected end of JSON input".
//
// This is a regression test for a real organisation-wide scan that produced
// ~130 warnings of exactly that shape against files that were perfectly
// readable. The cause: the ETag cache stored a validator but not the body, so
// the SECOND request for a blob URL got a 304 with an empty body, and FetchBlob
// discarded the not-modified flag and JSON-parsed the empty buffer. Every
// affected file was reported as unreadable and its agents were never seen.
//
// The second request is not exotic. All-branch scanning asks for the same
// unchanged file once per branch that contains it.
func TestBlobRefetchDoesNotBecomeAParseError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		// Behave like GitHub: offer a validator, and honour it.
		if r.Header.Get("If-None-Match") == `"blob-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"blob-etag"`)
		fmt.Fprint(w, `{"content":"aGVsbG8gd29ybGQ=","encoding":"base64"}`)
	}))
	defer srv.Close()

	p := testProvider(srv.URL)
	scope := ProviderScope{DisplayName: "acme/one", DefaultBranch: "main"}
	entry := TreeEntry{Path: "agent.json", SHA: "sha-1"}

	first, err := p.FetchBlob(context.Background(), ProviderContext{}, scope, entry)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if string(first) != "hello world" {
		t.Fatalf("first fetch decoded wrong: %q", first)
	}

	// The same blob on another branch. Before the fix this returned
	// "unexpected end of JSON input".
	onBranch := scope
	onBranch.Ref = "feature/x"
	second, err := p.FetchBlob(context.Background(), ProviderContext{}, onBranch, entry)
	if err != nil {
		t.Fatalf("re-reading the same blob must succeed, got: %v", err)
	}
	if string(second) != "hello world" {
		t.Fatalf("re-read returned different bytes: %q", second)
	}

	// And it should not have cost a second call at all: a blob SHA IS its
	// content hash, so the bytes were already held.
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected the repeat to be served from cache (1 call), got %d", n)
	}
	t.Log("PASS: repeated blob read served from cache, no parse error, no extra API call")
}

// A 304 on a LISTING must return the body the validator was issued for, not
// nothing. ListTree previously turned that case into an empty tree — a silent
// "this branch has no files", which is a false all-clear rather than an error.
func TestNotModifiedListingReturnsTheCachedBody(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("If-None-Match") == `"tree-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"tree-etag"`)
		fmt.Fprint(w, `{"truncated":false,"tree":[{"path":"agent.json","type":"blob","sha":"s1","size":10}]}`)
	}))
	defer srv.Close()

	p := testProvider(srv.URL)
	scope := ProviderScope{DisplayName: "acme/one", DefaultBranch: "main"}

	if entries, _, err := p.ListTree(context.Background(), ProviderContext{}, scope); err != nil || len(entries) != 1 {
		t.Fatalf("first listing: %d entries, err=%v", len(entries), err)
	}

	entries, truncated, err := p.ListTree(context.Background(), ProviderContext{}, scope)
	if err != nil {
		t.Fatalf("revalidated listing: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("a 304 must reuse the cached tree, got %d entries — an empty tree here "+
			"would read as 'this repository has no files'", len(entries))
	}
	if truncated {
		t.Fatal("truncation flag must survive the cache")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected 2 requests (the second revalidating), got %d", n)
	}
	t.Log("PASS: 304 on a listing serves the cached body instead of an empty result")
}
