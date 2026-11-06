// Package modelprovider reads a model provider organisation (OpenAI,
// Anthropic) with its admin key: its API keys, their projects and owners,
// and hourly model usage per key, project and model
// (SPEC-agent-runtime-provider-usage.md §6).
//
// Read only, by construction: the clients issue GET requests to a fixed list
// of provider endpoints and nothing else. The admin key goes into one request
// header and nowhere else: never into a URL, an error or a log line. Redirects
// are refused, because Go forwards custom headers (x-api-key) across hosts on
// a redirect.
package modelprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Providers.
const (
	OpenAI    = "openai"
	Anthropic = "anthropic"
)

// Valid reports whether p is a supported provider.
func Valid(p string) bool { return p == OpenAI || p == Anthropic }

// Provider hosts: fixed, never configured by a workspace.
const (
	openAIBaseURL    = "https://api.openai.com/v1"
	anthropicBaseURL = "https://api.anthropic.com/v1"

	// AnthropicVersion is the anthropic-version header sent.
	AnthropicVersion = "2026-10-21"

	requestTimeout = 30 * time.Second
	maxBody        = 16 << 20
	maxRetries     = 4
	maxRetryWait   = 60 * time.Second
	maxPages       = 2000
	userAgent      = "AuthSec-ModelProviderUsage/1 (+https://authsec.ai)"
)

var baseURLs = struct {
	sync.RWMutex
	openai, anthropic string
}{openai: openAIBaseURL, anthropic: anthropicBaseURL}

// OverrideBaseURLsForTest points the clients at fake provider servers. Tests
// only: production never calls it, and no workspace input reaches it. It
// returns the undo.
func OverrideBaseURLsForTest(openai, anthropic string) (restore func()) {
	baseURLs.Lock()
	po, pa := baseURLs.openai, baseURLs.anthropic
	baseURLs.openai, baseURLs.anthropic = openai, anthropic
	baseURLs.Unlock()
	return func() {
		baseURLs.Lock()
		baseURLs.openai, baseURLs.anthropic = po, pa
		baseURLs.Unlock()
	}
}

// Org is the organisation an admin key belongs to, as the provider names it.
type Org struct {
	ID   string
	Name string
}

// Key is one provider API key. Never a key value: Hint is the provider's own
// redacted hint.
type Key struct {
	ID          string
	Name        string
	Hint        string
	ProjectID   string
	ProjectName string
	OwnerType   string // user | service_account | ""
	OwnerID     string
	OwnerName   string
	CreatedAt   *time.Time
	LastUsedAt  *time.Time
	Status      string // active | inactive | archived | expired
}

// UsageRow is one hour of one key on one model in one project.
type UsageRow struct {
	KeyID             string
	ProjectID         string
	Model             string
	BucketStart       time.Time
	Requests          *int64 // nil: the provider reports no request count
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
}

// KeyEvent is a key created / deleted event from the organisation's audit
// log (OpenAI only).
type KeyEvent struct {
	ID        string
	Type      string // api_key.created | api_key.deleted
	KeyID     string
	ProjectID string
	At        time.Time
}

// Client reads one organisation.
type Client interface {
	Provider() string
	// Validate makes one read call and returns the organisation.
	Validate(ctx context.Context) (Org, error)
	// ListKeys lists up to max keys; truncated when there were more.
	ListKeys(ctx context.Context, max int) (keys []Key, truncated bool, err error)
	// Usage is hourly usage in [from, to), aggregated per (key, project,
	// model, hour) across the provider's usage endpoints.
	Usage(ctx context.Context, from, to time.Time) ([]UsageRow, error)
	// KeyEvents is key created / deleted events since since; nil without an
	// audit log (Anthropic) or when the organisation has not enabled it.
	KeyEvents(ctx context.Context, since time.Time) ([]KeyEvent, error)
}

// Error is a provider call that failed. Message never contains the admin key.
type Error struct {
	Status  int
	Auth    bool // 401 / 403: the provider refused the admin key
	Message string
}

func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("provider returned HTTP %d: %s", e.Status, e.Message)
	}
	return e.Message
}

// IsAuth reports whether err is the provider refusing the admin key.
func IsAuth(err error) bool {
	var pe *Error
	return errors.As(err, &pe) && pe.Auth
}

// New builds the client of provider with adminKey. hc may be nil.
func New(provider, adminKey string, hc *http.Client) (Client, error) {
	if hc == nil {
		hc = &http.Client{Timeout: requestTimeout}
	}
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cp.Timeout == 0 || cp.Timeout > requestTimeout {
		cp.Timeout = requestTimeout
	}
	baseURLs.RLock()
	oa, an := baseURLs.openai, baseURLs.anthropic
	baseURLs.RUnlock()
	switch provider {
	case OpenAI:
		return &openAIClient{h: &httpGetter{hc: &cp, base: oa, auth: func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+adminKey)
		}}}, nil
	case Anthropic:
		return &anthropicClient{h: &httpGetter{hc: &cp, base: an, auth: func(r *http.Request) {
			r.Header.Set("x-api-key", adminKey)
			r.Header.Set("anthropic-version", AnthropicVersion)
		}}}, nil
	}
	return nil, fmt.Errorf("unsupported provider %q", provider)
}

/* ------------------------------------------------------------------------- */

// httpGetter is the only way the clients reach a provider: GET, fixed base.
type httpGetter struct {
	hc    *http.Client
	base  string
	auth  func(*http.Request)
	sleep func(context.Context, time.Duration) error // tests
}

func (g *httpGetter) wait(ctx context.Context, d time.Duration) error {
	if g.sleep != nil {
		return g.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// get GETs base+path?q into out (JSON), retrying 429 and 5xx. It returns the
// response headers of the successful call.
func (g *httpGetter) get(ctx context.Context, path string, q url.Values, out any) (http.Header, error) {
	u := g.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var last error
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, &Error{Message: "could not build the provider request"}
		}
		g.auth(req)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := g.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// A transport error names the URL, never a header.
			last = &Error{Message: "provider unreachable: " + scrub(err.Error())}
			if attempt >= maxRetries {
				return nil, last
			}
			if err := g.wait(ctx, backoff(attempt, "")); err != nil {
				return nil, err
			}
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if rerr != nil {
				return nil, &Error{Status: resp.StatusCode, Message: "reading the provider response failed"}
			}
			if len(body) > maxBody {
				return nil, &Error{Status: resp.StatusCode, Message: "the provider response is larger than 16 MiB"}
			}
			if err := json.Unmarshal(body, out); err != nil {
				return nil, &Error{Status: resp.StatusCode, Message: "the provider response is not the documented JSON"}
			}
			return resp.Header, nil
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return nil, &Error{Status: resp.StatusCode, Auth: true, Message: providerMessage(body)}
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			last = &Error{Status: resp.StatusCode, Message: providerMessage(body)}
			if attempt >= maxRetries {
				return nil, last
			}
			if err := g.wait(ctx, backoff(attempt, resp.Header.Get("Retry-After"))); err != nil {
				return nil, err
			}
		default:
			return nil, &Error{Status: resp.StatusCode, Message: providerMessage(body)}
		}
	}
}

// backoff is Retry-After (seconds, capped) or 2, 4, 8, 16 s.
func backoff(attempt int, retryAfter string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && n >= 0 {
		d := time.Duration(n) * time.Second
		if d > maxRetryWait {
			d = maxRetryWait
		}
		return d
	}
	return time.Duration(2<<attempt) * time.Second
}

var keyShaped = regexp.MustCompile(`(sk-[A-Za-z0-9_\-]{4,}|[A-Za-z0-9_\-]{40,})`)

// scrub removes anything shaped like a key and bounds the length.
func scrub(s string) string {
	s = keyShaped.ReplaceAllString(s, "[redacted]")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// Scrub is scrub for callers that store a provider message.
func Scrub(s string) string { return scrub(s) }

// providerMessage is the provider's error message ({"error":{"message"}}),
// scrubbed, or a generic one.
func providerMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return scrub(e.Error.Message)
	}
	return "no error message"
}

// usageKey aggregates usage rows.
type usageKey struct {
	key, project, model string
	bucket              int64
}

type usageAgg struct {
	m     map[usageKey]*UsageRow
	order []usageKey
}

func newUsageAgg() *usageAgg { return &usageAgg{m: map[usageKey]*UsageRow{}} }

func (a *usageAgg) add(r UsageRow) {
	r.BucketStart = r.BucketStart.UTC().Truncate(time.Hour)
	k := usageKey{r.KeyID, r.ProjectID, r.Model, r.BucketStart.Unix()}
	cur := a.m[k]
	if cur == nil {
		cp := r
		if r.Requests != nil {
			n := *r.Requests
			cp.Requests = &n
		}
		a.m[k] = &cp
		a.order = append(a.order, k)
		return
	}
	if r.Requests != nil {
		if cur.Requests == nil {
			n := int64(0)
			cur.Requests = &n
		}
		*cur.Requests += *r.Requests
	}
	cur.InputTokens += r.InputTokens
	cur.CachedInputTokens += r.CachedInputTokens
	cur.OutputTokens += r.OutputTokens
}

func (a *usageAgg) rows() []UsageRow {
	out := make([]UsageRow, 0, len(a.order))
	for _, k := range a.order {
		r := a.m[k]
		if r.InputTokens == 0 && r.OutputTokens == 0 && r.CachedInputTokens == 0 && (r.Requests == nil || *r.Requests == 0) {
			continue
		}
		out = append(out, *r)
	}
	return out
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func unixPtr(n *int64) *time.Time {
	if n == nil || *n <= 0 {
		return nil
	}
	t := time.Unix(*n, 0).UTC()
	return &t
}
