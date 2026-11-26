package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// Decision sources (agent_gateway_decision.source).
const (
	SourcePDP        = "pdp"
	SourceCache      = "cache"
	SourceGateway    = "gateway"
	SourceFailOpen   = "fail_open"
	SourceFailClosed = "fail_closed"
)

// Decision is what the gateway enforces.
type Decision struct {
	Allowed  bool
	Reason   string
	PolicyID string
	// DecisionID is the PDP's decision (for a cache hit, the cached one).
	DecisionID string
	Source     string
	LatencyMS  float64
}

// Hints are the PDP's fail-mode hints.
type Hints struct {
	Mode        string                `json:"mode"`
	DenyTargets []agentgateway.Target `json:"deny_targets"`
	TTLSeconds  int                   `json:"ttl_seconds"`
}

type cacheEntry struct {
	d       Decision
	expires time.Time
}

// decisionCache is a bounded TTL cache of PDP decisions.
type decisionCache struct {
	mu  sync.Mutex
	max int
	m   map[string]cacheEntry
	now func() time.Time
}

func newDecisionCache(max int, now func() time.Time) *decisionCache {
	return &decisionCache{max: max, m: map[string]cacheEntry{}, now: now}
}

func (c *decisionCache) get(k string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return Decision{}, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, k)
		return Decision{}, false
	}
	return e.d, true
}

func (c *decisionCache) put(k string, d Decision, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max {
		for kk, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, kk)
			}
		}
		for kk := range c.m {
			if len(c.m) < c.max {
				break
			}
			delete(c.m, kk)
		}
	}
	c.m[k] = cacheEntry{d: d, expires: now.Add(ttl)}
}

func (c *decisionCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// CacheKey is the cache key of a request: everything the PDP decides on
// (agent and its attributes, action, target), never the arguments.
func CacheKey(r agentgateway.Request) string {
	labels := append([]string(nil), r.Labels...)
	sort.Strings(labels)
	return strings.Join([]string{r.Kind, r.SubjectID, r.IdentityID, r.WorkloadID, strings.Join(labels, ","),
		r.Server, r.ServerURL, r.Tool, r.Provider, r.Model, r.Operation}, "\x1f")
}

// PDPClient asks AuthSec and applies the cache and the fail mode.
type PDPClient struct {
	base       string
	credential string
	version    string
	hc         *http.Client
	timeout    time.Duration
	failMode   string
	cache      *decisionCache
	hints      atomic.Pointer[Hints]
	now        func() time.Time
	up         *Uploader
}

// NewPDPClient builds the client.
func NewPDPClient(cfg *Config, version string, hc *http.Client, up *Uploader) *PDPClient {
	if hc == nil {
		hc = &http.Client{}
	}
	c := &PDPClient{base: cfg.AuthSec.URL, credential: cfg.AuthSec.credential, version: version, hc: hc,
		timeout: cfg.timeout(), failMode: cfg.FailMode, now: time.Now, up: up}
	c.cache = newDecisionCache(cfg.Cache.MaxEntries, func() time.Time { return c.now() })
	return c
}

func (c *PDPClient) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-AuthSec-Gateway-Version", c.version)
	return req, nil
}

var errPDP = errors.New("pdp unavailable")

// evaluate calls POST /pdp/access/v1/evaluation.
func (c *PDPClient) evaluate(ctx context.Context, r agentgateway.Request) (agentgateway.EvaluationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodPost, "/pdp/access/v1/evaluation", r.ToAuthZEN())
	if err != nil {
		return agentgateway.EvaluationResponse{}, err
	}
	if r.RequestID != "" {
		req.Header.Set("X-Request-ID", r.RequestID)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return agentgateway.EvaluationResponse{}, fmt.Errorf("%w: %v", errPDP, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return agentgateway.EvaluationResponse{}, fmt.Errorf("%w: status %d: %s", errPDP, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out agentgateway.EvaluationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("%w: bad response: %v", errPDP, err)
	}
	return out, nil
}

func ctxString(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

// failDecision applies the fail mode (spec §7).
func (c *PDPClient) failDecision(r agentgateway.Request) Decision {
	allowed := false
	switch c.failMode {
	case FailOpen:
		allowed = true
	case FailAuto:
		h := c.hints.Load()
		if h != nil && h.Mode != agentgateway.ModeEnforce {
			allowed = true
			for _, t := range h.DenyTargets {
				if t.Matches(r) {
					allowed = false
					break
				}
			}
		}
	}
	d := Decision{Allowed: allowed, Reason: agentgateway.ReasonPDPUnavailable, Source: SourceFailClosed}
	if allowed {
		d.Source = SourceFailOpen
	}
	return d
}

// Decide decides one request: the cache, else the PDP, else the fail mode.
// Decisions the gateway makes itself (cache, fail mode) are queued for
// upload; the PDP records its own.
func (c *PDPClient) Decide(ctx context.Context, r agentgateway.Request) Decision {
	start := time.Now()
	key := CacheKey(r)
	if d, ok := c.cache.get(key); ok {
		ref := d.DecisionID
		d.Source = SourceCache
		d.LatencyMS = msSince(start)
		c.up.Decision(r, d, ref)
		return d
	}
	resp, err := c.evaluate(ctx, r)
	if err != nil {
		log.Printf("[agent-gateway] pdp outcome=unavailable fail_mode=%s err=%v", c.failMode, err)
		d := c.failDecision(r)
		d.LatencyMS = msSince(start)
		c.up.Decision(r, d, "")
		return d
	}
	d := Decision{Allowed: resp.Decision, Source: SourcePDP, LatencyMS: msSince(start),
		Reason:     ctxString(resp.Context, "reason_admin", "reason"),
		PolicyID:   ctxString(resp.Context, "reason_admin", "policy_id"),
		DecisionID: ctxString(resp.Context, "decision_id")}
	if ttl, ok := resp.Context["ttl_seconds"].(float64); ok && ttl > 0 {
		if ttl > 300 {
			ttl = 300
		}
		c.cache.put(key, d, time.Duration(ttl)*time.Second)
	}
	return d
}

// RefreshHints fetches GET /pdp/v1/policy-hints.
func (c *PDPClient) RefreshHints(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodGet, "/pdp/v1/policy-hints", nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy hints: status %d", resp.StatusCode)
	}
	var h Hints
	if err := json.Unmarshal(raw, &h); err != nil {
		return err
	}
	c.hints.Store(&h)
	return nil
}

// RunHints refreshes the hints every interval until ctx ends.
func (c *PDPClient) RunHints(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := c.RefreshHints(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[agent-gateway] policy hints refresh failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000.0 }

/* --------------------------------- upload --------------------------------- */

// Usage is token usage of a model call.
type Usage struct {
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`
}

func (u *Usage) empty() bool {
	return u == nil || (u.InputTokens == nil && u.OutputTokens == nil && u.TotalTokens == nil)
}

// Record is one uploaded record (POST /pdp/v1/decisions).
type Record struct {
	ID             string               `json:"id"`
	RecordType     string               `json:"record_type"`
	Source         string               `json:"source"`
	DecidedAt      time.Time            `json:"decided_at"`
	Subject        *agentgateway.Entity `json:"subject"`
	Action         *agentgateway.Action `json:"action"`
	Resource       *agentgateway.Entity `json:"resource"`
	Decision       string               `json:"decision"`
	Reason         string               `json:"reason"`
	PolicyID       string               `json:"policy_id,omitempty"`
	DecisionRef    string               `json:"decision_ref,omitempty"`
	LatencyMS      *float64             `json:"latency_ms,omitempty"`
	ArgsDigest     string               `json:"args_digest,omitempty"`
	Usage          *Usage               `json:"usage,omitempty"`
	UpstreamStatus *int                 `json:"upstream_status,omitempty"`
	RequestID      string               `json:"request_id,omitempty"`
}

// Uploader queues records and posts them in batches.
type Uploader struct {
	pdp      *PDPClient
	mu       sync.Mutex
	q        []Record
	max      int
	batch    int
	dropped  int64
	now      func() time.Time
	wake     chan struct{}
	inflight sync.Mutex
}

// NewUploader builds an uploader; Attach sets its client.
func NewUploader(cfg *Config) *Uploader {
	return &Uploader{max: cfg.Upload.MaxQueue, batch: cfg.Upload.BatchSize, now: time.Now, wake: make(chan struct{}, 1)}
}

// Attach sets the PDP client used for uploads.
func (u *Uploader) Attach(c *PDPClient) { u.pdp = c }

func (u *Uploader) push(r Record) {
	if u == nil {
		return
	}
	u.mu.Lock()
	if len(u.q) >= u.max {
		u.q = u.q[1:]
		u.dropped++
	}
	u.q = append(u.q, r)
	full := len(u.q) >= u.batch
	u.mu.Unlock()
	if full {
		select {
		case u.wake <- struct{}{}:
		default:
		}
	}
}

func baseRecord(r agentgateway.Request, now time.Time) Record {
	e := r.ToAuthZEN()
	return Record{ID: uuid.NewString(), DecidedAt: now.UTC(), Subject: e.Subject, Action: e.Action, Resource: e.Resource,
		ArgsDigest: r.ArgsDigest, RequestID: r.RequestID}
}

func word(allowed bool) string {
	if allowed {
		return agentgateway.EffectAllow
	}
	return agentgateway.EffectDeny
}

// Decision queues a decision the gateway made itself (not a PDP one).
func (u *Uploader) Decision(r agentgateway.Request, d Decision, ref string) {
	if u == nil || d.Source == SourcePDP {
		return
	}
	rec := baseRecord(r, u.now())
	rec.RecordType, rec.Source, rec.Decision, rec.Reason = "decision", d.Source, word(d.Allowed), d.Reason
	rec.PolicyID, rec.DecisionRef = d.PolicyID, ref
	lat := d.LatencyMS
	rec.LatencyMS = &lat
	u.push(rec)
}

// Outcome queues the outcome of an allowed call (status, latency, usage).
func (u *Uploader) Outcome(r agentgateway.Request, d Decision, status int, latencyMS float64, usage *Usage) {
	if u == nil {
		return
	}
	rec := baseRecord(r, u.now())
	rec.RecordType, rec.Source, rec.Decision, rec.Reason = "outcome", d.Source, agentgateway.EffectAllow, agentgateway.ReasonUpstreamCompleted
	rec.PolicyID, rec.DecisionRef = d.PolicyID, d.DecisionID
	rec.LatencyMS = &latencyMS
	if status >= 100 && status <= 599 {
		rec.UpstreamStatus = &status
	}
	if !usage.empty() {
		rec.Usage = usage
	}
	u.push(rec)
}

// Pending is the queue length (tests, health).
func (u *Uploader) Pending() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.q)
}

// Flush posts queued records until the queue is empty or a post fails.
func (u *Uploader) Flush(ctx context.Context) error {
	u.inflight.Lock()
	defer u.inflight.Unlock()
	for {
		u.mu.Lock()
		n := len(u.q)
		if n > u.batch {
			n = u.batch
		}
		batch := append([]Record(nil), u.q[:n]...)
		dropped := u.dropped
		u.dropped = 0
		u.mu.Unlock()
		if dropped > 0 {
			log.Printf("[agent-gateway] upload queue full: %d records dropped", dropped)
		}
		if n == 0 {
			return nil
		}
		retry, err := u.post(ctx, batch)
		if err != nil && retry {
			return err
		}
		if err != nil {
			log.Printf("[agent-gateway] upload refused, %d records dropped: %v", n, err)
		}
		u.mu.Lock()
		// The queue may have dropped from its head meanwhile; remove what
		// was sent by id.
		sent := map[string]bool{}
		for _, r := range batch {
			sent[r.ID] = true
		}
		kept := u.q[:0]
		for _, r := range u.q {
			if !sent[r.ID] {
				kept = append(kept, r)
			}
		}
		u.q = kept
		u.mu.Unlock()
	}
}

// post sends one batch; retry reports whether a failure is worth retrying.
func (u *Uploader) post(ctx context.Context, batch []Record) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := u.pdp.newRequest(ctx, http.MethodPost, "/pdp/v1/decisions", map[string]any{"records": batch})
	if err != nil {
		return false, err
	}
	resp, err := u.pdp.hc.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 || resp.StatusCode == http.StatusUnauthorized:
		return true, fmt.Errorf("status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("status %d", resp.StatusCode)
	}
}

// Run uploads every interval (and when a batch fills) until ctx ends, with
// backoff after failures; it flushes once more on the way out.
func (u *Uploader) Run(ctx context.Context, every time.Duration) {
	backoff := every
	t := time.NewTimer(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = u.Flush(fctx)
			cancel()
			return
		case <-t.C:
		case <-u.wake:
		}
		if err := u.Flush(ctx); err != nil {
			log.Printf("[agent-gateway] upload failed, retrying: %v", err)
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		} else {
			backoff = every
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(backoff)
	}
}
