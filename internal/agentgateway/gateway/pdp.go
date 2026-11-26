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
	// ArgBounds are the deciding policy's argument bounds (P17): the
	// gateway checks the call's arguments against them.
	ArgBounds *agentgateway.ArgBounds
}

// ReasonInvalidArgBounds refuses a call whose policy's bounds this gateway
// cannot read: a bound it cannot check is never skipped.
const ReasonInvalidArgBounds = "invalid_arg_bounds"

// Hints are what AuthSec tells a gateway between decisions
// (GET /pdp/v1/policy-hints): the workspace mode and deny targets (auto fail
// mode), and (AS-174) this gateway's fail mode and decision cache lifetime as
// AuthSec sets them, the agents it must refuse locally, and versions.
type Hints struct {
	Mode        string                `json:"mode"`
	DenyTargets []agentgateway.Target `json:"deny_targets"`
	// TTLSeconds is how long the hints themselves are good for.
	TTLSeconds int `json:"ttl_seconds"`
	// FailMode is AuthSec's fail mode for this gateway; local config can
	// only make it stricter. Empty (an older AuthSec) counts as auto.
	FailMode string `json:"fail_mode,omitempty"`
	// CacheTTLSeconds caps how long any decision is cached (0 = never).
	CacheTTLSeconds *int `json:"cache_ttl_seconds,omitempty"`
	// Stopped are the agents refused before the cache and the PDP.
	Stopped []agentgateway.StoppedSubject `json:"stopped,omitempty"`
	// PolicyVersion changes with any policy or setting: the cache is
	// emptied when it does (a new deny is not served from an old allow).
	PolicyVersion string `json:"policy_version,omitempty"`
	// AgentKeys are the AuthSec-issued agent keys this gateway may accept,
	// each with the workload identity it is bound to (W6).
	AgentKeys []AgentKeyHint `json:"agent_keys,omitempty"`
	// Version is the whole body's version (the ETag).
	Version string `json:"version,omitempty"`
}

type cacheEntry struct {
	d       Decision
	expires time.Time
	// req is the request decided (its subject and kind), so the entries of
	// a stopped agent can be purged.
	req agentgateway.Request
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

func (c *decisionCache) put(k string, r agentgateway.Request, d Decision, ttl time.Duration) {
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
	c.m[k] = cacheEntry{d: d, expires: now.Add(ttl), req: r}
}

// purge removes the entries whose request matches and returns how many.
func (c *decisionCache) purge(match func(agentgateway.Request) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, e := range c.m {
		if match(e.req) {
			delete(c.m, k)
			n++
		}
	}
	return n
}

// capTTL shortens every entry to at most ttl from now (0 empties the cache).
func (c *decisionCache) capTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := c.now().Add(ttl)
	for k, e := range c.m {
		if ttl <= 0 {
			delete(c.m, k)
			continue
		}
		if e.expires.After(limit) {
			e.expires = limit
			c.m[k] = e
		}
	}
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

// MaxCacheTTL is the longest a decision is ever cached, whatever AuthSec or
// the PDP says.
const MaxCacheTTL = 300 * time.Second

// minHintsStale is the shortest time after which hints count as stale.
const minHintsStale = 30 * time.Second

// PDPClient asks AuthSec and applies the stop list, the cache and the fail
// mode.
type PDPClient struct {
	base       string
	credential string
	version    string
	hc         *http.Client
	timeout    time.Duration
	// failMode and maxTTL are the LOCAL configuration: they can only make
	// AuthSec's values stricter.
	failMode string
	maxTTL   time.Duration
	cache    *decisionCache
	hints    atomic.Pointer[Hints]
	// hintsAt is when hints were last confirmed (a 200 or a 304), unix ns.
	hintsAt    atomic.Int64
	hintsEvery time.Duration
	hintsMu    sync.Mutex
	etag       string
	now        func() time.Time
	up         *Uploader
	// agentKeys are the hints' agent keys by sha256.
	agentKeys atomic.Pointer[map[string]AgentKeyHint]
}

// AgentKey returns the AuthSec-issued agent key with this sha256.
func (c *PDPClient) AgentKey(sha string) (AgentKeyHint, bool) {
	m := c.agentKeys.Load()
	if m == nil {
		return AgentKeyHint{}, false
	}
	k, ok := (*m)[sha]
	return k, ok
}

// NewPDPClient builds the client.
func NewPDPClient(cfg *Config, version string, hc *http.Client, up *Uploader) *PDPClient {
	if hc == nil {
		hc = &http.Client{}
	}
	every := time.Duration(cfg.AuthSec.HintsIntervalS) * time.Second
	if every <= 0 {
		every = 5 * time.Second
	}
	c := &PDPClient{base: cfg.AuthSec.URL, credential: cfg.AuthSec.credential, version: version, hc: hc,
		timeout: cfg.timeout(), failMode: cfg.FailMode, maxTTL: time.Duration(cfg.Cache.MaxTTLSeconds) * time.Second,
		hintsEvery: every, now: time.Now, up: up}
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

// FailMode is the fail mode in force: the stricter of AuthSec's (auto until
// hints arrive, or when an older AuthSec sends none) and the local one.
func (c *PDPClient) FailMode() string {
	server := FailAuto
	if h := c.hints.Load(); h != nil && h.FailMode != "" {
		server = h.FailMode
	}
	return agentgateway.StricterFailMode(c.failMode, server)
}

// CacheTTLCap is the longest a decision may be cached now: MaxCacheTTL,
// AuthSec's cache_ttl_seconds and the local max_ttl_seconds, whichever is
// shortest.
func (c *PDPClient) CacheTTLCap() time.Duration {
	limit := MaxCacheTTL
	if h := c.hints.Load(); h != nil && h.CacheTTLSeconds != nil {
		if d := time.Duration(*h.CacheTTLSeconds) * time.Second; d < limit {
			limit = d
		}
	}
	if c.maxTTL > 0 && c.maxTTL < limit {
		limit = c.maxTTL
	}
	if limit < 0 {
		limit = 0
	}
	return limit
}

// hintsFresh reports whether hints were confirmed recently enough for the
// cache to be used: a cached allow is served only while the stop list that
// would refuse it is current.
func (c *PDPClient) hintsFresh() bool {
	at := c.hintsAt.Load()
	if at == 0 {
		return false
	}
	stale := 3 * c.hintsEvery
	if stale < minHintsStale {
		stale = minHintsStale
	}
	return c.now().Sub(time.Unix(0, at)) <= stale
}

// StoppedBy returns the stop refusing r, or nil.
func (c *PDPClient) StoppedBy(r agentgateway.Request) *agentgateway.StoppedSubject {
	h := c.hints.Load()
	if h == nil {
		return nil
	}
	return agentgateway.StoppedBy(h.Stopped, r)
}

// failDecision applies the fail mode (spec §7).
func (c *PDPClient) failDecision(r agentgateway.Request) Decision {
	allowed := false
	switch c.FailMode() {
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

// StoppedDecision is the local refusal of a stopped agent.
func StoppedDecision() Decision {
	return Decision{Allowed: false, Reason: agentgateway.ReasonAgentStopped, Source: SourceGateway}
}

// Decide decides one request: a stopped agent is refused first (whatever
// the fail mode, the workspace mode or the cache), then the cache (only
// while hints are fresh), else the PDP, else the fail mode. Decisions the
// gateway makes itself (stop, cache, fail mode) are queued for upload; the
// PDP records its own.
func (c *PDPClient) Decide(ctx context.Context, r agentgateway.Request) Decision {
	start := time.Now()
	if s := c.StoppedBy(r); s != nil {
		d := StoppedDecision()
		d.LatencyMS = msSince(start)
		log.Printf("[agent-gateway] stopped agent refused agent=%s ref=%s", r.SubjectID, s.Ref)
		c.up.Decision(r, d, "")
		return d
	}
	key := CacheKey(r)
	if c.hintsFresh() {
		if d, ok := c.cache.get(key); ok {
			ref := d.DecisionID
			d.Source = SourceCache
			d.LatencyMS = msSince(start)
			c.up.Decision(r, d, ref)
			return d
		}
	}
	resp, err := c.evaluate(ctx, r)
	if err != nil {
		log.Printf("[agent-gateway] pdp outcome=unavailable fail_mode=%s err=%v", c.FailMode(), err)
		d := c.failDecision(r)
		d.LatencyMS = msSince(start)
		c.up.Decision(r, d, "")
		return d
	}
	d := Decision{Allowed: resp.Decision, Source: SourcePDP, LatencyMS: msSince(start),
		Reason:     ctxString(resp.Context, "reason_admin", "reason"),
		PolicyID:   ctxString(resp.Context, "reason_admin", "policy_id"),
		DecisionID: ctxString(resp.Context, "decision_id")}
	if d.Allowed {
		b, ok := agentgateway.BoundsFromContext(resp.Context)
		if !ok {
			log.Printf("[agent-gateway] unreadable argument bounds from AuthSec policy=%s: call refused", d.PolicyID)
			d.Allowed, d.Reason, d.Source = false, ReasonInvalidArgBounds, SourceGateway
			c.up.Decision(r, d, d.DecisionID)
			return d
		}
		d.ArgBounds = b
	}
	if ttl, ok := resp.Context["ttl_seconds"].(float64); ok && ttl > 0 {
		dur := time.Duration(ttl) * time.Second
		if limit := c.CacheTTLCap(); dur > limit {
			dur = limit
		}
		c.cache.put(key, r, d, dur)
	}
	return d
}

// applyHints installs new hints, then purges what they invalidate: every
// cached decision when the policy version changed, the entries of stopped
// agents, and whatever outlives the cache lifetime cap. Hints are installed
// first, so a request racing the purge already meets the new stop list.
func (c *PDPClient) applyHints(h *Hints) {
	keys := make(map[string]AgentKeyHint, len(h.AgentKeys))
	for _, k := range h.AgentKeys {
		keys[strings.ToLower(k.KeySHA256)] = k
	}
	c.agentKeys.Store(&keys)
	old := c.hints.Swap(h)
	c.hintsAt.Store(c.now().UnixNano())
	if old == nil || old.PolicyVersion != h.PolicyVersion {
		c.cache.purge(func(agentgateway.Request) bool { return true })
	}
	if len(h.Stopped) > 0 {
		if n := c.cache.purge(func(r agentgateway.Request) bool { return agentgateway.StoppedBy(h.Stopped, r) != nil }); n > 0 {
			log.Printf("[agent-gateway] purged %d cached decisions of stopped agents", n)
		}
	}
	c.cache.capTTL(c.CacheTTLCap())
	if old == nil || len(old.Stopped) != len(h.Stopped) || old.FailMode != h.FailMode {
		log.Printf("[agent-gateway] hints stopped_agents=%d fail_mode=%s (authsec=%q local=%s) cache_ttl_cap=%s",
			len(h.Stopped), c.FailMode(), h.FailMode, c.failMode, c.CacheTTLCap())
	}
}

// RefreshHints fetches GET /pdp/v1/policy-hints, conditional on the last
// version (an unchanged body is a 304).
func (c *PDPClient) RefreshHints(ctx context.Context) error {
	c.hintsMu.Lock()
	defer c.hintsMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodGet, "/pdp/v1/policy-hints", nil)
	if err != nil {
		return err
	}
	if c.etag != "" && c.hints.Load() != nil {
		req.Header.Set("If-None-Match", c.etag)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusNotModified && c.hints.Load() != nil {
		c.hintsAt.Store(c.now().UnixNano())
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy hints: status %d", resp.StatusCode)
	}
	var h Hints
	if err := json.Unmarshal(raw, &h); err != nil {
		return err
	}
	c.etag = resp.Header.Get("ETag")
	c.applyHints(&h)
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
	RunID          string               `json:"run_id,omitempty"`
	// ModelVersion is the model the provider says answered (outcomes).
	ModelVersion string `json:"model_version,omitempty"`
	// ProviderKeyID is the AuthSec-held provider key used (outcomes).
	ProviderKeyID string `json:"provider_key_id,omitempty"`
	// Violations are the bounded paths a call broke (never values).
	Violations []agentgateway.BoundViolation `json:"violations,omitempty"`
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
		ArgsDigest: r.ArgsDigest, RequestID: r.RequestID, RunID: r.RunID}
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

// DecisionViolations queues a gateway decision on a call outside its
// argument bounds: the violated paths and rules, never the values.
func (u *Uploader) DecisionViolations(r agentgateway.Request, d Decision, ref string, v []agentgateway.BoundViolation) {
	if u == nil {
		return
	}
	rec := baseRecord(r, u.now())
	rec.RecordType, rec.Source, rec.Decision, rec.Reason = "decision", d.Source, word(d.Allowed), d.Reason
	rec.PolicyID, rec.DecisionRef, rec.Violations = d.PolicyID, ref, v
	lat := d.LatencyMS
	rec.LatencyMS = &lat
	u.push(rec)
}

// OutcomeInfo is what the gateway learned from the upstream's answer.
type OutcomeInfo struct {
	Usage         *Usage
	ModelVersion  string
	ProviderKeyID string
}

// Outcome queues the outcome of an allowed call (status, latency, usage).
func (u *Uploader) Outcome(r agentgateway.Request, d Decision, status int, latencyMS float64, usage *Usage) {
	u.OutcomeWith(r, d, status, latencyMS, OutcomeInfo{Usage: usage})
}

// OutcomeWith queues an outcome with the model version and provider key.
func (u *Uploader) OutcomeWith(r agentgateway.Request, d Decision, status int, latencyMS float64, info OutcomeInfo) {
	if u == nil {
		return
	}
	usage := info.Usage
	rec := baseRecord(r, u.now())
	rec.ModelVersion, rec.ProviderKeyID = info.ModelVersion, info.ProviderKeyID
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
