package agentgateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // time windows name IANA zones; a minimal image has no zoneinfo

	"github.com/google/uuid"
)

// Effects and workspace modes.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"

	ModeObserve = "observe"
	ModeEnforce = "enforce"
)

// Decision reasons (reason_admin.reason, agent_gateway_decision.reason).
const (
	ReasonPolicyDeny            = "policy_deny"
	ReasonPolicyAllow           = "policy_allow"
	ReasonRateLimited           = "rate_limited"
	ReasonNotAllowlisted        = "not_allowlisted"
	ReasonDefaultAllow          = "default_allow"
	ReasonDefaultDeny           = "default_deny"
	ReasonToolDefinitionChanged = "tool_definition_changed"
	ReasonToolNotPinned         = "tool_not_pinned"
	ReasonPDPUnavailable        = "pdp_unavailable"
	ReasonUpstreamCompleted     = "upstream_completed"
)

// Limits on a policy.
const (
	MaxPolicyNameLen   = 200
	MaxPatternLen      = 512
	MaxCallsPerMinute  = 100000
	MaxPoliciesPerWS   = 1000
	MaxDescriptionLen  = 2000
	MaxPriorityMagnitd = 1000000
)

// TimeWindow limits a policy to days and an hour range in a time zone.
// Start and End are "HH:MM"; both empty means the whole day; Start > End
// spans midnight. Days are mon..sun (empty = every day).
type TimeWindow struct {
	Days     []string `json:"days,omitempty"`
	Start    string   `json:"start,omitempty"`
	End      string   `json:"end,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
}

// Conditions are a policy's conditions.
type Conditions struct {
	TimeWindow *TimeWindow `json:"time_window,omitempty"`
	// MaxCallsPerMinute (allow policies only): calls beyond it are denied
	// rate_limited.
	MaxCallsPerMinute int `json:"max_calls_per_minute,omitempty"`
}

// Policy is one agent_tool_policy row as evaluated.
type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Effect      string     `json:"effect"`
	Kind        string     `json:"kind"`
	Subject     Selector   `json:"subject"`
	Target      Target     `json:"target"`
	Conditions  Conditions `json:"conditions"`
	// DenyUnlisted (allow only): the agents this policy selects may use
	// only targets of this kind that some allow policy allows them.
	DenyUnlisted bool `json:"deny_unlisted"`
	Priority     int  `json:"priority"`
	Enabled      bool `json:"enabled"`
}

// Selector names the agents a policy governs. Every non-empty field must
// match; an empty selector matches every agent.
type Selector struct {
	IdentityID string `json:"identity_id,omitempty"`
	WorkloadID string `json:"workload_id,omitempty"`
	AgentLabel string `json:"agent_label,omitempty"`
	// ClientID is a pattern on subject.id (gateway client id or SPIFFE ID).
	ClientID  string `json:"client_id,omitempty"`
	GatewayID string `json:"gateway_id,omitempty"`
}

// Target is what a policy applies to; patterns, ” = any.
type Target struct {
	Kind      string `json:"kind,omitempty"`
	Server    string `json:"server,omitempty"`
	ServerURL string `json:"server_url,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Model     string `json:"model,omitempty"`
}

// FieldError is one validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Message }

// ParseConditions decodes a conditions object strictly (unknown members are
// refused, so a typo never silently widens a policy).
func ParseConditions(raw []byte) (Conditions, error) {
	var c Conditions
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return c, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("conditions: %w", err)
	}
	return c, nil
}

var dayIndex = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func parseHM(s string) (int, bool) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, false
	}
	return hh*60 + mm, true
}

// Validate checks a policy (the PDP refuses to store an invalid one).
func (p *Policy) Validate() []FieldError {
	var errs []FieldError
	add := func(f, m string) { errs = append(errs, FieldError{Field: f, Message: m}) }
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > MaxPolicyNameLen {
		add("name", fmt.Sprintf("name is required (at most %d characters)", MaxPolicyNameLen))
	}
	if len(p.Description) > MaxDescriptionLen {
		add("description", fmt.Sprintf("at most %d characters", MaxDescriptionLen))
	}
	if p.Effect != EffectAllow && p.Effect != EffectDeny {
		add("effect", "effect must be allow or deny")
	}
	switch p.Kind {
	case KindMCPTool:
		if p.Target.Provider != "" || p.Target.Model != "" {
			add("target", "an mcp_tool policy names server, server_url and tool, not provider or model")
		}
	case KindModel:
		if p.Target.Server != "" || p.Target.ServerURL != "" || p.Target.Tool != "" {
			add("target", "a model policy names provider and model, not server or tool")
		}
		p.Target.Provider = strings.ToLower(p.Target.Provider)
	default:
		add("kind", "kind must be mcp_tool or model")
	}
	p.Target.Kind = p.Kind
	for f, v := range map[string]string{"target.server": p.Target.Server, "target.server_url": p.Target.ServerURL,
		"target.tool": p.Target.Tool, "target.provider": p.Target.Provider, "target.model": p.Target.Model,
		"subject.client_id": p.Subject.ClientID, "subject.agent_label": p.Subject.AgentLabel} {
		if len(v) > MaxPatternLen {
			add(f, fmt.Sprintf("at most %d characters", MaxPatternLen))
		}
	}
	for f, v := range map[string]*string{"subject.identity_id": &p.Subject.IdentityID,
		"subject.workload_id": &p.Subject.WorkloadID, "subject.gateway_id": &p.Subject.GatewayID} {
		if *v == "" {
			continue
		}
		id, err := uuid.Parse(*v)
		if err != nil {
			add(f, "must be a UUID")
			continue
		}
		*v = id.String()
	}
	if p.DenyUnlisted && p.Effect != EffectAllow {
		add("deny_unlisted", "deny_unlisted applies to allow policies only")
	}
	if p.Priority > MaxPriorityMagnitd || p.Priority < -MaxPriorityMagnitd {
		add("priority", "priority must be between -1000000 and 1000000")
	}
	c := p.Conditions
	if c.MaxCallsPerMinute < 0 || c.MaxCallsPerMinute > MaxCallsPerMinute {
		add("conditions.max_calls_per_minute", fmt.Sprintf("must be between 1 and %d", MaxCallsPerMinute))
	}
	if c.MaxCallsPerMinute > 0 && p.Effect != EffectAllow {
		add("conditions.max_calls_per_minute", "a rate applies to allow policies only")
	}
	if w := c.TimeWindow; w != nil {
		for i, d := range w.Days {
			d = strings.ToLower(strings.TrimSpace(d))
			if _, ok := dayIndex[d]; !ok {
				add("conditions.time_window.days", "days are mon, tue, wed, thu, fri, sat, sun")
				break
			}
			w.Days[i] = d
		}
		if (w.Start == "") != (w.End == "") {
			add("conditions.time_window", "start and end are both set or both empty")
		}
		if w.Start != "" {
			s, ok1 := parseHM(w.Start)
			e, ok2 := parseHM(w.End)
			if !ok1 || !ok2 {
				add("conditions.time_window", "start and end are HH:MM")
			} else if s == e {
				add("conditions.time_window", "start and end must differ")
			}
		}
		if w.Timezone != "" {
			if _, err := time.LoadLocation(w.Timezone); err != nil {
				add("conditions.time_window.timezone", "unknown time zone")
			}
		}
	}
	return errs
}

// Active reports whether the window contains t (nil window: always).
func (w *TimeWindow) Active(t time.Time) bool {
	if w == nil {
		return true
	}
	loc := time.UTC
	if w.Timezone != "" {
		if l, err := time.LoadLocation(w.Timezone); err == nil {
			loc = l
		} else {
			return false // fail closed for an allow; a deny is checked the same way
		}
	}
	lt := t.In(loc)
	if len(w.Days) > 0 {
		ok := false
		for _, d := range w.Days {
			if dayIndex[d] == lt.Weekday() {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if w.Start == "" {
		return true
	}
	s, _ := parseHM(w.Start)
	e, _ := parseHM(w.End)
	m := lt.Hour()*60 + lt.Minute()
	if s < e {
		return m >= s && m < e
	}
	return m >= s || m < e
}

// Glob matches s against pattern, where '*' matches any run of characters
// (including none) and every other character matches itself. An empty
// pattern matches everything.
func Glob(pattern, s string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// MatchesSubject reports whether the selector selects the request's agent.
func (s Selector) MatchesSubject(r Request) bool {
	if s.GatewayID != "" && !strings.EqualFold(s.GatewayID, r.GatewayID) {
		return false
	}
	if s.IdentityID != "" && !strings.EqualFold(s.IdentityID, r.IdentityID) {
		return false
	}
	if s.WorkloadID != "" && !strings.EqualFold(s.WorkloadID, r.WorkloadID) {
		return false
	}
	if s.ClientID != "" && !Glob(s.ClientID, r.SubjectID) {
		return false
	}
	if s.AgentLabel != "" {
		ok := false
		for _, l := range r.Labels {
			if Glob(s.AgentLabel, l) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Matches reports whether the target covers the request's resource.
func (t Target) Matches(r Request) bool {
	if t.Kind != "" && t.Kind != r.Kind {
		return false
	}
	if r.Kind == KindModel {
		return Glob(strings.ToLower(t.Provider), strings.ToLower(r.Provider)) && Glob(t.Model, r.Model)
	}
	return Glob(t.Server, r.Server) && Glob(t.ServerURL, r.ServerURL) && Glob(t.Tool, r.Tool)
}

// RateLimiter takes one call from a policy's bucket for key; false when it
// is empty. A nil RateLimiter (a dry run) never refuses and takes nothing.
type RateLimiter interface {
	Take(policyID, key string, perMinute int) bool
}

// Trace is one policy's part in a decision (the dry run shows them all).
type Trace struct {
	PolicyID     string `json:"policy_id"`
	Name         string `json:"name"`
	Effect       string `json:"effect"`
	Enabled      bool   `json:"enabled"`
	SubjectMatch bool   `json:"subject_match"`
	TargetMatch  bool   `json:"target_match"`
	WindowActive bool   `json:"window_active"`
	// Outcome: decided, rate_limited, not_applicable, superseded.
	Outcome string `json:"outcome"`
}

// Result is a decision.
type Result struct {
	Allowed    bool
	Reason     string
	PolicyID   string
	PolicyName string
	// Cacheable: a gateway may reuse it (false when a rate applied).
	Cacheable bool
	// TTLCap, when > 0, bounds how long a gateway may cache it (a time
	// window may close).
	TTLCap time.Duration
	Trace  []Trace
}

// SortPolicies orders policies as evaluation reads them: priority
// descending, then name, then id -- so a decision always names the same
// policy.
func SortPolicies(ps []Policy) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority != ps[j].Priority {
			return ps[i].Priority > ps[j].Priority
		}
		if ps[i].Name != ps[j].Name {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].ID < ps[j].ID
	})
}

// RateKey is the rate bucket key of a request (per gateway, agent and
// target; the policy id is passed separately).
func RateKey(r Request) string {
	return r.GatewayID + "\x1f" + r.SubjectID + "\x1f" + r.Kind + "\x1f" + r.ResourceID()
}

// Evaluate decides one request against the workspace's policies (sorted by
// SortPolicies) and mode:
//
//  1. a matching enabled deny policy denies (policy_deny);
//  2. matching enabled allow policies, in order: the first with a token
//     allows (policy_allow); if every one is out of tokens, rate_limited;
//  3. an enabled allow policy with deny_unlisted of this kind that selects
//     the agent denies (not_allowlisted);
//  4. the mode: observe allows (default_allow), enforce denies
//     (default_deny).
//
// "Matching" is subject, target and an active time window.
func Evaluate(policies []Policy, r Request, mode string, now time.Time, rl RateLimiter) Result {
	res := Result{Cacheable: true}
	trace := make([]Trace, 0, len(policies))
	var deny, allows, listing []int
	windowed := false
	for i := range policies {
		p := &policies[i]
		t := Trace{PolicyID: p.ID, Name: p.Name, Effect: p.Effect, Enabled: p.Enabled, Outcome: "not_applicable"}
		if p.Kind == r.Kind {
			t.SubjectMatch = p.Subject.MatchesSubject(r)
			t.TargetMatch = p.Target.Matches(r)
			t.WindowActive = p.Conditions.TimeWindow.Active(now)
		}
		trace = append(trace, t)
		if !p.Enabled || p.Kind != r.Kind || !t.SubjectMatch {
			continue
		}
		if p.Effect == EffectAllow && p.DenyUnlisted {
			listing = append(listing, i)
		}
		if !t.TargetMatch {
			continue
		}
		if p.Conditions.TimeWindow != nil {
			windowed = true
		}
		if !t.WindowActive {
			continue
		}
		if p.Effect == EffectDeny {
			deny = append(deny, i)
		} else {
			allows = append(allows, i)
		}
	}
	if windowed {
		// A window opens or closes on a minute boundary.
		next := now.Truncate(time.Minute).Add(time.Minute)
		res.TTLCap = next.Sub(now)
		if res.TTLCap < time.Second {
			res.TTLCap = time.Second
		}
	}
	decide := func(i int, allowed bool, reason string) {
		res.Allowed, res.Reason = allowed, reason
		res.PolicyID, res.PolicyName = policies[i].ID, policies[i].Name
		trace[i].Outcome = "decided"
	}
	switch {
	case len(deny) > 0:
		decide(deny[0], false, ReasonPolicyDeny)
		for _, i := range deny[1:] {
			trace[i].Outcome = "superseded"
		}
		for _, i := range allows {
			trace[i].Outcome = "superseded"
		}
	case len(allows) > 0:
		decided := false
		for _, i := range allows {
			p := policies[i]
			if decided {
				trace[i].Outcome = "superseded"
				continue
			}
			if p.Conditions.MaxCallsPerMinute > 0 {
				res.Cacheable = false
				if rl != nil && !rl.Take(p.ID, RateKey(r), p.Conditions.MaxCallsPerMinute) {
					trace[i].Outcome = "rate_limited"
					continue
				}
			}
			decide(i, true, ReasonPolicyAllow)
			decided = true
		}
		if !decided {
			first := allows[0]
			res.Allowed, res.Reason = false, ReasonRateLimited
			res.PolicyID, res.PolicyName = policies[first].ID, policies[first].Name
		}
	case len(listing) > 0:
		decide(listing[0], false, ReasonNotAllowlisted)
	case mode == ModeEnforce:
		res.Allowed, res.Reason = false, ReasonDefaultDeny
	default:
		res.Allowed, res.Reason = true, ReasonDefaultAllow
	}
	res.Trace = trace
	return res
}

// DenyTargets are the targets of the enabled deny policies (the gateway's
// fail-mode hints): a gateway that cannot reach AuthSec fails closed for
// these in its auto fail mode.
func DenyTargets(policies []Policy) []Target {
	seen := map[Target]bool{}
	var out []Target
	for _, p := range policies {
		if !p.Enabled || p.Effect != EffectDeny {
			continue
		}
		t := p.Target
		t.Kind = p.Kind
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
