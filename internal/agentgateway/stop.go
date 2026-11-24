package agentgateway

import (
	"sort"
	"strings"
)

// Stopped subjects and fail modes (AS-174). A stopped subject is an agent a
// gateway must refuse LOCALLY, before its decision cache and before the PDP,
// whatever its fail mode and whatever the workspace mode: a containment
// (agent_containment, live states) or a deny policy that blocks every target
// of a kind for an agent. AuthSec hands the list to each gateway in its
// policy hints; the PDP refuses the same subjects itself (reason
// agent_stopped), so a call the gateway has not cached is refused at once.

// ReasonAgentStopped is the reason of a refusal of a stopped subject.
const ReasonAgentStopped = "agent_stopped"

// Fail modes of a gateway (what it does when the PDP cannot answer).
const (
	FailClosed = "closed"
	FailAuto   = "auto"
	FailOpen   = "open"
)

// failStrictness orders fail modes: higher is stricter.
var failStrictness = map[string]int{FailOpen: 0, FailAuto: 1, FailClosed: 2}

// ValidFailMode reports whether m is a fail mode.
func ValidFailMode(m string) bool {
	_, ok := failStrictness[m]
	return ok
}

// StricterFailMode returns the stricter of two fail modes; an unknown value
// counts as closed (the strictest), so a typo never loosens.
func StricterFailMode(a, b string) string {
	ra, oka := failStrictness[a]
	rb, okb := failStrictness[b]
	if !oka || !okb {
		return FailClosed
	}
	if ra >= rb {
		return a
	}
	return b
}

// LoosensFailMode reports whether going from `from` to `to` loosens the fail
// mode (closed -> auto/open, auto -> open).
func LoosensFailMode(from, to string) bool {
	rf, okf := failStrictness[from]
	rt, okt := failStrictness[to]
	if !okf || !okt {
		return true
	}
	return rt < rf
}

// StoppedSubject is one stopped agent. Every non-empty selector field must
// match the calling agent (as Selector.MatchesSubject; gateway_id is never sent
// to a gateway: the list is already the gateway's own). Kind, when set,
// limits the stop to calls of that kind (a model-level containment stops
// model calls only). Ref names why ("containment:<id>", "policy:<id>").
type StoppedSubject struct {
	Selector
	Kind string `json:"kind,omitempty"`
	Ref  string `json:"ref"`
}

// empty reports whether the stop selects nobody in particular. Such an
// entry is never produced and never matches: a stop names an agent.
func (s StoppedSubject) empty() bool {
	return s.IdentityID == "" && s.WorkloadID == "" && s.ClientID == "" && s.AgentLabel == ""
}

// Matches reports whether the stop refuses the request. A request with no
// kind (a gateway refusing a whole connection, e.g. an MCP stream) matches
// a stop of any kind only when the stop has no kind.
func (s StoppedSubject) Matches(r Request) bool {
	if s.empty() {
		return false
	}
	if s.Kind != "" && s.Kind != r.Kind {
		return false
	}
	sel := s.Selector
	sel.GatewayID = ""
	return sel.MatchesSubject(r)
}

// StoppedBy returns the first stop refusing r, or nil.
func StoppedBy(stops []StoppedSubject, r Request) *StoppedSubject {
	for i := range stops {
		if stops[i].Matches(r) {
			return &stops[i]
		}
	}
	return nil
}

func allPattern(s string) bool { return s == "" || strings.Trim(s, "*") == "" }

// blocksEveryTarget reports whether a deny policy refuses every target of
// its kind, always: enabled, no time window, every target pattern "any".
func blocksEveryTarget(p Policy) bool {
	if !p.Enabled || p.Effect != EffectDeny || p.Conditions.TimeWindow != nil {
		return false
	}
	t := p.Target
	return allPattern(t.Server) && allPattern(t.ServerURL) && allPattern(t.Tool) &&
		allPattern(t.Provider) && allPattern(t.Model)
}

// PolicyStops are the stops a gateway gets from deny policies: a deny
// policy that blocks every target of its kind for a named agent (identity,
// workload, client id or label) and applies to gatewayID (no gateway, or
// this one). A deny policy for every agent is not a stop (it is a deny
// target, and the PDP refuses it).
func PolicyStops(policies []Policy, gatewayID string) []StoppedSubject {
	var out []StoppedSubject
	for _, p := range policies {
		if !blocksEveryTarget(p) {
			continue
		}
		if p.Subject.GatewayID != "" && !strings.EqualFold(p.Subject.GatewayID, gatewayID) {
			continue
		}
		s := StoppedSubject{Selector: p.Subject, Kind: p.Kind, Ref: "policy:" + p.ID}
		s.GatewayID = ""
		if s.empty() {
			continue
		}
		out = append(out, s)
	}
	return out
}

// SortStops orders stops deterministically (a stable hints version).
func SortStops(stops []StoppedSubject) {
	key := func(s StoppedSubject) string {
		return strings.Join([]string{s.Ref, s.Kind, s.IdentityID, s.WorkloadID, s.ClientID, s.AgentLabel}, "\x1f")
	}
	sort.Slice(stops, func(i, j int) bool { return key(stops[i]) < key(stops[j]) })
}
