package agentcontain

import (
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// Behavioural verification (spec §5.8 "Verification (2)"): after a
// containment's changes are read back, AuthSec watches the identity's
// CloudTrail events (the poller and the event stream both hand them to the
// agent_contain_verify sink). A SUCCESSFUL call by the contained identity
// after contained_at + VerifyGrace marks the containment not effective, with
// the events. "None seen" means something only when CloudTrail evidence
// covers the time after contained_at + VerifyGrace (the event stream's newest
// event time, or the poller's read cursor, has passed it): then the
// containment is verified (verified_at) -- provisionally: an event delivered
// later still flips it to not effective. With no such evidence it stays
// undecided and, after VerifyGiveUp, is recorded as unverifiable. A
// containment no event can be attributed to (Unverifiable) is never verified.
// Calls a deny cannot block (DenyImmune) are not evidence.
//
// DECISION P3-6 (what counts, per level):
//   - identity: any successful API call attributed to the identity;
//   - model: a successful model call (agentruntime.Event.IsModelCall) or an
//     AgentCore invoke;
//   - workload, when every workload on the identity is contained: as identity;
//   - workload on a shared role: only calls whose role session name is a
//     contained Lambda function's name (Lambda's session name is the function
//     name: UNVERIFIED, spec §10 §5.2 change), recorded as weak evidence.
//     ECS task sessions are not matched (their session name is not known).

// VerifyGrace is CloudTrail's delivery delay plus IAM propagation.
const VerifyGrace = 5 * time.Minute

// VerifyGiveUp is how long after containment AuthSec waits for CloudTrail
// events covering the grace period before it records the containment as
// unverifiable (no events were received since it) instead of verified.
const VerifyGiveUp = 24 * time.Hour

// CutOff is the time after which a successful call counts against the
// containment, and the time CloudTrail evidence must cover before "no late
// call" means anything.
func (c Contained) CutOff() time.Time { return c.ContainedAt.Add(VerifyGrace) }

// Unverifiable reports a containment whose effect no event can show: a
// workload containment of ECS services on a role shared with other
// workloads. An ECS task's role session name is not the service's (DECISION
// P3-6), so no CloudTrail event can be attributed to the contained services;
// absence of late calls would prove nothing.
func (c Contained) Unverifiable() (bool, string) {
	if c.Level == LevelWorkload && !c.Dedicated && len(c.SessionNames) == 0 {
		return true, "The contained workloads (ECS services) share the role with other workloads and their CloudTrail sessions cannot be told apart, so no event can confirm or refute the containment. Read-back of each change is the only evidence."
	}
	return false, ""
}

// DenyImmune reports a call an explicit deny cannot block: it succeeds under
// the deny-all policy and is no evidence the containment failed.
// sts:GetCallerIdentity needs no permission; a call made by an AWS service
// on the identity's behalf (userIdentity.invokedBy) is made with the
// service's own authority, not by the contained identity's permissions.
func DenyImmune(e agentruntime.Event) bool {
	if e.InvokedBy != "" {
		return true
	}
	return strings.EqualFold(e.EventSource, "sts.amazonaws.com") && e.EventName == "GetCallerIdentity"
}

// Contained is one live containment as the verifier sees it.
type Contained struct {
	ID          uuid.UUID
	Level       string
	IdentityARN string
	UniqueID    string
	ContainedAt time.Time
	// Dedicated: every workload on the identity is contained (workload level).
	Dedicated bool
	// SessionNames are the contained Lambda functions' names (workload level).
	SessionNames []string
}

// LateEvent is a successful call after the grace: evidence the containment
// is not effective.
type LateEvent struct {
	EventID     string    `json:"event_id"`
	EventTime   time.Time `json:"event_time"`
	EventSource string    `json:"event_source"`
	EventName   string    `json:"event_name"`
	SessionName string    `json:"session_name,omitempty"`
	Region      string    `json:"region,omitempty"`
	// Weak: matched by session name only (workload level on a shared role).
	Weak bool `json:"weak,omitempty"`
}

// MatchesIdentity reports whether the event is attributed to the identity.
func (c Contained) MatchesIdentity(e agentruntime.Event) bool {
	a := e.Attribution()
	if a.How == "" || a.ARN == "" {
		return false
	}
	if !strings.EqualFold(a.ARN, c.IdentityARN) {
		return false
	}
	// A recreated identity has the same ARN and another unique id.
	if c.UniqueID != "" && a.UniqueID != "" && a.UniqueID != c.UniqueID {
		return false
	}
	return true
}

// Late returns the events that show the containment is not effective,
// sorted by time.
func Late(c Contained, events []agentruntime.Event) []LateEvent {
	cut := c.CutOff()
	names := map[string]bool{}
	for _, n := range c.SessionNames {
		names[n] = true
	}
	var out []LateEvent
	for _, e := range events {
		if !e.IsAPICall() || e.ErrorCode != "" || e.AuthorizationDenied {
			continue
		}
		if !e.EventTime.After(cut) || DenyImmune(e) || !c.MatchesIdentity(e) {
			continue
		}
		weak := false
		switch c.Level {
		case LevelIdentity:
		case LevelModel:
			if !e.IsModelCall() && e.EventSource != agentruntime.SourceAgentCore {
				continue
			}
		case LevelWorkload:
			if !c.Dedicated {
				if e.SessionName == "" || !names[e.SessionName] {
					continue
				}
				weak = true
			}
		default:
			continue
		}
		out = append(out, LateEvent{EventID: e.EventID, EventTime: e.EventTime, EventSource: e.EventSource,
			EventName: e.EventName, SessionName: e.SessionName, Region: e.Region, Weak: weak})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].EventTime.Equal(out[j].EventTime) {
			return out[i].EventTime.Before(out[j].EventTime)
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}

// MaxLateEvents caps the refs kept on a containment.
const MaxLateEvents = 50

// MergeLate adds new late events to the recorded ones, unique by event id
// (the poller and the stream deliver the same event), capped.
func MergeLate(have, add []LateEvent) ([]LateEvent, bool) {
	seen := map[string]bool{}
	for _, e := range have {
		seen[e.EventID] = true
	}
	changed := false
	out := append([]LateEvent{}, have...)
	for _, e := range add {
		if seen[e.EventID] || len(out) >= MaxLateEvents {
			continue
		}
		seen[e.EventID] = true
		out = append(out, e)
		changed = true
	}
	return out, changed
}
