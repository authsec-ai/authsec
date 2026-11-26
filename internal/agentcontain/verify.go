package agentcontain

import (
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsbroker"
)

// Behavioural verification (spec §5.8 "Verification (2)"): after a
// containment's changes are read back, AuthSec watches the identity's
// CloudTrail events (the poller and the event stream both hand them to the
// agent_contain_verify sink).
//
//   - A SUCCESSFUL call by the contained identity after contained_at +
//     VerifyGrace marks the containment not effective, with the events (Late).
//   - The containment is verified (verified_at) only by PROOF: a call by the
//     contained identity after the same cutoff that AWS REFUSED
//     (AuthorizationDenied) with an error message naming this containment's
//     own AuthSec policy (Proof). The proving event is recorded. A later
//     successful call still flips a verified containment to not effective.
//   - Silence is never proof: no late call can mean the identity is idle or
//     that CloudTrail delivery is late or broken. Without proof the
//     containment stays undecided and, after VerifyGiveUp, is recorded as
//     unverifiable (Pending); a proof that arrives later still verifies it.
//   - A containment no refusal can prove (Unverifiable: the workload level,
//     which attaches no policy) is recorded as unverifiable at the cutoff.
//
// Calls a deny cannot block (DenyImmune) are not evidence of failure.
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

// VerifyGiveUp is how long after containment AuthSec waits for a proving
// refusal (Proof) before it records the containment as unverifiable.
const VerifyGiveUp = 24 * time.Hour

// CutOff is the time after which a successful call counts against the
// containment and a refused call can prove it: contained_at plus the
// delivery, propagation and clock-skew allowance (VerifyGrace).
func (c Contained) CutOff() time.Time { return c.ContainedAt.Add(VerifyGrace) }

// Unverifiable reports a containment whose effect no event can prove. The
// workload level attaches no AuthSec policy (it sets Lambda concurrency and
// ECS desired counts to zero), so AWS never refuses a call naming one: only a
// successful late call (not effective) can be seen. On a shared role with ECS
// services it cannot even be refuted (an ECS task's role session name is not
// the service's, DECISION P3-6).
func (c Contained) Unverifiable() (bool, string) {
	switch c.Level {
	case LevelKey:
		return true, "A deactivated access key fails authentication (InvalidClientTokenId) before any policy is evaluated, and CloudTrail does not reliably record such a call against the user, so no refusal can prove the stop. Read-back of the key's status is the evidence; a successful call signed with the key still marks it not effective."
	case LevelEntra:
		return true, "Entra sign-in refusals are not ingested, so no event can prove the service principal is disabled. Read-back of accountEnabled and of the removed role assignments is the evidence, and every token issued before the stop has expired (token_expiry_at)."
	case LevelKubernetes:
		return true, "Kubernetes audit events are not ingested, so no refused request can prove the ServiceAccount lost its bindings. The cluster agent's report and the RBAC sweeps are the evidence."
	case LevelGateway:
		return true, "A gateway stop is enforced by the customer's gateway from AuthSec's deny list; its decision log is not yet read as proof."
	case LevelPlatform:
		return true, "A platform stop is asked of whoever can act on the platform; AuthSec cannot observe it."
	}
	if c.Level == LevelWorkload && !c.Dedicated && len(c.SessionNames) == 0 {
		return true, "The contained workloads (ECS services) share the role with other workloads and their CloudTrail sessions cannot be told apart, so no event can confirm or refute the containment. Read-back of each change is the only evidence."
	}
	if c.Level == LevelWorkload {
		return true, "Workload containment changes no IAM policy, so AWS never refuses a call in its name and no CloudTrail event can prove it works. Read-back of each change is the evidence; a successful call by a contained workload still marks it not effective."
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
	// Target is the access key id (key) or agent reference (source_identity).
	Target string
	// Assumers are the chain level's denied assumers (ARN and unique id).
	Assumers []Assumer
	// TokenExpiry is token_expiry_at: an Entra stop is not judged before it.
	TokenExpiry *time.Time
}

// matchesAssumer reports whether the event is a call by one of the chain
// stop's denied assumers.
func (c Contained) matchesAssumer(e agentruntime.Event) bool {
	a := e.Attribution()
	if a.ARN == "" {
		return false
	}
	for _, x := range c.Assumers {
		if strings.EqualFold(x.ARN, a.ARN) && (x.UniqueID == "" || a.UniqueID == "" || x.UniqueID == a.UniqueID) {
			return true
		}
	}
	return false
}

// agentSession reports whether the event is a session the broker opened for
// the source_identity stop's agent.
func (c Contained) agentSession(e agentruntime.Event) bool {
	if c.Target == "" || e.SourceIdentity == "" {
		return false
	}
	ok, _ := pathMatch(awsbroker.AgentSourcePattern(c.Target), e.SourceIdentity)
	return ok
}

// pathMatch is IAM StringLike for one '*' wildcard pattern.
func pathMatch(pattern, s string) (bool, error) {
	i := strings.Index(pattern, "*")
	if i < 0 {
		return pattern == s, nil
	}
	pre, suf := pattern[:i], pattern[i+1:]
	return len(s) >= len(pre)+len(suf) && strings.HasPrefix(s, pre) && strings.HasSuffix(s, suf), nil
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
		if !e.EventTime.After(cut) || DenyImmune(e) {
			continue
		}
		if c.Level == LevelChain {
			// An assumer still assuming the role.
			if c.matchesAssumer(e) && strings.EqualFold(e.EventSource, "sts.amazonaws.com") && e.EventName == "AssumeRole" &&
				strings.EqualFold(e.RequestFacts[agentruntime.FactRoleARN], c.IdentityARN) {
				out = append(out, LateEvent{EventID: e.EventID, EventTime: e.EventTime, EventSource: e.EventSource,
					EventName: e.EventName, SessionName: e.SessionName, Region: e.Region})
				continue
			}
		}
		if !c.MatchesIdentity(e) {
			continue
		}
		weak := false
		switch c.Level {
		case LevelKey:
			if c.Target == "" || e.AccessKeyID != c.Target {
				continue
			}
		case LevelSessionsBefore, LevelChain:
			// A session issued before the stop still working.
			if e.SessionCreatedAt == nil || !e.SessionCreatedAt.Before(c.ContainedAt) {
				continue
			}
		case LevelSourceIdentity:
			if !c.agentSession(e) {
				continue
			}
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

// ProofPolicyNames are the AuthSec policies of the containment whose name in
// a refusal proves it: the deny policy (identity and model level) and, at the
// identity level, the session revocation. None for the workload level.
func (c Contained) ProofPolicyNames() []string {
	if c.UniqueID == "" || c.ID == uuid.Nil {
		return nil
	}
	switch c.Level {
	case LevelIdentity:
		return []string{ContainPolicyName(c.UniqueID, c.ID), RevokePolicyName(c.UniqueID, c.ID)}
	case LevelModel, LevelSourceIdentity:
		return []string{ContainPolicyName(c.UniqueID, c.ID)}
	case LevelSessionsBefore:
		return []string{RevokePolicyName(c.UniqueID, c.ID)}
	case LevelChain:
		out := []string{RevokePolicyName(c.UniqueID, c.ID)}
		for _, a := range c.Assumers {
			if a.UniqueID != "" {
				out = append(out, ChainPolicyName(a.UniqueID, c.ID))
			}
		}
		return out
	}
	return nil
}

// ProofEvent is the refused call that proves a containment works.
type ProofEvent struct {
	EventID     string    `json:"event_id"`
	EventTime   time.Time `json:"event_time"`
	EventSource string    `json:"event_source"`
	EventName   string    `json:"event_name"`
	ErrorCode   string    `json:"error_code"`
	Policy      string    `json:"policy"`
	SessionName string    `json:"session_name,omitempty"`
	Region      string    `json:"region,omitempty"`
}

// namesPolicy reports whether msg names the policy as an ARN's last path
// element (".../policy/authsec/<name>"), not as a prefix of a longer name.
func namesPolicy(msg, name string) bool {
	needle := "/" + name
	for i := 0; i < len(msg); {
		k := strings.Index(msg[i:], needle)
		if k < 0 {
			return false
		}
		end := i + k + len(needle)
		if end == len(msg) || !policyNameChar(msg[end]) {
			return true
		}
		i += k + 1
	}
	return false
}

// policyNameChar: IAM policy names are [\w+=,.@-].
func policyNameChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("_+=,.@-", b) >= 0
}

// Proof returns the earliest event that proves the containment works: an API
// call attributed to the contained identity, after CutOff, that AWS refused
// with an authorization error (AuthorizationDenied: AccessDenied,
// AccessDeniedException, UnauthorizedOperation) whose message names one of
// the containment's own policies (ProofPolicyNames). At the model level the
// call must be one the containment denies (a model call or an AgentCore
// invoke). A refusal by any other policy, or one whose message names no
// policy, proves nothing about this containment. nil when none.
func Proof(c Contained, events []agentruntime.Event) *ProofEvent {
	names := c.ProofPolicyNames()
	if len(names) == 0 {
		return nil
	}
	cut := c.CutOff()
	var best *ProofEvent
	for _, e := range events {
		if !e.IsAPICall() || !e.AuthorizationDenied || e.ErrorMessage == "" {
			continue
		}
		if !e.EventTime.After(cut) {
			continue
		}
		if !c.MatchesIdentity(e) && !(c.Level == LevelChain && c.matchesAssumer(e)) {
			continue
		}
		if c.Level == LevelModel && !e.IsModelCall() && e.EventSource != agentruntime.SourceAgentCore {
			continue
		}
		if c.Level == LevelSourceIdentity && !c.agentSession(e) {
			continue
		}
		policy := ""
		for _, n := range names {
			if namesPolicy(e.ErrorMessage, n) {
				policy = n
				break
			}
		}
		if policy == "" {
			continue
		}
		p := ProofEvent{EventID: e.EventID, EventTime: e.EventTime, EventSource: e.EventSource, EventName: e.EventName,
			ErrorCode: e.ErrorCode, Policy: policy, SessionName: e.SessionName, Region: e.Region}
		if best == nil || p.EventTime.Before(best.EventTime) || (p.EventTime.Equal(best.EventTime) && p.EventID < best.EventID) {
			best = &p
		}
	}
	return best
}

// Pending decisions: the clock's verdict on a containment no event has
// proven or refuted yet.
const (
	PendingWait         = "wait"         // keep waiting for a proving refusal
	PendingUnverifiable = "unverifiable" // record it as unverifiable
)

// Pending is what the clock alone decides for a containment without proof:
// nothing before CutOff; unverifiable for good (final) when no refusal can
// prove it (Unverifiable); otherwise wait until contained_at + VerifyGiveUp,
// then unverifiable, which a later proof still turns into verified. The
// clock never verifies.
func Pending(c Contained, now time.Time) (decision string, final bool, why string) {
	if !now.After(c.CutOff()) {
		return PendingWait, false, ""
	}
	if c.Level == LevelEntra && c.TokenExpiry != nil && now.Before(*c.TokenExpiry) {
		// Tokens issued before the stop may still be used: not judged yet.
		return PendingWait, false, ""
	}
	if bad, reason := c.Unverifiable(); bad {
		return PendingUnverifiable, true, reason
	}
	if now.Before(c.ContainedAt.Add(VerifyGiveUp)) {
		return PendingWait, false, ""
	}
	return PendingUnverifiable, false, ""
}

// ProbeProves is the policy of the containment an active probe's refusal
// message names ("" when none): the same naming rule as Proof.
func ProbeProves(c Contained, msg string) string {
	for _, n := range c.ProofPolicyNames() {
		if namesPolicy(msg, n) {
			return n
		}
	}
	return ""
}
