package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/google/uuid"
)

// What an in-cluster agent reports it is doing with the plan it holds.
//
// These are OBSERVATIONS reported by the agent, never settings pushed to it: the
// control plane originates no connection into a customer cluster (EN-0), so the
// only honest thing to store is what the cluster said about itself.
const (
	// EnforcementModeUnreported is the zero value: no agent has ever reported.
	// Distinct from observe, which is a live agent deliberately enforcing nothing.
	EnforcementModeUnreported = ""
	// EnforcementModeObserve counts what it WOULD have denied and allows everything.
	// The default and the only mode any agent ships with today (EN-10).
	EnforcementModeObserve = "observe"
	// EnforcementModeEvict evicts pods of quarantined agents but denies nothing.
	// Phase 5.
	EnforcementModeEvict = "evict"
	// EnforcementModeDeny refuses pod creation at admission. Phase 6.
	EnforcementModeDeny = "deny"
)

// ValidEnforcementModes returns the modes an agent may report.
func ValidEnforcementModes() []string {
	return []string{
		EnforcementModeUnreported, EnforcementModeObserve,
		EnforcementModeEvict, EnforcementModeDeny,
	}
}

// EnforcementPlan is one published version of the document an in-cluster agent
// polls.
//
// A row per VERSION, not per poll. A poll that finds the plan unchanged mints no
// row -- version is bumped by content, so a changed version always means something
// a human decided actually changed.
type EnforcementPlan struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	// DiscoverySourceID scopes the plan to one cluster, which is what stops a
	// leaked actuation token from reading another cluster's decisions.
	DiscoverySourceID uuid.UUID `json:"discovery_source_id" gorm:"type:uuid;not null"`
	// Version is monotonic per connector. The agent reports the version it is
	// enforcing; the difference between that and this is the enforcement gap.
	Version int64 `json:"version" gorm:"not null"`
	// Plan is the document that was served. Stored rather than regenerated,
	// because "what were we enforcing at the time" is not answerable from state
	// that has since changed.
	//
	// jsonb, so a stored plan is QUERYABLE -- "which clusters were ever told to
	// contain this fingerprint" is one index scan rather than a decode of every
	// row. The cost is that jsonb normalises key order and whitespace, so these
	// are not the same BYTES that were marshalled. They are the same document,
	// which is all the agent and the audit trail need.
	Plan        json.RawMessage `json:"plan" gorm:"type:jsonb;not null;default:'{}'"`
	ContentHash string          `json:"content_hash" gorm:"not null;default:''"`
	GeneratedAt time.Time       `json:"generated_at" gorm:"not null;default:now()"`
	CreatedAt   time.Time       `json:"created_at"`
}

func (EnforcementPlan) TableName() string { return "enforcement_plans" }

// EnforcementPlanDoc is the JSON document the agent receives.
//
// This shape is a CONTRACT with every deployed agent, which upgrades on the
// customer's schedule and not ours. Fields may be added; none may change meaning.
type EnforcementPlanDoc struct {
	Version     int64     `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Cluster     string    `json:"cluster"`
	// Deny is an explicit fingerprint list, never a predicate (EN-3). A detection
	// bug can lengthen this list; it can never widen what the agent evaluates,
	// and every entry corresponds to a decision a human made.
	Deny []EnforcementPlanEntry `json:"deny"`
}

// EnforcementPlanEntry is one contained agent.
//
// The workload coordinates are redundant with the fingerprint, which already
// encodes them -- they are here so a cluster operator reading the plan can tell
// what it refers to without a lookup in the console. The agent matches on
// Fingerprint alone.
type EnforcementPlanEntry struct {
	Fingerprint  string `json:"fingerprint"`
	Namespace    string `json:"namespace,omitempty"`
	WorkloadKind string `json:"workload_kind,omitempty"`
	WorkloadName string `json:"workload_name,omitempty"`
	Container    string `json:"container,omitempty"`
	// PolicyID is set when a policy asked for this; empty when an operator
	// quarantined the agent directly. Both are decisions; only one has a policy.
	PolicyID string `json:"policy_id,omitempty"`
	// DecisionID is the discovered_agents row, and is what an operator pastes into
	// the console to find the decision behind a blocked pod.
	DecisionID string `json:"decision_id"`
	// Reason is surfaced verbatim to whoever hits the block. It names the
	// governance decision, never the mechanism (EN-8).
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since"`
}

// PlanDocFormat versions the SHAPE of the document, as opposed to its contents.
//
// It is mixed into the hash so that changing the document -- adding a field,
// changing what one means -- republishes every cluster's plan on its next poll.
// Without it a shape change would not alter the deny list, no version would be
// minted, and clusters would keep being served the OLD document indefinitely: a
// field added for a reason would simply never arrive anywhere until something
// unrelated happened to be quarantined.
//
// Bump this whenever EnforcementPlanDoc or EnforcementPlanEntry changes.
const PlanDocFormat = "v1"

// Hash is a content digest over the deny list and the document format.
//
// Version and GeneratedAt are excluded ON PURPOSE: including them would make every
// plan differ from the last, which is exactly the comparison this exists to make.
// Entries are sorted first so that two plans with the same contents in a different
// row order hash identically -- otherwise a query plan change would look like a
// governance change and bump the version the whole fleet re-fetches on.
func (d *EnforcementPlanDoc) Hash() string {
	entries := make([]EnforcementPlanEntry, len(d.Deny))
	copy(entries, d.Deny)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
	h := sha256.New()
	_, _ = h.Write([]byte(PlanDocFormat))
	_, _ = h.Write([]byte{0})
	for i := range entries {
		e := &entries[i]
		// Field-separated so that ("ab","c") and ("a","bc") cannot collide.
		for _, part := range []string{
			e.Fingerprint, e.Namespace, e.WorkloadKind, e.WorkloadName,
			e.Container, e.PolicyID, e.DecisionID, e.Reason,
		} {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EnforcementReport is what an agent says about itself when it fetches a plan.
//
// It arrives ON the fetch rather than on a separate call: one authenticated round
// trip both reports and refreshes, so "what version is this cluster enforcing" is
// exactly as fresh as "when did it last poll", and neither fact can exist without
// the other.
type EnforcementReport struct {
	// Mode is what the agent says it is running. Refused if not in
	// ValidEnforcementModes.
	Mode string
	// Version is the plan version in force in the cluster BEFORE this fetch --
	// which is the correct thing to compare against, because the fetch is what
	// closes the gap.
	Version *int64
	// DenialsTotal is cumulative since the agent process started, so it resets on
	// restart. A rate and a liveness signal, never an all-time total.
	DenialsTotal *int64
}
