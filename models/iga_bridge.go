package models

import (
	"time"

	"github.com/google/uuid"
)

// Link states for a discovered-agent -> iga_agents correlation.
//
// Deliberately the same vocabulary as iga_correlations, minus 'split': a k8s
// workload is one logical agent or none, so there is nothing to split.
const (
	IGALinkProposed = "proposed"
	IGALinkAccepted = "accepted"
	IGALinkRejected = "rejected"
)

// Correlation strength. Only a shared identifier earns 'strong'; anything
// inferred is 'weak' and cannot be accepted without a human decision.
const (
	IGALinkStrong = "strong"
	IGALinkWeak   = "weak"
)

// ValidIGALinkDecisions returns the decisions a reviewer may record. Note that
// 'proposed' is the initial state, not a decision someone can make.
func ValidIGALinkDecisions() []string {
	return []string{IGALinkAccepted, IGALinkRejected}
}

// DiscoveredAgentIGALink is the claim that a workload observed running in a
// cluster and a canonical agent in the correlated estate are the same thing.
//
// It is a claim, not a fact, which is why it carries its own state, its evidence
// (JoinKey/Strength) and its decision record rather than being a column on
// either side. The two models it joins are populated by different channels with
// no shared identifier, so an automatic proposal is the most that can be
// honestly asserted.
type DiscoveredAgentIGALink struct {
	ID                uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	DiscoveredAgentID uuid.UUID `json:"discovered_agent_id" gorm:"type:uuid;not null"`
	IGAAgentID        uuid.UUID `json:"iga_agent_id" gorm:"type:uuid;not null"`

	// JoinKey is why this was proposed, in a form a reviewer can evaluate —
	// e.g. "display_name:research-agent". An unexplained proposal is one a
	// reviewer can only rubber-stamp.
	JoinKey  string `json:"join_key" gorm:"not null;default:''"`
	Strength string `json:"strength" gorm:"not null;default:'weak'"`

	State     string     `json:"state" gorm:"not null;default:'proposed'"`
	DecidedBy *uuid.UUID `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`

	// Version guards the decision, matching the iga_* decision routes: a stale
	// decision is rejected rather than last-write-wins.
	Version int64 `json:"version" gorm:"not null;default:1"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Decided reports whether a human has ruled on this link. Computed, so a
	// caller never has to know that 'proposed' is the only undecided state.
	Decided bool `json:"decided" gorm:"-"`
}

func (DiscoveredAgentIGALink) TableName() string { return "discovered_agent_iga_links" }
