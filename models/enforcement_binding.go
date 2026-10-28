package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Enforcement binding states. The binding follows the lifecycle:
//
//	draft → planned → approved → active → superseded
//
// Each state transition is validated by EnforcementBindingTransitionAllowed.
const (
	BindingStateDraft      = "draft"
	BindingStatePlanned    = "planned"
	BindingStateApproved   = "approved"
	BindingStateActive     = "active"
	BindingStateSuperseded = "superseded"
)

// Identity modes supported by the enforcement binding.
const (
	IdentityModeSPIFFE      = "spiffe"
	IdentityModeEnrolledMTLS = "enrolled_mtls"
)

// ValidBindingStates returns all valid enforcement binding states.
func ValidBindingStates() []string {
	return []string{
		BindingStateDraft,
		BindingStatePlanned,
		BindingStateApproved,
		BindingStateActive,
		BindingStateSuperseded,
	}
}

// ValidIdentityModes returns the allowed identity mode values.
func ValidIdentityModes() []string {
	return []string{IdentityModeSPIFFE, IdentityModeEnrolledMTLS}
}

// EnforcementBindingTransitionAllowed reports whether a state transition
// from → to is valid in the binding lifecycle.
func EnforcementBindingTransitionAllowed(from, to string) bool {
	switch from {
	case BindingStateDraft:
		return to == BindingStatePlanned
	case BindingStatePlanned:
		return to == BindingStateApproved || to == BindingStateDraft
	case BindingStateApproved:
		return to == BindingStateActive || to == BindingStateDraft
	case BindingStateActive:
		return to == BindingStateSuperseded || to == BindingStateDraft
	case BindingStateSuperseded:
		return false
	}
	return false
}

// EnforcementBinding links a discovered agent to an enforcement backend,
// identity mode, and contributing policies. Resolution order:
//
//  1. Approved agent-specific binding
//  2. Policy default from contributing policies
//  3. Workspace default
//
// Conflicts arise when contributing policies disagree on backend selection.
type EnforcementBinding struct {
	ID                       uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID              uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null;index"`
	AgentID                  uuid.UUID      `json:"agent_id" gorm:"type:uuid;not null"`
	WorkloadID               *uuid.UUID     `json:"workload_id,omitempty" gorm:"type:uuid"`
	BindingRevision          int            `json:"binding_revision" gorm:"not null;default:1"`
	PolicyRefs               pq.StringArray `json:"policy_refs" gorm:"type:text[];not null"`
	Backend                  string         `json:"backend" gorm:"type:text;not null"` // authsec, openshell
	BackendProfile           string         `json:"backend_profile" gorm:"type:text;not null"`
	IdentityMode             string         `json:"identity_mode" gorm:"type:text;not null"` // spiffe, enrolled_mtls
	IdentityBindingID        *uuid.UUID     `json:"identity_binding_id,omitempty" gorm:"type:uuid"`
	TargetExecutionSelector  string         `json:"target_execution_selector,omitempty" gorm:"type:text"`
	CapabilityDigest         string         `json:"capability_digest,omitempty" gorm:"type:text"`
	PlanHash                 string         `json:"plan_hash,omitempty" gorm:"type:text"`
	State                    string         `json:"state" gorm:"type:text;not null;default:'draft'"`
	PlanJobID                *uuid.UUID     `json:"plan_job_id,omitempty" gorm:"type:uuid"`
	Blockers                 pq.StringArray `json:"blockers,omitempty" gorm:"type:text[]"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

func (EnforcementBinding) TableName() string { return "enforcement_bindings" }

// BindingConflict records a disagreement between contributing policies on
// enforcement backend or profile selection for an agent.
type BindingConflict struct {
	AgentID    uuid.UUID `json:"agent_id"`
	PolicyIDs  []string  `json:"policy_ids"`
	Field      string    `json:"field"`    // "backend", "profile", "identity_mode"
	Values     []string  `json:"values"`   // conflicting values
	Resolution string    `json:"resolution"` // "workspace_default", "manual", "unresolved"
}

// BindingResolution describes how a binding was resolved for an agent.
type BindingResolution struct {
	Source          string     `json:"source"` // "agent_binding", "policy_default", "workspace_default"
	BindingID       *uuid.UUID `json:"binding_id,omitempty"`
	Backend         string     `json:"backend"`
	BackendProfile  string     `json:"backend_profile"`
	IdentityMode    string     `json:"identity_mode"`
	ContributingPolicies []string `json:"contributing_policies,omitempty"`
	Conflicts       []BindingConflict `json:"conflicts,omitempty"`
}
