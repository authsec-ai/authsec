package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

// PolicyContext is a prepared policy context document used by BG05 (Policy
// Context Preparation). Each row captures the canonical target, base policy
// IDs/revisions, proposed rule, evidence refs, capability requirements,
// unsupported reasons and projected impact. Contexts expire after 30 minutes
// and are cleaned up by the expiry worker.
type PolicyContext struct {
	ID                 uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID        uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null"`
	ActorUserID        uuid.UUID      `json:"actor_user_id" gorm:"type:uuid;not null"`
	SourceKind         string         `json:"source_kind" gorm:"type:text;not null"`
	RootWorkloadID     *uuid.UUID     `json:"root_workload_id,omitempty" gorm:"type:uuid"`
	GraphRevision      *int64         `json:"graph_revision,omitempty" gorm:"type:int8"`
	SelectedRef        string         `json:"selected_ref,omitempty" gorm:"type:text"`
	ActionID           *uuid.UUID     `json:"action_id,omitempty" gorm:"type:uuid"`
	RequestedEffect    string         `json:"requested_effect" gorm:"type:text;not null;default:'deny'"`
	SelectedOperations pq.StringArray `json:"selected_operations,omitempty" gorm:"type:text[]"`
	ContextDocument    datatypes.JSON `json:"context_document" gorm:"type:jsonb;not null"`
	SourceHash         string         `json:"source_hash" gorm:"type:text;not null"`
	ExpiresAt          time.Time      `json:"expires_at" gorm:"not null"`
	CreatedAt          time.Time      `json:"created_at"`
}

func (PolicyContext) TableName() string { return "iga_policy_contexts" }

// PolicyContextDocument is the JSONB payload stored in context_document. It
// holds everything the policy editor needs to present the context and build
// a draft rule.
type PolicyContextDocument struct {
	CanonicalTarget    map[string]any `json:"canonical_target"`
	BasePolicies       []BasePolicyRef `json:"base_policies"`
	ProposedRule       map[string]any `json:"proposed_rule,omitempty"`
	EvidenceRefs       []string       `json:"evidence_refs,omitempty"`
	CapabilityReqs     []string       `json:"capability_reqs,omitempty"`
	UnsupportedReasons []string       `json:"unsupported_reasons,omitempty"`
	Impact             map[string]any `json:"impact,omitempty"`
}

// BasePolicyRef identifies a base policy and its revision used in context
// preparation.
type BasePolicyRef struct {
	PolicyID uuid.UUID `json:"policy_id"`
	Revision int       `json:"revision"`
}

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

// PolicyContextRequest is what the UI sends to prepare a policy context.
type PolicyContextRequest struct {
	SourceKind         string     `json:"source_kind" binding:"required"`
	RootWorkloadID     *uuid.UUID `json:"root_workload_id,omitempty"`
	GraphRevision      *int64     `json:"graph_revision,omitempty"`
	SelectedRef        string     `json:"selected_ref,omitempty"`
	ActionID           *uuid.UUID `json:"action_id,omitempty"`
	RequestedEffect    string     `json:"requested_effect,omitempty"`
	SelectedOperations []string   `json:"selected_operations,omitempty"`
}

// PolicyContextResponse is what the API returns after preparing or retrieving
// a policy context.
type PolicyContextResponse struct {
	ID                 uuid.UUID          `json:"id"`
	WorkspaceID        uuid.UUID          `json:"workspace_id"`
	ActorUserID        uuid.UUID          `json:"actor_user_id"`
	SourceKind         string             `json:"source_kind"`
	RootWorkloadID     *uuid.UUID         `json:"root_workload_id,omitempty"`
	GraphRevision      *int64             `json:"graph_revision,omitempty"`
	SelectedRef        string             `json:"selected_ref,omitempty"`
	ActionID           *uuid.UUID         `json:"action_id,omitempty"`
	RequestedEffect    string             `json:"requested_effect"`
	SelectedOperations []string           `json:"selected_operations,omitempty"`
	ContextDocument    PolicyContextDocument `json:"context_document"`
	SourceHash         string             `json:"source_hash"`
	ExpiresAt          time.Time          `json:"expires_at"`
	CreatedAt          time.Time          `json:"created_at"`
}

// Valid source kinds for PolicyContextRequest.SourceKind.
const (
	PolicyContextSourceGraph  = "graph"
	PolicyContextSourceAction = "action"
)

// ValidPolicyContextSourceKinds returns the allowed source_kind values.
func ValidPolicyContextSourceKinds() []string {
	return []string{PolicyContextSourceGraph, PolicyContextSourceAction}
}
