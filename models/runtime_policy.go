package models

import (
	"time"

	"github.com/google/uuid"
)

// Runtime policy lifecycle. The allowed edges live in
// services.RuntimePolicyTransitionAllowed. A6 moves a revision through
// draft, validated and approved. simulated is set by the later simulator.
// published, superseded and revoked are delivery states.
const (
	RuntimePolicyStateDraft      = "draft"
	RuntimePolicyStateValidated  = "validated"
	RuntimePolicyStateSimulated  = "simulated"
	RuntimePolicyStateApproved   = "approved"
	RuntimePolicyStatePublished  = "published"
	RuntimePolicyStateSuperseded = "superseded"
	RuntimePolicyStateRevoked    = "revoked"

	RuntimePolicyFormatV1 = "authsec.runtime.v1"

	// RuntimePolicyActorCandidateSystem is the actor kind of the account that
	// generates candidates. That account cannot approve or enforce.
	RuntimePolicyActorCandidateSystem = "candidate_system"
)

// RuntimePolicyCandidateSystemUserID is the well-known actor id for candidate
// generation. It is not a users row. Tokens that present this id, or the
// actor kind above, are refused on approve and enforce.
var RuntimePolicyCandidateSystemUserID = uuid.MustParse("00000000-0000-4000-8000-00000000c415")

// RuntimePolicyStates is every lifecycle state, in declaration order.
func RuntimePolicyStates() []string {
	return []string{
		RuntimePolicyStateDraft,
		RuntimePolicyStateValidated,
		RuntimePolicyStateSimulated,
		RuntimePolicyStateApproved,
		RuntimePolicyStatePublished,
		RuntimePolicyStateSuperseded,
		RuntimePolicyStateRevoked,
	}
}

// IsRuntimePolicyCandidateSystem reports whether this actor generates
// candidates. Either the well-known id or the actor kind is enough.
func IsRuntimePolicyCandidateSystem(userID uuid.UUID, actorKind string) bool {
	return userID == RuntimePolicyCandidateSystemUserID || actorKind == RuntimePolicyActorCandidateSystem
}

// RuntimePolicy is the stable policy identity. CurrentDraftRevision is the
// revision a draft edit or approval must name. Lifecycle mirrors that revision.
type RuntimePolicy struct {
	ID                   uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID          uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	Name                 string    `json:"name" gorm:"not null"`
	OwnerUserID          uuid.UUID `json:"owner_user_id" gorm:"type:uuid;not null"`
	CurrentDraftRevision int       `json:"current_draft_revision" gorm:"not null"`
	Lifecycle            string    `json:"lifecycle" gorm:"not null"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func (RuntimePolicy) TableName() string { return "runtime_policies" }

// RuntimePolicyRevision is one immutable document. Past draft, document and
// content_hash cannot change, and the row cannot be deleted.
type RuntimePolicyRevision struct {
	ID             uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID    uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID       uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`
	Revision       int       `json:"revision" gorm:"not null"`
	Document       []byte    `json:"document" gorm:"type:jsonb;not null"`
	ContentHash    string    `json:"content_hash" gorm:"not null"`
	AuthorUserID   uuid.UUID `json:"author_user_id" gorm:"type:uuid;not null"`
	State          string    `json:"state" gorm:"not null"`
	GraphRevision  int64     `json:"graph_revision" gorm:"not null"`
	CompilerFormat string    `json:"compiler_format" gorm:"not null"`
	CreatedAt      time.Time `json:"created_at"`
}

func (RuntimePolicyRevision) TableName() string { return "runtime_policy_revisions" }
