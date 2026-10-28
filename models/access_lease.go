package models

import (
	"time"

	"github.com/lib/pq"
)

// Governance access-request states. A request moves through pending ->
// approved/denied/cancelled/expired. Only an approved request produces a lease.
//
// These are prefixed with GovRequest to avoid collision with the XAA AccessRequest
// status constants in xaa.go, which serve a different flow (cross-app authorization).
const (
	GovRequestPending   = "pending"
	GovRequestApproved  = "approved"
	GovRequestDenied    = "denied"
	GovRequestCancelled = "cancelled"
	GovRequestExpired   = "expired"
)

// Access lease states. A lease is the materialised grant produced by an approved request.
//
// issued   -- created but not yet within its validity window (not_before is in the future).
// active   -- within its validity window and not yet fully consumed or revoked.
// consumed -- max_uses reached; the lease can no longer be redeemed.
// expired  -- expires_at has passed without revocation.
// revoked  -- explicitly revoked by an administrator or policy action.
const (
	LeaseStateIssued   = "issued"
	LeaseStateActive   = "active"
	LeaseStateConsumed = "consumed"
	LeaseStateExpired  = "expired"
	LeaseStateRevoked  = "revoked"
)

// ValidGovRequestStates returns the allowed governance access-request states.
func ValidGovRequestStates() []string {
	return []string{GovRequestPending, GovRequestApproved, GovRequestDenied,
		GovRequestCancelled, GovRequestExpired}
}

// ValidLeaseStates returns the allowed lease states.
func ValidLeaseStates() []string {
	return []string{LeaseStateIssued, LeaseStateActive, LeaseStateConsumed,
		LeaseStateExpired, LeaseStateRevoked}
}

// GovAccessRequest is a time-bounded request for access to a resource, part of the
// IGA access governance surface (Batch 9, S23-S28). Approval produces an AccessLease;
// denial, cancellation and expiry do not.
//
// Named GovAccessRequest to avoid collision with the XAA AccessRequest in xaa.go, which
// serves the cross-app authorization flow and has a different schema.
//
// The requester and the subject may differ: an administrator can request access on behalf
// of another principal. The request carries its own expiry so stale requests do not
// accumulate in the pending queue.
type GovAccessRequest struct {
	ID             string     `json:"id" db:"id"`
	WorkspaceID    string     `json:"workspace_id" db:"workspace_id"`
	RequesterID    string     `json:"requester_id" db:"requester_id"`
	SubjectID      string     `json:"subject_id" db:"subject_id"`
	ResourceID     string     `json:"resource_id" db:"resource_id"`
	Action         string     `json:"action" db:"action"`
	Reason         string     `json:"reason" db:"reason"`
	State          string     `json:"state" db:"state"`
	ExpiresAt      time.Time  `json:"expires_at" db:"expires_at"`
	DecidedBy      string     `json:"decided_by,omitempty" db:"decided_by"`
	DecidedAt      *time.Time `json:"decided_at,omitempty" db:"decided_at"`
	DecisionReason string     `json:"decision_reason,omitempty" db:"decision_reason"`
	LeaseID        string     `json:"lease_id,omitempty" db:"lease_id"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// AccessLease is the materialised, time-bounded and use-bounded grant produced by an
// approved GovAccessRequest.
//
// A lease is redeemed (use_count incremented) atomically by an operation; once max_uses
// is reached the lease transitions to consumed and further redemptions are refused. An
// administrator or policy action can revoke a lease before its natural expiry.
//
// ApprovalIDs links the lease to the approval chain that authorised it. PolicyRevision
// records which version of the governing policy was in effect when the lease was issued,
// so a later audit can answer "was this grant consistent with the policy at the time?".
type AccessLease struct {
	ID             string         `json:"id" db:"id"`
	WorkspaceID    string         `json:"workspace_id" db:"workspace_id"`
	RequestID      string         `json:"request_id" db:"request_id"`
	SubjectID      string         `json:"subject_id" db:"subject_id"`
	ResourceID     string         `json:"resource_id" db:"resource_id"`
	Action         string         `json:"action" db:"action"`
	State          string         `json:"state" db:"state"`
	NotBefore      time.Time      `json:"not_before" db:"not_before"`
	ExpiresAt      time.Time      `json:"expires_at" db:"expires_at"`
	MaxUses        int            `json:"max_uses" db:"max_uses"`
	UseCount       int            `json:"use_count" db:"use_count"`
	ApprovalIDs    pq.StringArray `json:"approval_ids" db:"approval_ids"`
	PolicyRevision string         `json:"policy_revision" db:"policy_revision"`
	CreatedAt      time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at" db:"updated_at"`
}
