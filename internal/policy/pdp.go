package policy

import (
	"context"

	"github.com/google/uuid"
)

// Effect is the PDP decision outcome.
type Effect string

const (
	// EffectPermit — an active permit policy matched; issuance may proceed.
	EffectPermit Effect = "permit"
	// EffectDeny — a deny policy matched; issuance should be blocked in enforce mode.
	EffectDeny Effect = "deny"
	// EffectNoPolicy — no policy row matched; the existing thin gates remain authoritative.
	EffectNoPolicy Effect = "no_policy"
)

// PolicyRequest carries the issuance context against which the PDP evaluates.
type PolicyRequest struct {
	WorkspaceID      uuid.UUID
	ClientID         string
	SubjectType      string // "user" or "service_account"
	SubjectID        uuid.UUID
	ResourceServerID uuid.UUID
	TokenFamily      string // "m2m", "xaa", "ciba"
	RequestedScopes  string
}

// PolicyDecision is what the PDP returns.
type PolicyDecision struct {
	Effect Effect
	Reason string
}

// PDP is the policy-decision-point interface for token issuance.
type PDP interface {
	Decide(ctx context.Context, req PolicyRequest) (PolicyDecision, error)
}
