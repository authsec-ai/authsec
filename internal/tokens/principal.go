package tokens

import "github.com/google/uuid"

const (
	SubjectTypeUser           = "user"
	SubjectTypeServiceAccount = "service_account"
)

// Principal is the normalized token subject resolved before any issuance.
// For M2M: SubjectType="service_account", SubjectID=service_account.id.
// For XAA/CIBA: SubjectType="user", SubjectID=local user UUID.
type Principal struct {
	SubjectType string
	SubjectID   uuid.UUID
	WorkspaceID uuid.UUID
}

// Actor is the delegating client when an agent is acting on behalf of a user
// (XAA / CIBA). For M2M the token is issued directly to the SA — no actor.
type Actor struct {
	ClientID string
	SpiffeID *string
}
