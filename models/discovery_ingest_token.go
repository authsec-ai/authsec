package models

import (
	"time"

	"github.com/google/uuid"
)

// DiscoveryIngestToken is a credential a discovery agent presents on the
// discovery ingress (/authsec/discovery/agent-registration, /sightings,
// /lifecycle, /resync-manifest, /rbac-snapshot) as `Authorization: Bearer`.
//
// Only the sha256 of the token is stored. The plaintext exists once, in the
// response to the mint call, and nowhere else; TokenHash is tagged `json:"-"`
// so no response can carry it by accident either. Revoking a token sets
// RevokedAt rather than deleting the row, so what a token authorised stays
// attributable after it stops working. See 043_discovery_ingest_auth.sql.
type DiscoveryIngestToken struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	// DiscoverySourceID, when set, confines the token to calls that resolve to
	// that one discovery source. Nil: any source in the workspace (an
	// enrollment token, usable before the agent's source exists).
	DiscoverySourceID *uuid.UUID `json:"discovery_source_id" gorm:"type:uuid"`
	// TokenHash is sha256(token) as lower-case hex. Never serialised.
	TokenHash string `json:"-" gorm:"column:token_hash;not null"`
	// TokenPrefix is the first 8 characters of the token: enough for an
	// operator to tell tokens apart in a list, never enough to use one.
	TokenPrefix string     `json:"token_prefix" gorm:"not null;default:''"`
	Label       string     `json:"label" gorm:"not null;default:''"`
	CreatedBy   string     `json:"created_by" gorm:"not null;default:''"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

// TableName pins the table; GORM's pluraliser would otherwise guess.
func (DiscoveryIngestToken) TableName() string { return "discovery_ingest_tokens" }
