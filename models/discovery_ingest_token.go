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
// so no response can carry it by accident either.
//
// A token stops working when it is revoked, when it expires, or when the
// source it is bound to is deleted -- and in none of those cases is its row
// deleted. Revoking sets RevokedAt; deleting a source revokes its bound tokens
// in the same transaction and the foreign key then nulls DiscoverySourceID
// (SourceBound stays true), so what a token authorised stays attributable
// after it stops working. Only deleting the whole workspace removes its
// tokens. See 043_discovery_ingest_auth.sql and 044_ingest_token_lifecycle.sql.
type DiscoveryIngestToken struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	// DiscoverySourceID, when set, confines the token to calls that resolve to
	// that one discovery source. Nil on a token that is not SourceBound: any
	// source in the workspace (an enrollment token, usable before the agent's
	// source exists). Nil on a SourceBound token: its source was deleted, and
	// the token is revoked and valid for nothing.
	DiscoverySourceID *uuid.UUID `json:"discovery_source_id" gorm:"type:uuid"`
	// SourceBound records that the token was minted for one source. It is kept
	// after the source is gone, so a NULL DiscoverySourceID never reads as
	// "workspace-wide" for a token that was not.
	SourceBound bool `json:"source_bound" gorm:"column:source_bound;not null"`
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
	// ExpiresAt, when set, is when the token stops working, exactly as if it
	// had been revoked then. Nil never expires.
	ExpiresAt *time.Time `json:"expires_at"`

	// Expired is computed by the database when a token is listed or revoked
	// (expires_at <= now()); it is not a column.
	Expired bool `json:"expired" gorm:"->;-:migration"`
	// SourceDeleted is computed likewise: the token was bound to a source that
	// has since been deleted (source_bound AND discovery_source_id IS NULL). Such
	// a token was revoked by the deletion.
	SourceDeleted bool `json:"source_deleted" gorm:"->;-:migration"`
}

// TableName pins the table; GORM's pluraliser would otherwise guess.
func (DiscoveryIngestToken) TableName() string { return "discovery_ingest_tokens" }
