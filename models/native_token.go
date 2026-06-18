package models

import (
	"time"

	"github.com/google/uuid"
)

// Token family constants for NativeToken.TokenFamily.
const (
	TokenFamilyXAA  = "xaa"  // ID-JAG redemption (agent acting for a user)
	TokenFamilyM2M  = "m2m"  // client_credentials (service account)
	TokenFamilyCIBA = "ciba" // backchannel-approved (user, via agent)
)

// Revoked-token kinds for RevokedToken.Kind.
const (
	RevokedKindIDJAG       = "id_jag"
	RevokedKindAccessToken = "access_token"
)

// NativeToken is the metadata-only registry for a token minted by the
// NativeSealer (M2M / XAA / CIBA). It holds NO raw token material — the JWT
// proves signature + jti, and this row is the authoritative source for
// workspace / subject / resource-server / family / scope at introspection time.
//
// Backing table: public.native_tokens (001_bootstrap.sql). GORM is read/write
// here but never AutoMigrate's it — the SQL is the source of truth.
type NativeToken struct {
	JTI              uuid.UUID  `json:"jti" gorm:"column:jti;type:uuid;primaryKey"`
	Iss              string     `json:"iss" gorm:"column:iss;type:text;not null"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"column:workspace_id;type:uuid;not null"`
	TokenFamily      string     `json:"token_family" gorm:"column:token_family;type:text;not null"`
	SubjectType      string     `json:"subject_type" gorm:"column:subject_type;type:text;not null"`
	SubjectID        uuid.UUID  `json:"subject_id" gorm:"column:subject_id;type:uuid;not null"`
	ActorClientID    *string    `json:"actor_client_id,omitempty" gorm:"column:actor_client_id;type:text"`
	ActorSpiffeID    *string    `json:"actor_spiffe_id,omitempty" gorm:"column:actor_spiffe_id;type:text"`
	ClientID         string     `json:"client_id" gorm:"column:client_id;type:text;not null"`
	ResourceServerID uuid.UUID  `json:"resource_server_id" gorm:"column:resource_server_id;type:uuid;not null"`
	Aud              string     `json:"aud" gorm:"column:aud;type:text;not null"`
	Scope            string     `json:"scope" gorm:"column:scope;type:text;not null"`
	SourceGrantJTI   *string    `json:"source_grant_jti,omitempty" gorm:"column:source_grant_jti;type:text"`
	RarID            *uuid.UUID `json:"rar_id,omitempty" gorm:"column:rar_id;type:uuid"`
	IssuedAt         time.Time  `json:"issued_at" gorm:"column:issued_at;not null"`
	ExpiresAt        time.Time  `json:"expires_at" gorm:"column:expires_at;not null"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty" gorm:"column:revoked_at"`
}

// TableName pins the table name (GORM would otherwise pluralize correctly here,
// but we make it explicit to match the hand-curated bootstrap).
func (NativeToken) TableName() string { return "native_tokens" }

// RevokedToken is the revocation source of truth. Keyed (iss, kind, jti) because
// a jti is only unique per issuer and revocation meaning differs by kind.
//
// Backing table: public.revoked_tokens.
type RevokedToken struct {
	Iss       string    `json:"iss" gorm:"column:iss;type:text;primaryKey"`
	Kind      string    `json:"kind" gorm:"column:kind;type:text;primaryKey"`
	JTI       string    `json:"jti" gorm:"column:jti;type:text;primaryKey"`
	RevokedAt time.Time `json:"revoked_at" gorm:"column:revoked_at;not null;default:now()"`
	Reason    *string   `json:"reason,omitempty" gorm:"column:reason;type:text"`
	ExpiresAt time.Time `json:"expires_at" gorm:"column:expires_at;not null"`
}

func (RevokedToken) TableName() string { return "revoked_tokens" }

// IDJAGReplay records a redeemed ID-JAG as *seen* (one-shot replay guard),
// keyed (iss, jti). This is never a revocation record.
//
// Backing table: public.id_jag_replay_cache.
type IDJAGReplay struct {
	Iss       string    `json:"iss" gorm:"column:iss;type:text;primaryKey"`
	JTI       string    `json:"jti" gorm:"column:jti;type:text;primaryKey"`
	ExpiresAt time.Time `json:"expires_at" gorm:"column:expires_at;not null"`
}

func (IDJAGReplay) TableName() string { return "id_jag_replay_cache" }
