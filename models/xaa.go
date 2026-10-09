package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TrustedIssuer describes an external Authorization Server whose ID-JAGs are
// accepted for XAA redemption at this AuthSec instance. provider_name links to
// oidc_user_identities for subject materialization.
//
// Backing table: public.trusted_issuers.
type TrustedIssuer struct {
	ID                    uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Iss                   string         `json:"iss" gorm:"type:text;not null;uniqueIndex:uq_trusted_issuers_iss"`
	JWKSUri               string         `json:"jwks_uri" gorm:"type:text;not null;column:jwks_uri"`
	AllowedAlgs           pq.StringArray `json:"allowed_algs" gorm:"type:text[];not null;default:'{RS256}'"`
	AllowedAuds           pq.StringArray `json:"allowed_auds" gorm:"type:text[];not null;default:'{}'"`
	ClockSkewSecs         int            `json:"clock_skew_secs" gorm:"not null;default:30"`
	WorkspaceClaimMapping *string        `json:"workspace_claim_mapping,omitempty" gorm:"type:text"`
	SubjectMapping        *string        `json:"subject_mapping,omitempty" gorm:"type:text"`
	ProviderName          string         `json:"provider_name" gorm:"type:text;not null"`
	JITProvisioning       bool           `json:"jit_provisioning" gorm:"not null;default:false"`
	Status                string         `json:"status" gorm:"type:text;not null;default:'active'"`
	RevokedAt             *time.Time     `json:"revoked_at,omitempty" gorm:"column:revoked_at"`
	CreatedAt             time.Time      `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt             time.Time      `json:"updated_at" gorm:"not null;default:now()"`
}

func (TrustedIssuer) TableName() string { return "trusted_issuers" }

// A2ABrokeringPolicy is a permit/deny rule for cross-app XAA redemption or
// issuance. side='redemption' gates incoming ID-JAG redemption; side='issuance'
// gates outbound ID-JAG issuance (Phase 5).
//
// Backing table: public.a2a_brokering_policies.
type A2ABrokeringPolicy struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	Side             string     `json:"side" gorm:"type:text;not null"`
	ClientID         *string    `json:"client_id,omitempty" gorm:"type:text"`
	ResourceServerID *uuid.UUID `json:"resource_server_id,omitempty" gorm:"type:uuid"`
	Effect           string     `json:"effect" gorm:"type:text;not null;default:'permit'"`
	Conditions       *string    `json:"conditions,omitempty" gorm:"type:jsonb"`
	CreatedAt        time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (A2ABrokeringPolicy) TableName() string { return "a2a_brokering_policies" }

// AccessRequest is the coordination record for "identity wants access but has
// no grant yet". It drives the admin queue, requester status, and notifications.
// It is NOT an authority for token issuance — that requires registration +
// live RBAC both passing.
//
// Status transitions: pending → approved | denied | expired; approved → revoked.
// A partial-unique index on status='pending' ensures at most one open request
// per (subject, rs, client) — retries do an upsert updating updated_at.
//
// Backing table: public.access_requests.
type AccessRequest struct {
	ID                   uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID          uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	ResourceServerID     uuid.UUID  `json:"resource_server_id" gorm:"type:uuid;not null"`
	SubjectType          string     `json:"subject_type" gorm:"type:text;not null"`
	SubjectID            uuid.UUID  `json:"subject_id" gorm:"type:uuid;not null"`
	RequestedByClient    string     `json:"requested_by_client" gorm:"type:text;not null"`
	RequestedScopes      string     `json:"requested_scopes" gorm:"type:text;not null;default:''"`
	RequestedRarID       *uuid.UUID `json:"requested_rar_id,omitempty" gorm:"type:uuid"`
	AuthorizationDetails *string    `json:"authorization_details,omitempty" gorm:"type:jsonb"`
	Status               string     `json:"status" gorm:"type:text;not null;default:'pending'"`
	Reason               *string    `json:"reason,omitempty" gorm:"type:text"`
	CreatedAt            time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt            time.Time  `json:"updated_at" gorm:"not null;default:now()"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty" gorm:"type:timestamptz"`
	// Governance intent, added with entitlement provenance. Justification and Purpose
	// are carried into the provenance record on approval; RequestedDuration is what the
	// requester ASKED for, as distinct from ExpiresAt, which is what they were granted.
	Justification     string         `json:"justification" gorm:"type:text;not null;default:''"`
	Purpose           string         `json:"purpose" gorm:"type:text;not null;default:''"`
	RequestOrigin     string         `json:"request_origin" gorm:"type:text;not null;default:'admin'"`
	RequestedDuration *time.Duration `json:"requested_duration,omitempty" gorm:"type:interval"`
	DiscoveredAgentID *uuid.UUID     `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`
	DecidedBy         *uuid.UUID     `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt         *time.Time     `json:"decided_at,omitempty" gorm:"type:timestamptz"`
}

func (AccessRequest) TableName() string { return "access_requests" }

// AccessRequestStatus constants.
const (
	AccessRequestPending  = "pending"
	AccessRequestApproved = "approved"
	AccessRequestDenied   = "denied"
	AccessRequestExpired  = "expired"
	AccessRequestRevoked  = "revoked"
)
