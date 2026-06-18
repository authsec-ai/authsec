package models

import (
	"time"

	"github.com/google/uuid"
)

// Policy is a permit/deny rule for the token-issuance PDP.
// NULL selectors are wildcards: a NULL subject_id matches any subject of the
// given subject_type; NULL client_id matches any client; NULL resource_server_id
// matches any RS. token_family='*' matches all families.
//
// Backing table: public.policies.
type Policy struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	Name             string     `json:"name" gorm:"type:text;not null"`
	Description      *string    `json:"description,omitempty" gorm:"type:text"`
	SubjectType      *string    `json:"subject_type,omitempty" gorm:"type:text"`
	SubjectID        *uuid.UUID `json:"subject_id,omitempty" gorm:"type:uuid"`
	ClientID         *string    `json:"client_id,omitempty" gorm:"type:text"`
	ResourceServerID *uuid.UUID `json:"resource_server_id,omitempty" gorm:"type:uuid"`
	TokenFamily      string     `json:"token_family" gorm:"type:text;not null;default:'*'"`
	Effect           string     `json:"effect" gorm:"type:text;not null;default:'permit'"`
	Priority         int        `json:"priority" gorm:"not null;default:0"`
	Conditions       *string    `json:"conditions,omitempty" gorm:"type:jsonb"`
	IsActive         bool       `json:"is_active" gorm:"not null;default:true"`
	CreatedAt        time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (Policy) TableName() string { return "policies" }

// AuthIssuanceAudit is a shadow-mode comparison record written when
// POLICY_ENGINE_MODE=shadow. pdp_effect is what the PDP decided;
// gate_effect is what the existing thin gates (P2/P3) decided;
// pdp_agrees is true when they match (or when pdp has no opinion).
//
// Backing table: public.auth_issuance_audit.
type AuthIssuanceAudit struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	TokenFamily      string     `json:"token_family" gorm:"type:text;not null"`
	ClientID         string     `json:"client_id" gorm:"type:text;not null"`
	SubjectType      string     `json:"subject_type" gorm:"type:text;not null"`
	SubjectID        *uuid.UUID `json:"subject_id,omitempty" gorm:"type:uuid"`
	ResourceServerID uuid.UUID  `json:"resource_server_id" gorm:"type:uuid;not null"`
	PDPEffect        string     `json:"pdp_effect" gorm:"type:text;not null"`
	GateEffect       string     `json:"gate_effect" gorm:"type:text;not null"`
	PDPAgrees        bool       `json:"pdp_agrees" gorm:"not null"`
	ScopesRequested  string     `json:"scopes_requested" gorm:"type:text;not null;default:''"`
	ScopesGranted    string     `json:"scopes_granted" gorm:"type:text;not null;default:''"`
	PDPReason        *string    `json:"pdp_reason,omitempty" gorm:"type:text"`
	CreatedAt        time.Time  `json:"created_at" gorm:"not null;default:now()"`
}

func (AuthIssuanceAudit) TableName() string { return "auth_issuance_audit" }
