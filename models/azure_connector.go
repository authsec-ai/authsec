package models

import (
	"time"

	"github.com/google/uuid"
)

// Azure onboarding purposes. The state row's purpose decides which callback
// branch is legal, so a login state cannot be replayed into the consent branch.
const (
	AzureOAuthPurposeLogin   = "login"
	AzureOAuthPurposeConsent = "consent"
)

// AzureConnector is one Entra tenant this workspace has admin-consented into.
//
// It is deliberately NOT a CloudConnector: consent alone proves nothing can be
// read. ARMReaderOK is what says the tenant is actually usable, and it stays
// false until an ARM Reader check passes.
type AzureConnector struct {
	ID          uuid.UUID `json:"id"           gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`

	TenantID    string `json:"tenant_id"              gorm:"type:text;not null"`
	DisplayName string `json:"display_name,omitempty" gorm:"type:text"`
	Domain      string `json:"domain,omitempty"       gorm:"type:text"`

	ConsentedAt *time.Time `json:"consented_at,omitempty" gorm:"type:timestamptz"`

	// false until an ARM Reader check has actually passed. Onboarding is
	// complete when a row exists AND this is true. ARMCheckedAt still being nil
	// is what says a check has never run at all.
	ARMReaderOK  bool       `json:"arm_reader_ok"              gorm:"column:arm_reader_ok;not null;default:false"`
	ARMCheckedAt *time.Time `json:"arm_checked_at,omitempty"   gorm:"column:arm_checked_at;type:timestamptz"`
	ARMLastError string     `json:"arm_last_error,omitempty"   gorm:"column:arm_last_error;type:text"`

	// PrincipalObjectID is the AuthSec service principal's object id inside this
	// tenant. Known only after consent, and required by any role assignment.
	PrincipalObjectID string `json:"principal_object_id,omitempty" gorm:"column:principal_object_id;type:text"`

	CreatedAt time.Time `json:"created_at" gorm:"type:timestamptz;autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"type:timestamptz;autoUpdateTime"`
}

func (AzureConnector) TableName() string { return "azure_connectors" }

// AzureOAuthState is one pending browser redirect.
//
// Every field the callback trusts is read from here rather than from the query
// string Microsoft appends, because the query string is attacker-reachable and
// this row is not.
type AzureOAuthState struct {
	State       string    `json:"-" gorm:"type:text;primaryKey"`
	WorkspaceID uuid.UUID `json:"-" gorm:"type:uuid;not null"`

	Purpose  string `json:"-" gorm:"type:text;not null"`
	TenantID string `json:"-" gorm:"type:text"`

	CreatedBy string    `json:"-" gorm:"type:text"`
	ExpiresAt time.Time `json:"-" gorm:"type:timestamptz;not null"`
	CreatedAt time.Time `json:"-" gorm:"type:timestamptz;autoCreateTime"`
}

func (AzureOAuthState) TableName() string { return "azure_oauth_state" }
