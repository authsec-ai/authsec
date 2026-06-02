package models

import (
	"time"

	"github.com/google/uuid"
)

// Risk levels for oauth_scopes.risk_level — see models/agent_action.go for
// the shared RiskLevelLow / RiskLevelMedium / RiskLevelHigh / RiskLevelCritical
// constants; the CHECK in migration 028 mirrors those.

// Sources for oauth_scopes.source (matches CHECK in migration 028).
const (
	ScopeSourceAdmin             = "admin"
	ScopeSourceApplicationCreate = "application_create"
	ScopeSourceSDKDiscovered     = "sdk_discovered"
)

// OAuthScope is one per-Application scope. Lives in tenant DB.
// The Application's resource_servers.scopes_supported array is kept in
// sync by application code — every oauth_scopes write touches both.
type OAuthScope struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID      string    `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ApplicationID uuid.UUID `json:"application_id" gorm:"type:uuid;not null;index"`
	ScopeString   string    `json:"scope_string" gorm:"type:text;not null"`
	DisplayName   string    `json:"display_name,omitempty" gorm:"type:text"`
	Description   string    `json:"description,omitempty" gorm:"type:text"`
	RiskLevel     string    `json:"risk_level" gorm:"type:text;not null;default:'low'"`
	Source        string    `json:"source" gorm:"type:text;not null;default:'admin'"`
	CreatedAt     time.Time `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt     time.Time `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (OAuthScope) TableName() string { return "oauth_scopes" }
