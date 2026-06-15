package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// XAAIssuanceModeInternal means the client authenticates at AuthSec's
// /idjag/token endpoint with a client_secret we store. XAAIssuanceModeExternal
// means the ID-JAG is signed by some other trusted IdP (e.g. Okta) — the row
// just exists so we can pin policy against the requesting_client_id, but we
// never check a secret against it.
const (
	XAAIssuanceModeInternal = "internal"
	XAAIssuanceModeExternal = "external"
)

// XAAClientApp is the requesting-app identity for Cross-App Access. Lives in
// master DB. See migrations/master/111_create_xaa_client_apps.sql for the
// schema commentary; this struct mirrors it 1:1.
type XAAClientApp struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID         uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	ClientID         string     `json:"client_id" gorm:"type:text;uniqueIndex;not null"`
	ClientSecretHash string     `json:"-" gorm:"type:text"` // nil for external issuance mode
	Name             string     `json:"name" gorm:"type:text;not null"`
	DisplayName      string     `json:"display_name,omitempty" gorm:"type:text"`
	IssuanceMode     string     `json:"issuance_mode" gorm:"type:text;not null;default:'internal'"`
	Active           bool       `json:"active" gorm:"not null;default:true"`
	CreatedAt        time.Time  `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty" gorm:"index"`
}

func (XAAClientApp) TableName() string { return "xaa_client_apps" }

// ApplicationXAAPolicy is the per-Application allowlist for which XAA client
// apps may exchange an ID-JAG for an access token here. Tenant DB.
type ApplicationXAAPolicy struct {
	ID                  uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID            uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index"`
	ResourceServerID    uuid.UUID      `json:"resource_server_id" gorm:"type:uuid;not null;index"`
	RequestingClientID  string         `json:"requesting_client_id" gorm:"type:text;not null"`
	TrustedIssuer       string         `json:"trusted_issuer" gorm:"type:text;not null;default:''"`
	AllowedScopes       pq.StringArray `json:"allowed_scopes" gorm:"type:text[];not null;default:'{}'"`
	Enabled             bool           `json:"enabled" gorm:"not null;default:true"`
	CreatedAt           time.Time      `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt           time.Time      `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ApplicationXAAPolicy) TableName() string { return "application_xaa_policies" }
