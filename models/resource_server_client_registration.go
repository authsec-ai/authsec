package models

import (
	"time"

	"github.com/google/uuid"
)

// Status values for resource_server_client_registrations.status.
const (
	RegistrationStatusApproved = "approved"
	RegistrationStatusPending  = "pending"
	RegistrationStatusRevoked  = "revoked"
)

// ResourceServerClientRegistration joins a resource_server (tenant DB) with an
// mcp_oauth_clients row (master DB). client_id is a string, not a UUID FK,
// because PostgreSQL cannot declare a cross-database FK. Lives in the tenant DB.
type ResourceServerClientRegistration struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ResourceServerID uuid.UUID  `json:"resource_server_id" gorm:"type:uuid;not null;index"`
	ClientID         string     `json:"client_id" gorm:"type:varchar(512);not null;index"`
	Status           string     `json:"status" gorm:"type:text;not null;default:'approved'"`
	RegistrationType string     `json:"registration_type" gorm:"type:varchar(20);not null;default:'dcr'"`
	CreatedAt        time.Time  `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedReason    *string    `json:"revoked_reason,omitempty" gorm:"type:text"`
}

func (ResourceServerClientRegistration) TableName() string {
	return "resource_server_client_registrations"
}
