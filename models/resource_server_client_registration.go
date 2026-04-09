package models

import (
	"time"

	"github.com/google/uuid"
)

// ResourceServerClientRegistration is the join table between resource servers and OAuth clients.
// A client can only access an RS if there is an approved row here.
// All access paths (/oauth/authorize, /oauth/register, consent, introspection) must check this table.
type ResourceServerClientRegistration struct {
	ID               uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ResourceServerID uuid.UUID `json:"resource_server_id" gorm:"type:uuid;not null;uniqueIndex:idx_rscr_rs_client"`
	OAuthClientID    uuid.UUID `json:"oauth_client_id" gorm:"type:uuid;not null;uniqueIndex:idx_rscr_rs_client"`
	Status           string    `json:"status" gorm:"type:varchar(20);not null;default:'approved'"`
	RegistrationType string    `json:"registration_type" gorm:"type:varchar(20);not null"`
	CreatedAt        time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
}

func (ResourceServerClientRegistration) TableName() string {
	return "resource_server_client_registrations"
}
