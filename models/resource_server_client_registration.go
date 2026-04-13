package models

import (
	"time"

	"github.com/google/uuid"
)

// ResourceServerClientRegistration is the join table between resource servers and OAuth clients.
// A client can only access an RS if there is an approved row here.
// All access paths (/oauth/authorize, /oauth/register, consent, introspection) must check this table.
type ResourceServerClientRegistration struct {
	ID               uuid.UUID `json:"id" gorm:"column:id;type:uuid;primary_key;default:gen_random_uuid()"`
	ResourceServerID uuid.UUID `json:"resource_server_id" gorm:"column:resource_server_id;type:uuid;not null;uniqueIndex:idx_rscr_rs_client"`
	OAuthClientID    uuid.UUID `json:"oauth_client_id" gorm:"column:oauth_client_id;type:uuid;not null;uniqueIndex:idx_rscr_rs_client"`
	Status           string    `json:"status" gorm:"column:status;type:varchar(20);not null;default:'approved'"`
	RegistrationType string    `json:"registration_type" gorm:"column:registration_type;type:varchar(20);not null"`
	CreatedAt        time.Time `json:"created_at" gorm:"column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (ResourceServerClientRegistration) TableName() string {
	return "resource_server_client_registrations"
}
