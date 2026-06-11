package models

import (
	"time"

	"github.com/google/uuid"
)

type SCIMEvent struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SCIMConnectionID uuid.UUID  `json:"scim_connection_id" gorm:"type:uuid;not null;index"`
	Ts               time.Time  `json:"ts" gorm:"not null;default:now()"`
	Method           string     `json:"method" gorm:"type:varchar(8);not null"`
	Path             string     `json:"path" gorm:"type:text;not null"`
	ResourceType     string     `json:"resource_type" gorm:"type:varchar(16);not null;default:''"`
	ResourceID       *string    `json:"resource_id,omitempty" gorm:"type:text"`
	StatusCode       int        `json:"status_code" gorm:"not null"`
	ErrorText        *string    `json:"error_text,omitempty" gorm:"type:text"`
	IPAddress        *string    `json:"ip_address,omitempty" gorm:"type:varchar(64)"`
	UserAgent        *string    `json:"user_agent,omitempty" gorm:"type:text"`
}

func (SCIMEvent) TableName() string {
	return "scim_events"
}
