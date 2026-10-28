package models

import (
	"time"

	"github.com/google/uuid"
)

const (
	WPBStatePending    = "pending"
	WPBStateActive     = "active"
	WPBStateSuperseded = "superseded"
	WPBStateRevoked    = "revoked"
)

type WorkloadPolicyBinding struct {
	ID             uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	WorkloadID     uuid.UUID `json:"workload_id" gorm:"type:uuid;not null"`
	PolicyID       uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`
	Revision       int       `json:"revision" gorm:"not null"`
	State          string    `json:"state" gorm:"type:text;not null;default:'pending'"`
	DeliveryCursor int64     `json:"delivery_cursor" gorm:"not null;default:0"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (WorkloadPolicyBinding) TableName() string { return "workload_policy_bindings" }
