package models

import (
	"time"

	"github.com/google/uuid"
)

type SyncRun struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SyncConfigID     uuid.UUID  `json:"sync_config_id" gorm:"type:uuid;not null;index"`
	StartedAt        time.Time  `json:"started_at" gorm:"not null;default:now()"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	Status           string     `json:"status" gorm:"type:varchar(32);not null"`
	DryRun           bool       `json:"dry_run" gorm:"not null;default:false"`
	UsersCreated     int        `json:"users_created" gorm:"not null;default:0"`
	UsersUpdated     int        `json:"users_updated" gorm:"not null;default:0"`
	UsersFailed      int        `json:"users_failed" gorm:"not null;default:0"`
	UsersSkipped     int        `json:"users_skipped" gorm:"not null;default:0"`
	ErrorText        *string    `json:"error_text,omitempty" gorm:"type:text"`
	TriggeredByKind  string     `json:"triggered_by_kind" gorm:"type:varchar(32);not null;default:'manual'"`
}

func (SyncRun) TableName() string {
	return "sync_runs"
}
