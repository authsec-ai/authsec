package models

import (
	"time"

	"github.com/google/uuid"
)

// Drift event type constants.
const (
	DriftEventScopeDeleted        = "scope_deleted"
	DriftEventToolUnmapped        = "tool_unmapped"
	DriftEventDefaultRoleDisabled = "default_role_disabled"
	DriftEventSecretRotated       = "secret_rotated"
)

// ResourceServerDriftEvent records a post-activation destructive admin edit.
// One row per event; per-admin dismissal tracked in ResourceServerDriftEventDismissal.
type ResourceServerDriftEvent struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	RSID         uuid.UUID  `json:"rs_id" gorm:"type:uuid;not null;index:idx_rs_drift_events_rs_occurred"`
	EventType    string     `json:"event_type" gorm:"type:text;not null"`
	EventPayload []byte     `json:"event_payload,omitempty" gorm:"type:jsonb"`
	OccurredAt   time.Time  `json:"occurred_at" gorm:"not null;default:NOW();index:idx_rs_drift_events_rs_occurred"`
	OccurredBy   *uuid.UUID `json:"occurred_by,omitempty" gorm:"type:uuid"`
}

func (ResourceServerDriftEvent) TableName() string {
	return "resource_server_drift_events"
}

// ResourceServerDriftEventDismissal records a per-admin dismissal of a drift event.
type ResourceServerDriftEventDismissal struct {
	EventID     uuid.UUID `json:"event_id" gorm:"type:uuid;primaryKey"`
	AdminUserID uuid.UUID `json:"admin_user_id" gorm:"type:uuid;primaryKey"`
	DismissedAt time.Time `json:"dismissed_at" gorm:"not null;default:NOW()"`
}

func (ResourceServerDriftEventDismissal) TableName() string {
	return "resource_server_drift_event_dismissals"
}
