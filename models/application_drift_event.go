package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Drift event types — keep the const list in sync with the CHECK constraint
// in migrations/tenant/027.
const (
	DriftEventSecretRotated       = "secret_rotated"
	DriftEventDefaultRoleDisabled = "default_role_disabled"
	DriftEventConnectionRevoked   = "connection_revoked"
	DriftEventToolUnmapped        = "tool_unmapped"
	DriftEventScopeDeleted        = "scope_deleted"
)

// ApplicationDriftEvent records a single drift event for an Application
// after it has been activated. Lives in the tenant DB.
type ApplicationDriftEvent struct {
	ID            uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID      string         `json:"tenant_id" gorm:"type:varchar(255);not null"`
	ApplicationID uuid.UUID      `json:"application_id" gorm:"type:uuid;not null;index"`
	EventType     string         `json:"event_type" gorm:"type:text;not null"`
	EventPayload  datatypes.JSON `json:"event_payload,omitempty" gorm:"type:jsonb"`
	OccurredAt    time.Time      `json:"occurred_at" gorm:"not null;default:CURRENT_TIMESTAMP;index"`
	OccurredBy    *uuid.UUID     `json:"occurred_by,omitempty" gorm:"type:uuid"`
}

func (ApplicationDriftEvent) TableName() string { return "application_drift_events" }

// ApplicationDriftEventDismissal records that a specific admin has
// acknowledged + dismissed a specific drift event. The composite PK
// (event_id, admin_user_id) means each admin can dismiss each event once.
type ApplicationDriftEventDismissal struct {
	EventID     uuid.UUID `json:"event_id" gorm:"type:uuid;primaryKey"`
	AdminUserID uuid.UUID `json:"admin_user_id" gorm:"type:uuid;primaryKey"`
	DismissedAt time.Time `json:"dismissed_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ApplicationDriftEventDismissal) TableName() string {
	return "application_drift_event_dismissals"
}
