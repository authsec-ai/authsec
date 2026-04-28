package models

import (
	"time"

	"github.com/google/uuid"
)

// Manifest attempt status constants.
const (
	ManifestAttemptSuccess        = "success"
	ManifestAttemptAuthFailed     = "auth_failed"
	ManifestAttemptInvalidPayload = "invalid_payload"
	ManifestAttemptEmptyToolList  = "empty_tool_list"
	ManifestAttemptServerError    = "server_error"
)

// ResourceServerManifestAttempt records each PUT to the sdk-manifest endpoint,
// successful or not. Powers the polling UI in step 2 Path A of the setup wizard.
type ResourceServerManifestAttempt struct {
	ID              uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	RSID            uuid.UUID  `json:"rs_id" gorm:"type:uuid;not null;index:idx_rs_manifest_attempts_rs_at"`
	AttemptedAt     time.Time  `json:"attempted_at" gorm:"not null;default:NOW();index:idx_rs_manifest_attempts_rs_at"`
	Status          string     `json:"status" gorm:"type:text;not null"`
	Reason          *string    `json:"reason,omitempty" gorm:"type:text"`
	ToolCount       *int       `json:"tool_count,omitempty"`
	ManifestVersion *string    `json:"manifest_version,omitempty" gorm:"type:text"`
	SDKBuildID      *string    `json:"sdk_build_id,omitempty" gorm:"type:text"`
}

func (ResourceServerManifestAttempt) TableName() string {
	return "resource_server_manifest_attempts"
}
