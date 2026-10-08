package services

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// LegacyNotificationChannels is the channel part of a workspace's legacy
// governance_notification_settings row (the retired agent-policy feature).
//
// DECISION (T3.20): this read lives in a file of its own, outside the IGA
// files scripts/ci-iga-isolation-check.sh scans -- the same seam as
// workspace_member_directory.go. The disposition plan (§2,
// governance_notification_settings: "Migrate channel addresses into Phase 3
// notification settings where a workspace has them -- copy, do not move")
// makes Phase 3 read this one legacy row, once, read-only. Nothing here
// writes, moves or deletes the legacy row: it stays until retirement (G4).
type LegacyNotificationChannels struct {
	WebhookURL    string
	WebhookSecret string
	EmailEnabled  bool
}

// ReadLegacyNotificationChannels returns the workspace's legacy channel
// settings, or nil when it has no row.
func ReadLegacyNotificationChannels(db *gorm.DB, ws uuid.UUID) (*LegacyNotificationChannels, error) {
	var rows []models.GovernanceNotificationSettings
	if err := db.Where("workspace_id = ?", ws).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &LegacyNotificationChannels{WebhookURL: r.WebhookURL, WebhookSecret: r.WebhookSecret, EmailEnabled: r.EmailEnabled}, nil
}
