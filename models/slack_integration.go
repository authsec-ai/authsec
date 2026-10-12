package models

import (
	"time"

	"github.com/google/uuid"
)

// Slack installation and user links (SPEC-iga-phase3-policy.md §7.11;
// migration 054). BotTokenRef names the Vault path; no token is stored here.

// WorkspaceSlackIntegration is a workspace's Slack app installation. One
// unrevoked installation per Slack team.
type WorkspaceSlackIntegration struct {
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	SlackTeamID        string     `json:"slack_team_id" gorm:"not null"`
	SlackTeamName      string     `json:"slack_team_name" gorm:"not null;default:''"`
	BotTokenRef        string     `json:"bot_token_ref" gorm:"not null"`
	ApprovalsChannelID string     `json:"approvals_channel_id" gorm:"not null;default:''"`
	InstalledBy        uuid.UUID  `json:"installed_by" gorm:"type:uuid;not null"`
	InstalledAt        time.Time  `json:"installed_at" gorm:"not null;default:now()"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

func (WorkspaceSlackIntegration) TableName() string { return "workspace_slack_integration" }

// SlackUserLink binds a Slack user to a workspace member, by verified email
// or console confirmation.
type SlackUserLink struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	SlackUserID string    `json:"slack_user_id" gorm:"primaryKey"`
	UserID      uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	LinkedVia   string    `json:"linked_via" gorm:"not null"`
	LinkedAt    time.Time `json:"linked_at" gorm:"not null;default:now()"`
}

func (SlackUserLink) TableName() string { return "slack_user_link" }
