package models

import (
	"time"

	"github.com/google/uuid"
)

// Which channel a warning went out on.
const (
	WarningChannelEmail   = "email"
	WarningChannelWebhook = "webhook"
)

// Why a recipient was chosen, in the order §3A.9 gives: who will be surprised.
const (
	// RecipientOwner is the accountable human, and the person whose workload
	// disappears. First for that reason.
	RecipientOwner = "owner"
	// RecipientAuthor wrote the policy; RecipientConfirmer authorised the
	// destructive expiry. Both signed up for the consequence.
	RecipientAuthor    = "author"
	RecipientConfirmer = "confirmer"
	// RecipientWorkspaceAdmin is the backstop, for when everyone above has left.
	RecipientWorkspaceAdmin = "workspace_admin"
	RecipientWebhook        = "webhook"
)

// Delivery state of one warning.
const (
	WarningPending = "pending"
	WarningSent    = "sent"
	// WarningFailed is retryable. WarningDead has exhausted its attempts and will
	// not be retried -- and, crucially, does NOT stop the action it warned about.
	WarningFailed = "failed"
	WarningDead   = "dead"
)

// MaxWarningAttempts bounds retries.
//
// Five, not unlimited: a permanently bad address must stop consuming the worker's
// budget, and a warning that has failed five times over its lead window is not
// going to arrive before the deadline it was warning about.
const MaxWarningAttempts = 5

// GovernanceNotificationSettings is one workspace's escalation configuration.
//
// The LOOKAHEAD is the system of record and needs no configuration at all --
// GET /governance/policies/upcoming is a pull, so there is no delivery to fail.
// Everything here is escalation on top of it, which is why a workspace with no row
// still works: it gets the defaults.
type GovernanceNotificationSettings struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	// WarningLead is how far ahead of a destructive deadline to warn.
	//
	// No `default` tag, deliberately: PGInterval is a time.Duration underneath, so
	// GORM parses a default tag as an int64 and "'7 days'" fails outright. The
	// column carries the default; Lead() carries it in Go.
	WarningLead PGInterval `json:"warning_lead" gorm:"type:interval;not null"`
	// WebhookURL is the optional second channel. Outbound only, so it costs nothing
	// against EN-0: calling a customer's Slack is not calling into their cluster.
	// https is enforced by a CHECK — a warning naming the workload about to be
	// deleted is a map of what to attack while nobody is watching it.
	WebhookURL    string `json:"webhook_url" gorm:"not null;default:''"`
	WebhookSecret string `json:"-" gorm:"not null;default:''"`
	EmailEnabled  bool   `json:"email_enabled" gorm:"not null;default:true"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (GovernanceNotificationSettings) TableName() string {
	return "governance_notification_settings"
}

// DefaultWarningLead is used when a workspace has no settings row.
const DefaultWarningLead = 7 * 24 * time.Hour

// Lead returns the configured lead, or the default.
func (s *GovernanceNotificationSettings) Lead() time.Duration {
	if s == nil || time.Duration(s.WarningLead) <= 0 {
		return DefaultWarningLead
	}
	return time.Duration(s.WarningLead)
}

// AgentPolicyWarning is one scheduled pre-deadline warning.
//
// A row per (policy, agent, deadline, channel, recipient). One agent, not one
// policy: "three of your agents will be deleted" is a summary, and the person who
// has to act needs to know which one is theirs.
type AgentPolicyWarning struct {
	ID                uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	PolicyID          uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`
	DiscoveredAgentID uuid.UUID `json:"discovered_agent_id" gorm:"type:uuid;not null"`
	// Deadline is what is being warned about, and part of the dedupe key: moving a
	// policy's expiry schedules a FRESH warning rather than reusing a sent one.
	Deadline time.Time `json:"deadline" gorm:"not null"`
	// OnExpiry is snapshotted, not read from the policy at send time -- the warning
	// has to describe what was scheduled when it was scheduled.
	OnExpiry      string `json:"on_expiry" gorm:"not null"`
	Channel       string `json:"channel" gorm:"not null"`
	Recipient     string `json:"recipient" gorm:"not null"`
	RecipientRole string `json:"recipient_role" gorm:"not null;default:''"`

	AvailableAt  time.Time  `json:"available_at" gorm:"not null"`
	State        string     `json:"state" gorm:"not null;default:'pending'"`
	AttemptCount int        `json:"attempt_count" gorm:"not null;default:0"`
	LastError    string     `json:"last_error" gorm:"not null;default:''"`
	SentAt       *time.Time `json:"sent_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (AgentPolicyWarning) TableName() string { return "agent_policy_warnings" }
