package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Phase 3 operations (SPEC-iga-phase3-policy.md §1.1, §4.3, §8; migrations
// 052-055): durable jobs, the append-only event log, hourly metrics, IaC
// sources and changes, the notification outbox and workspace settings. The
// enforcement binding, resource-policy collection and Slack tables are in
// cloud_enforcement.go and slack_integration.go.

// Enforcement modes (iga_gov_settings, §4.3).
const (
	GovModeFindingsOnly = "findings_only"
	GovModeEnforce      = "enforce"
)

// Job states (§8.1). queued and running are "open": one open job per
// (workspace, kind, dedupe_key).
const (
	GovJobQueued    = "queued"
	GovJobRunning   = "running"
	GovJobComplete  = "complete"
	GovJobFailed    = "failed"
	GovJobAbandoned = "abandoned"
)

// Event actor kinds.
const (
	GovActorUser      = "user"
	GovActorSystem    = "system"
	GovActorSlackUser = "slack_user"
	GovActorAWS       = "aws"
)

// IGAGovJob is fenced durable work. LeaseVersion is the fence token, never a
// clock.
type IGAGovJob struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	Kind           string     `json:"kind" gorm:"not null"`
	SubjectID      *uuid.UUID `json:"subject_id,omitempty" gorm:"type:uuid"`
	Rev            *int64     `json:"rev,omitempty"`
	DedupeKey      string     `json:"dedupe_key" gorm:"not null"`
	Status         string     `json:"status" gorm:"not null;default:'queued'"`
	RunAfter       time.Time  `json:"run_after" gorm:"not null;default:now()"`
	LeaseOwner     string     `json:"lease_owner" gorm:"not null;default:''"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	LeaseVersion   int64      `json:"lease_version" gorm:"not null;default:0"`
	Attempts       int        `json:"attempts" gorm:"not null;default:0"`
	MaxAttempts    int        `json:"max_attempts" gorm:"not null;default:5"`
	LastError      string     `json:"last_error" gorm:"not null;default:''"`
	CreatedAt      time.Time  `json:"created_at" gorm:"not null;default:now()"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

func (IGAGovJob) TableName() string { return "iga_gov_job" }

// IGAGovEvent is append-only audit, the source of Logs. UPDATE is refused and
// DELETE is refused outside a workspace purge (authsec.workspace_purge = on);
// trigger iga_gov_event_immutable. ID is GENERATED ALWAYS AS IDENTITY.
type IGAGovEvent struct {
	ID           int64           `json:"id" gorm:"primaryKey;autoIncrement"`
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	OccurredAt   time.Time       `json:"occurred_at" gorm:"not null;default:now()"`
	Event        string          `json:"event" gorm:"not null"`
	ActorKind    string          `json:"actor_kind" gorm:"not null"`
	ActorID      string          `json:"actor_id" gorm:"not null;default:''"`
	PolicyID     *uuid.UUID      `json:"policy_id,omitempty" gorm:"type:uuid"`
	VersionID    *uuid.UUID      `json:"version_id,omitempty" gorm:"type:uuid"`
	DeploymentID *uuid.UUID      `json:"deployment_id,omitempty" gorm:"type:uuid"`
	FindingID    *uuid.UUID      `json:"finding_id,omitempty" gorm:"type:uuid"`
	Payload      json.RawMessage `json:"payload" gorm:"type:jsonb;not null;default:'{}'"`
}

func (IGAGovEvent) TableName() string { return "iga_gov_event" }

// IGAGovMetricsHourly is one workspace-hour of posture counts (from
// iga_gov_service_posture) and change counts (from iga_gov_service_outcome).
// Hour is truncated to the hour (CHECK).
type IGAGovMetricsHourly struct {
	WorkspaceID                  uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Hour                         time.Time `json:"hour" gorm:"primaryKey"`
	PostureRemoved               int       `json:"posture_removed" gorm:"not null;default:0"`
	PostureExcludedRoutesRemain  int       `json:"posture_excluded_routes_remain" gorm:"not null;default:0"`
	PostureExcludedRoutesUnknown int       `json:"posture_excluded_routes_unknown" gorm:"not null;default:0"`
	PosturePending               int       `json:"posture_pending" gorm:"not null;default:0"`
	ChangesNewlyExcluded         int       `json:"changes_newly_excluded" gorm:"not null;default:0"`
	ChangesNewlyUnexcluded       int       `json:"changes_newly_unexcluded" gorm:"not null;default:0"`
	RolesRightSized              int       `json:"roles_right_sized" gorm:"not null;default:0"`
	RolesEligible                int       `json:"roles_eligible" gorm:"not null;default:0"`
	ApprovalP50Seconds           *int      `json:"approval_p50_seconds,omitempty" gorm:"column:approval_p50_seconds"`
	ApprovalP95Seconds           *int      `json:"approval_p95_seconds,omitempty" gorm:"column:approval_p95_seconds"`
	ApprovalsPending             int       `json:"approvals_pending" gorm:"not null;default:0"`
	ApplyToVerifiedP95Seconds    *int      `json:"apply_to_verified_p95_seconds,omitempty" gorm:"column:apply_to_verified_p95_seconds"`
	UnexpectedFailures           int       `json:"unexpected_failures" gorm:"not null;default:0"`
	Undos                        int       `json:"undos" gorm:"not null;default:0"`
	ComputedAt                   time.Time `json:"computed_at" gorm:"not null;default:now()"`
}

func (IGAGovMetricsHourly) TableName() string { return "iga_gov_metrics_hourly" }

// IGAGovIaCSource maps an account's roles to a repository directory (J2).
type IGAGovIaCSource struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID       uuid.UUID       `json:"connector_id" gorm:"type:uuid;not null"`
	Format            string          `json:"format" gorm:"not null"`
	DiscoverySourceID uuid.UUID       `json:"discovery_source_id" gorm:"type:uuid;not null"`
	Repository        string          `json:"repository" gorm:"not null"`
	BaseBranch        string          `json:"base_branch" gorm:"not null;default:'main'"`
	Directory         string          `json:"directory" gorm:"not null"`
	RoleMatch         json.RawMessage `json:"role_match" gorm:"type:jsonb;not null;default:'{}'"`
	CreatedBy         uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt         time.Time       `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovIaCSource) TableName() string { return "iga_gov_iac_source" }

// IGAGovIaCChange is the pull request of one iac_pr deployment.
type IGAGovIaCChange struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	DeploymentID uuid.UUID  `json:"deployment_id" gorm:"type:uuid;not null"`
	SourceID     uuid.UUID  `json:"source_id" gorm:"type:uuid;not null"`
	Branch       string     `json:"branch" gorm:"not null"`
	PRNumber     *int       `json:"pr_number,omitempty" gorm:"column:pr_number"`
	PRURL        string     `json:"pr_url" gorm:"column:pr_url;not null;default:''"`
	ProposedSHA  string     `json:"proposed_sha" gorm:"column:proposed_sha;not null;default:''"`
	ReviewedSHA  string     `json:"reviewed_sha" gorm:"column:reviewed_sha;not null;default:''"`
	MergedSHA    string     `json:"merged_sha" gorm:"column:merged_sha;not null;default:''"`
	MergedAt     *time.Time `json:"merged_at,omitempty"`
	ApplyRunRef  string     `json:"apply_run_ref" gorm:"not null;default:''"`
	State        string     `json:"state" gorm:"not null;default:'opening'"`
	UpdatedAt    time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovIaCChange) TableName() string { return "iga_gov_iac_change" }

// IGAGovNotification is one outbound notice (email, webhook or Slack).
type IGAGovNotification struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	SubjectKind  string     `json:"subject_kind" gorm:"not null"`
	SubjectID    uuid.UUID  `json:"subject_id" gorm:"type:uuid;not null"`
	Channel      string     `json:"channel" gorm:"not null"`
	Recipient    string     `json:"recipient" gorm:"not null"`
	State        string     `json:"state" gorm:"not null;default:'pending'"`
	AttemptCount int        `json:"attempt_count" gorm:"not null;default:0"`
	LastError    string     `json:"last_error" gorm:"not null;default:''"`
	SlackTS      string     `json:"slack_ts" gorm:"column:slack_ts;not null;default:''"`
	LastActionTS string     `json:"last_action_ts" gorm:"column:last_action_ts;not null;default:''"`
	AvailableAt  time.Time  `json:"available_at" gorm:"not null;default:now()"`
	SentAt       *time.Time `json:"sent_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovNotification) TableName() string { return "iga_gov_notification" }

// IGAGovSettings is a workspace's Phase 3 configuration; absent means every
// default (findings_only, 90-day window, ...).
type IGAGovSettings struct {
	WorkspaceID            uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	EnforcementMode        string    `json:"enforcement_mode" gorm:"not null;default:'findings_only'"`
	DefaultWindowDays      int       `json:"default_window_days" gorm:"not null;default:90"`
	DefaultObservationDays int       `json:"default_observation_days" gorm:"not null;default:7"`
	OwnerReviewDays        int       `json:"owner_review_days" gorm:"not null;default:3"`
	ApprovalValidDays      int       `json:"approval_valid_days" gorm:"not null;default:7"`
	CanaryHours            int       `json:"canary_hours" gorm:"not null;default:48"`
	IaCApplyHours          int       `json:"iac_apply_hours" gorm:"column:iac_apply_hours;not null;default:24"`
	EvidenceRetentionRevs  int       `json:"evidence_retention_revs" gorm:"not null;default:30"`
	// Notification channels (055, p3-wire). READ-ONLY to GORM and never
	// serialised: services.GovDBChannelStore writes them (the webhook secret
	// itself is in Vault; NotifyWebhookSecretRef is its path), and GET
	// /settings reports them in its notifications block.
	NotifyEmailEnabled     bool       `json:"-" gorm:"column:notify_email_enabled;->"`
	NotifyWebhookURL       string     `json:"-" gorm:"column:notify_webhook_url;->"`
	NotifyWebhookSecretRef string     `json:"-" gorm:"column:notify_webhook_secret_ref;->"`
	NotifyChannelsSource   string     `json:"-" gorm:"column:notify_channels_source;->"`
	NotifyChannelsCopiedAt *time.Time `json:"-" gorm:"column:notify_channels_copied_at;->"`
	UpdatedBy              *uuid.UUID `json:"updated_by,omitempty" gorm:"type:uuid"`
	UpdatedAt              time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovSettings) TableName() string { return "iga_gov_settings" }

// DefaultIGAGovSettings is the row a workspace without settings behaves as:
// the column defaults of 055 (tests/igagovschema checks they agree).
func DefaultIGAGovSettings(ws uuid.UUID) IGAGovSettings {
	return IGAGovSettings{
		WorkspaceID:            ws,
		EnforcementMode:        GovModeFindingsOnly,
		DefaultWindowDays:      90,
		DefaultObservationDays: 7,
		OwnerReviewDays:        3,
		ApprovalValidDays:      7,
		CanaryHours:            48,
		IaCApplyHours:          24,
		EvidenceRetentionRevs:  30,
		NotifyEmailEnabled:     true,
		NotifyChannelsSource:   "default",
	}
}
