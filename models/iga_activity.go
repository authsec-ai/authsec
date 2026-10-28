package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Event families classify the kind of runtime activity observed.
const (
	EventFamilyRuntimeOperation     = "runtime_operation"
	EventFamilyEnforcementLifecycle = "enforcement_lifecycle"
	EventFamilyApproval             = "approval"
	EventFamilyAdminPolicyChange    = "admin_policy_change"
)

// Activity phases mirror the collector contract's ActionDetail.Phase.
const (
	ActivityPhaseAttempt  = "attempt"
	ActivityPhaseExec     = "exec"
	ActivityPhaseComplete = "complete"
)

// Activity results mirror the collector contract's ActionDetail.Result.
const (
	ActivityResultSuccess = "success"
	ActivityResultDenied  = "denied"
	ActivityResultError   = "error"
	ActivityResultUnknown = "unknown"
)

// Mapping statuses track how far identity resolution has progressed.
const (
	MappingStatusUnmapped  = "unmapped"
	MappingStatusPartial   = "partial"
	MappingStatusMapped    = "mapped"
	MappingStatusConflict  = "conflict"
	MappingStatusManual    = "manual"
)

// IGARuntimeActivity is one projected runtime activity event, stored in the
// iga_runtime_activity table (migration 057). Each row is derived from a
// single collector observation and carries the canonical fields the Actions
// API serves.
//
// activity_sequence is a BIGSERIAL that provides a total order for
// cursor-based catch-up reads. action_id is the stable external identifier
// for idempotent dedup and API references.
type IGARuntimeActivity struct {
	ID                uuid.UUID       `json:"id"                   gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id"         gorm:"type:uuid;not null"`
	ActionID          uuid.UUID       `json:"action_id"            gorm:"type:uuid;not null"`
	CollectorID       uuid.UUID       `json:"collector_id"         gorm:"type:uuid;not null"`
	BatchID           uuid.UUID       `json:"batch_id"             gorm:"type:uuid;not null"`
	EventID           string          `json:"event_id"             gorm:"not null"`
	WorkloadID        *uuid.UUID      `json:"workload_id,omitempty"          gorm:"type:uuid"`
	RuntimeInstanceID *uuid.UUID      `json:"runtime_instance_id,omitempty"  gorm:"type:uuid"`
	IdentityAccountID *uuid.UUID      `json:"identity_account_id,omitempty"  gorm:"type:uuid"`
	ResourceID        *uuid.UUID      `json:"resource_id,omitempty"          gorm:"type:uuid"`
	EventFamily       string          `json:"event_family"         gorm:"not null"`
	Operation         string          `json:"operation,omitempty"`
	Phase             string          `json:"phase,omitempty"`
	Result            string          `json:"result,omitempty"`
	Outcome           string          `json:"outcome"              gorm:"not null"`
	Source            string          `json:"source,omitempty"`
	Attribution       string          `json:"attribution,omitempty"`
	Provenance        json.RawMessage `json:"provenance,omitempty" gorm:"type:jsonb"`
	PolicyRef         *uuid.UUID      `json:"policy_ref,omitempty"           gorm:"type:uuid"`
	ControlRef        string          `json:"control_ref,omitempty"`
	RuleRef           string          `json:"rule_ref,omitempty"`
	ObservedAt        time.Time       `json:"observed_at"          gorm:"not null"`
	ReceivedAt        time.Time       `json:"received_at"          gorm:"not null;default:now()"`
	IndexedAt         time.Time       `json:"indexed_at"           gorm:"not null;default:now()"`
	Count             int             `json:"count"                gorm:"not null;default:1"`
	Aggregation       string          `json:"aggregation,omitempty"`
	MappingStatus     string          `json:"mapping_status"       gorm:"not null;default:'unmapped'"`
	ActivityVersion   int             `json:"activity_version"     gorm:"not null;default:1"`
	ActivitySequence  int64           `json:"activity_sequence"    gorm:"autoIncrement"`
	RetainedUntil     *time.Time      `json:"retained_until,omitempty"`
}

func (IGARuntimeActivity) TableName() string { return "iga_runtime_activity" }
