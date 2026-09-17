package models

import (
	"time"

	"github.com/google/uuid"
)

// Scan run lifecycle. Only Published is authoritative: it is the state that
// says a pass finished and reconciled, and therefore the only one a reader may
// treat as "this inventory is current".
// Prefixed because the GitHub discovery pipeline already owns ScanRun* with a
// different vocabulary (it has `succeeded` and `cancelled`, and no publication
// step). Two pipelines, two lifecycles, no shared constants to confuse them.
const (
	CloudScanRunQueued    = "queued"
	CloudScanRunRunning   = "running"
	CloudScanRunPublished = "published"
	CloudScanRunFailed    = "failed"
	// CloudScanRunAbandoned is a run whose lease expired and which another run
	// superseded. Distinct from failed: nothing went wrong with the work, the
	// worker simply stopped existing.
	CloudScanRunAbandoned = "abandoned"
)

// CloudScanRun is one AWS scan attempt.
//
// It exists so a scan is a durable thing with an owner rather than a goroutine
// nobody can see. Three properties come from that and nothing else provides
// them: a restart can resume the run, two requests cannot walk the same account
// at once, and a worker that lost its lease cannot publish stale results over
// fresher ones.
type CloudScanRun struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`

	// Generation is 0 until a worker claims the run. A queued run has not
	// earned one: reconciliation reads generations as evidence that a pass
	// happened, so handing one to a run that never starts would be a lie the
	// deletion logic believes.
	Generation int    `json:"generation" gorm:"not null;default:0"`
	Status     string `json:"status" gorm:"not null;default:'queued'"`
	Trigger    string `json:"trigger" gorm:"not null;default:'manual'"`

	// LeaseOwner is the worker holding this run; "" when nobody does.
	LeaseOwner     string     `json:"lease_owner" gorm:"not null;default:''"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	// LeaseVersion is the fence token. A worker records the value it claimed
	// and publication demands the row still carries it, so a worker that
	// paused past its expiry is refused without anyone trusting a clock.
	LeaseVersion int64 `json:"lease_version" gorm:"not null;default:0"`

	Attempts  int    `json:"attempts" gorm:"not null;default:0"`
	LastError string `json:"last_error" gorm:"not null;default:''"`

	RequestedAt time.Time  `json:"requested_at" gorm:"not null;default:now()"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (CloudScanRun) TableName() string { return "cloud_scan_run" }

// Live reports whether this run still occupies the connector — the state the
// unique index enforces one of.
func (r CloudScanRun) Live() bool {
	return r.Status == CloudScanRunQueued || r.Status == CloudScanRunRunning
}

// Terminal reports whether the run has finished, however it finished.
func (r CloudScanRun) Terminal() bool { return !r.Live() }

// LeaseExpired reports whether this run's lease has lapsed as of now.
//
// Advisory only. It answers "should a worker try to reclaim this?", never "may
// this worker publish?" — that question is settled by the fence token in the
// UPDATE's WHERE clause, where no clock is consulted.
func (r CloudScanRun) LeaseExpired(now time.Time) bool {
	return r.LeaseExpiresAt == nil || !r.LeaseExpiresAt.After(now)
}
