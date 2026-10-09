package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Scan run lifecycle.
//
// queued and running are the only states a worker may claim. The three terminal
// states are distinct on purpose: a scan that finished with unreadable
// repositories SUCCEEDED (it did everything it was able to) and reports
// Complete=false; a scan that could not start at all FAILED. Collapsing the two
// would make "failed" mean both "we hit a permission wall on one repo" and "we
// never reached GitHub", which are different problems for whoever is on call.
const (
	ScanRunQueued    = "queued"
	ScanRunRunning   = "running"
	ScanRunSucceeded = "succeeded"
	ScanRunFailed    = "failed"
	ScanRunCancelled = "cancelled"
)

// Branch coverage modes.
//
// BranchModeDefault reads only each repository's default branch — the branch
// whose contents are actually in effect. BranchModeAll additionally reads other
// refs, where a declaration may be proposed but not yet merged, and is
// therefore WEAKER evidence. The distinction is carried through to every
// finding so a reviewer is never shown an unmerged proposal as though it were
// live configuration.
const (
	BranchModeDefault = "default"
	BranchModeAll     = "all"
)

// DefaultMaxBranchesPerRepo caps all-branch scanning.
//
// A long-lived repository accumulates hundreds of stale refs, and each one
// costs a tree listing. Without a ceiling, enabling all-branch mode on a large
// estate turns one scan into tens of thousands of API calls and exhausts the
// installation's rate limit for every other caller. Branches beyond the cap are
// COUNTED and force complete=false rather than being dropped quietly.
const DefaultMaxBranchesPerRepo = 20

// DiscoveryScanRun is one GitHub scan: its plan, its progress, its result, and
// its position in the queue.
//
// The same row serves all four roles. See 007_discovery_scan_runs.sql for why
// the queue and the report are deliberately not separate tables.
type DiscoveryScanRun struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SourceID    uuid.UUID `json:"source_id" gorm:"type:uuid;not null;index"`

	Status string `json:"status" gorm:"not null;default:'queued'"`

	// The plan as it stood when the scan was queued. Read these, not the live
	// source config, when interpreting a finished run: the config may have
	// changed since.
	SelectionMode string `json:"selection_mode" gorm:"not null;default:''"`
	BranchMode    string `json:"branch_mode" gorm:"not null;default:'default'"`
	MaxBranches   int    `json:"max_branches" gorm:"not null;default:0"`

	ReposSelected   int `json:"repos_selected" gorm:"not null;default:0"`
	ReposScanned    int `json:"repos_scanned" gorm:"not null;default:0"`
	ReposFailed     int `json:"repos_failed" gorm:"not null;default:0"`
	ReposExcluded   int `json:"repos_excluded" gorm:"not null;default:0"`
	ReposTruncated  int `json:"repos_truncated" gorm:"not null;default:0"`
	BranchesScanned int `json:"branches_scanned" gorm:"not null;default:0"`
	// BranchesSkipped counts refs we know exist and did not read, because
	// MaxBranches cut them off. Non-zero always forces Complete=false.
	BranchesSkipped int `json:"branches_skipped" gorm:"not null;default:0"`
	FilesFetched    int `json:"files_fetched" gorm:"not null;default:0"`
	// FilesFailed counts files that could not be read inside repositories that
	// opened fine. Separate from ReposFailed so a console never shows "0
	// failed" next to a list of unreadable files.
	FilesFailed     int `json:"files_failed" gorm:"not null;default:0"`
	SightingsNew    int `json:"sightings_new" gorm:"not null;default:0"`
	SightingsBumped int `json:"sightings_bumped" gorm:"not null;default:0"`

	// Complete is complete_for_selected_scope: every selected repository, and
	// every branch the plan asked for, was read in full. It is not a synonym for
	// "no error occurred".
	//
	// Only meaningful once Status is succeeded — the database refuses it
	// otherwise, so that a queued or failed run can never be read as an
	// authoritative all-clear.
	Complete bool `json:"complete_for_selected_scope" gorm:"not null;default:false"`

	// Degraded is the monotonic "we know we missed something": set the first
	// time a unit is unreadable, a tree is truncated, or the branch cap bites,
	// and never cleared. It survives a resume, which Complete cannot, and
	// Complete is derived from it when the run finishes.
	Degraded bool `json:"degraded" gorm:"not null;default:false"`

	ExcludedRepositories json.RawMessage `json:"excluded_repositories" gorm:"type:jsonb;not null;default:'[]'"`
	Warnings             json.RawMessage `json:"warnings" gorm:"type:jsonb;not null;default:'[]'"`
	Error                string          `json:"error" gorm:"not null;default:''"`

	// Cursor records finished units so a retry resumes. Shape: {"done":[...]}.
	Cursor json.RawMessage `json:"-" gorm:"type:jsonb;not null;default:'{}'"`

	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	MaxAttempts int        `json:"max_attempts" gorm:"not null;default:3"`
	LeasedBy    string     `json:"-" gorm:"not null;default:''"`
	LeasedUntil *time.Time `json:"-"`
	HeartbeatAt *time.Time `json:"heartbeat_at,omitempty"`

	RequestedBy string     `json:"requested_by" gorm:"not null;default:''"`
	QueuedAt    time.Time  `json:"queued_at" gorm:"not null;default:now()"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// TableName pins the table; GORM's pluraliser would otherwise guess.
func (DiscoveryScanRun) TableName() string { return "discovery_scan_runs" }

// Terminal reports whether the run has stopped moving. The console polls until
// this is true.
func (r *DiscoveryScanRun) Terminal() bool {
	return r.Status == ScanRunSucceeded || r.Status == ScanRunFailed || r.Status == ScanRunCancelled
}

// ScanCursor is the resume state: the units this run has already finished.
//
// A unit is "owner/name@branch". Storing finished units rather than an index
// into the repository list is what makes resume correct when the list itself
// changes between attempts — a repository added or removed on GitHub shifts
// every index after it, but a unit key still identifies the same work.
type ScanCursor struct {
	Done []string `json:"done"`
}
