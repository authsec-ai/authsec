package models

import (
	"time"

	"github.com/google/uuid"
)

// Limits and trigger labels for automatic AWS rescans.
const (
	// ScanScheduleMinIntervalMinutes is 6 hours. Hourly is deliberately not
	// offered: it multiplies AWS API cost and throttling for little gain until
	// event-driven refresh exists.
	ScanScheduleMinIntervalMinutes     = 360
	ScanScheduleMaxIntervalMinutes     = 10080 // 7 days
	ScanScheduleDefaultIntervalMinutes = 1440  // daily

	// CloudScanTriggerManual and CloudScanTriggerScheduled are the values of
	// cloud_scan_run.trigger.
	CloudScanTriggerManual    = "manual"
	CloudScanTriggerScheduled = "scheduled"
)

// CloudScanSchedule says when one AWS connector rescans itself. The scans it
// causes are ordinary cloud_scan_run rows with trigger "scheduled", run by the
// existing scan worker; this row only decides when one is queued.
//
// A missing row means "never scheduled", the same as Enabled = false.
type CloudScanSchedule struct {
	ConnectorID     uuid.UUID `json:"connector_id" gorm:"type:uuid;primaryKey"`
	WorkspaceID     uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	Enabled         bool      `json:"enabled" gorm:"not null;default:false"`
	IntervalMinutes int       `json:"interval_minutes" gorm:"not null;default:1440"`

	// TimeOfDayMinutes is the chosen time, in minutes after local midnight on a
	// quarter hour. Nil means no time was chosen: the schedule runs one interval
	// after it was turned on, as before. Timezone is the IANA zone the time is
	// read in. DayOfWeek (0 = Sunday) is used by weekly schedules.
	TimeOfDayMinutes *int   `json:"time_of_day_minutes,omitempty" gorm:"column:time_of_day_minutes"`
	Timezone         string `json:"timezone" gorm:"not null;default:UTC"`
	DayOfWeek        *int   `json:"day_of_week,omitempty" gorm:"column:day_of_week"`

	NextDueAt      *time.Time `json:"next_due_at,omitempty"`
	LastEnqueuedAt *time.Time `json:"last_enqueued_at,omitempty"`
	// StreakSince bounds which scheduled runs count toward pausing: runs
	// requested before it are ignored. Set when the schedule is turned on or
	// resumed.
	StreakSince *time.Time `json:"streak_since,omitempty"`

	// PausedReason is empty unless the scheduler paused the schedule after
	// repeated failures.
	PausedReason string `json:"paused_reason" gorm:"not null;default:''"`
	UpdatedBy    string `json:"updated_by" gorm:"not null;default:''"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (CloudScanSchedule) TableName() string { return "cloud_scan_schedule" }

// The only automatic-scan intervals offered: daily and weekly. The 360 and
// 10080 bounds above are what the database accepts; the API accepts only these.
const (
	ScanScheduleDailyMinutes  = 1440
	ScanScheduleWeeklyMinutes = 10080
)

// ScheduleIntervalAllowed reports whether an interval may be set.
func ScheduleIntervalAllowed(minutes int) bool {
	return minutes == ScanScheduleDailyMinutes || minutes == ScanScheduleWeeklyMinutes
}
