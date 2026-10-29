package services

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
)

// scheduler_active is deployment-wide evidence, not this process alone: a
// process without the loop does not say "not running" while the schedule is
// being served elsewhere; an overdue schedule says no scheduler serves it.
func TestScheduleViewSchedulerActive(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	cases := []struct {
		name    string
		s       *models.CloudScanSchedule
		running bool
		want    bool
	}{
		{"served elsewhere: not yet due", &models.CloudScanSchedule{Enabled: true, NextDueAt: at(time.Hour)}, false, true},
		{"served elsewhere: due a minute ago", &models.CloudScanSchedule{Enabled: true, NextDueAt: at(-time.Minute)}, false, true},
		{"nobody serves it: overdue", &models.CloudScanSchedule{Enabled: true, NextDueAt: at(-time.Hour)}, false, false},
		{"this process runs the loop", &models.CloudScanSchedule{Enabled: true, NextDueAt: at(-time.Hour)}, true, true},
		{"paused: not overdue", &models.CloudScanSchedule{Enabled: true, PausedReason: "x", NextDueAt: at(-time.Hour)}, false, true},
	}
	for _, c := range cases {
		if got := scheduleViewAt(c.s, now, c.running).SchedulerActive; got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
