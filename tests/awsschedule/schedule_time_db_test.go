package awsschedule_test

// A chosen time of day for automatic rescans, against real Postgres. Same
// fixture and gate as schedule_db_test.go: set TEST_DATABASE_URL, or the suite
// skips.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/services"
)

func strp(s string) *string { return &s }
func intp(i int) *int       { return &i }

func (f *fixture) putTimed(
	t *testing.T, enabled bool, minutes int, timing *services.ScheduleTiming,
) (*services.ScanScheduleView, error) {
	t.Helper()
	after, _, err := f.sched.PutWithTiming(context.Background(), f.ws, f.id, enabled, &minutes, timing, "test")
	return after, err
}

func inZone(t *testing.T, name string, at *time.Time) time.Time {
	t.Helper()
	if at == nil {
		t.Fatal("next_due_at is NULL")
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return at.In(loc)
}

// minutesIntoDay is the local wall-clock time as minutes after midnight.
func minutesIntoDay(l time.Time) int { return l.Hour()*60 + l.Minute() }

// Choosing 02:30 in Asia/Kolkata puts the next scan at the next 02:30 there, up
// to 30 minutes later for the connector's jitter, not one interval from now.
func TestChosenTimeSetsTheNextScan(t *testing.T) {
	f := newFixture(t)
	view, err := f.putTimed(t, true, 1440, &services.ScheduleTiming{
		TimeOfDay: strp("02:30"), Timezone: strp("Asia/Kolkata"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if view.TimeOfDay == nil || *view.TimeOfDay != "02:30" || view.Timezone != "Asia/Kolkata" {
		t.Fatalf("view = %+v, want 02:30 Asia/Kolkata", view)
	}
	now := time.Now()
	due := f.row(t).NextDueAt
	l := inZone(t, "Asia/Kolkata", due)
	if m := minutesIntoDay(l); m < 150 || m >= 180 {
		t.Fatalf("next scan at %s local, want 02:30 to 03:00", l.Format("15:04"))
	}
	if !due.After(now) || due.After(now.Add(25*time.Hour)) {
		t.Fatalf("next scan %s is not within the next day", due.Format(time.RFC3339))
	}
}

// After the scheduler serves a slot, the next one is the next occurrence of the
// chosen time, a day later, not one interval from the moment it ran.
func TestSchedulerKeepsTheChosenTime(t *testing.T) {
	f := newFixture(t)
	if _, err := f.putTimed(t, true, 1440, &services.ScheduleTiming{
		TimeOfDay: strp("02:30"), Timezone: strp("Asia/Kolkata"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec(`UPDATE cloud_scan_schedule SET next_due_at = now() - interval '1 minute' WHERE connector_id = ?`, f.id).Error; err != nil {
		t.Fatal(err)
	}
	// Serve it at an hour that is NOT the chosen one, as a late or retried slot would be.
	at := time.Now().Add(time.Minute)
	if n := f.runAt(t, at); n != 1 {
		t.Fatalf("served %d schedules, want 1", n)
	}
	if total, _ := f.runs(t, "scheduled"); total != 1 {
		t.Fatalf("queued %d scheduled scans, want 1", total)
	}
	due := f.row(t).NextDueAt
	l := inZone(t, "Asia/Kolkata", due)
	if m := minutesIntoDay(l); m < 150 || m >= 180 {
		t.Fatalf("next scan at %s local, want 02:30 to 03:00", l.Format("15:04"))
	}
	if !due.After(at) || due.After(at.Add(25*time.Hour)) {
		t.Fatalf("next scan %s is not within a day of the run", due.Format(time.RFC3339))
	}
}

func TestWeeklyChosenTime(t *testing.T) {
	f := newFixture(t)
	if _, err := f.putTimed(t, true, 10080, &services.ScheduleTiming{
		TimeOfDay: strp("06:00"), Timezone: strp("Europe/London"), DayOfWeek: intp(3),
	}); err != nil {
		t.Fatal(err)
	}
	due := f.row(t).NextDueAt
	l := inZone(t, "Europe/London", due)
	if l.Weekday() != time.Wednesday {
		t.Fatalf("next scan is on a %s, want Wednesday", l.Weekday())
	}
	if m := minutesIntoDay(l); m < 360 || m >= 390 {
		t.Fatalf("next scan at %s local, want 06:00 to 06:30", l.Format("15:04"))
	}
	if due.After(time.Now().Add(8 * 24 * time.Hour)) {
		t.Fatalf("next scan %s is more than a week away", due.Format(time.RFC3339))
	}
}

func TestChosenTimeIsValidated(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name     string
		minutes  int
		timing   services.ScheduleTiming
		wantParm string
	}{
		{"not a quarter hour", 1440, services.ScheduleTiming{TimeOfDay: strp("02:10")}, "time_of_day"},
		{"not a time", 1440, services.ScheduleTiming{TimeOfDay: strp("25:00")}, "time_of_day"},
		{"unknown zone", 1440, services.ScheduleTiming{Timezone: strp("Mars/Base")}, "timezone"},
		{"server-local zone", 1440, services.ScheduleTiming{Timezone: strp("Local")}, "timezone"},
		{"weekday out of range", 10080, services.ScheduleTiming{TimeOfDay: strp("06:00"), DayOfWeek: intp(9)}, "day_of_week"},
		{"weekly time without a weekday", 10080, services.ScheduleTiming{TimeOfDay: strp("06:00")}, "day_of_week"},
	}
	for _, c := range cases {
		c := c
		_, err := f.putTimed(t, true, c.minutes, &c.timing)
		var pe *services.ScheduleParamError
		if !errors.As(err, &pe) || pe.Param != c.wantParm {
			t.Errorf("%s: err = %v, want a parameter error naming %s", c.name, err, c.wantParm)
		}
	}
	// Nothing was written by the refused requests.
	var n int
	if err := f.db.Raw(`SELECT count(*) FROM cloud_scan_schedule WHERE connector_id = ? AND time_of_day_minutes IS NOT NULL`, f.id).Row().Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a refused request still stored a time (%d rows)", n)
	}
	// The database refuses a time off the quarter hour as a second line of defence.
	f.put(t, true, 1440)
	if err := f.db.Exec(`UPDATE cloud_scan_schedule SET time_of_day_minutes = 7 WHERE connector_id = ?`, f.id).Error; err == nil {
		t.Fatal("the database accepted a time that is not on a quarter hour")
	}
}

// Changing only the chosen time moves the next scan but leaves the failure
// history alone: it is not a restart of the streak.
func TestChangingOnlyTheTimeKeepsTheFailureHistory(t *testing.T) {
	f := newFixture(t)
	if _, err := f.putTimed(t, true, 1440, &services.ScheduleTiming{
		TimeOfDay: strp("02:30"), Timezone: strp("UTC"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec(`UPDATE cloud_scan_schedule SET streak_since = now() - interval '2 days' WHERE connector_id = ?`, f.id).Error; err != nil {
		t.Fatal(err)
	}
	before := f.row(t)
	if _, err := f.putTimed(t, true, 1440, &services.ScheduleTiming{TimeOfDay: strp("14:00")}); err != nil {
		t.Fatal(err)
	}
	after := f.row(t)
	if after.StreakSince == nil || before.StreakSince == nil ||
		after.StreakSince.Sub(*before.StreakSince).Abs() > time.Second {
		t.Fatalf("streak_since moved from %v to %v; changing the time must not restart it", before.StreakSince, after.StreakSince)
	}
	l := inZone(t, "UTC", after.NextDueAt)
	if m := minutesIntoDay(l); m < 14*60 || m >= 14*60+30 {
		t.Fatalf("next scan at %s UTC, want 14:00 to 14:30", l.Format("15:04"))
	}
}

// A schedule that never chose a time behaves exactly as before.
func TestNoChosenTimeKeepsTheOldBehaviour(t *testing.T) {
	f := newFixture(t)
	view := f.put(t, true, 1440)
	if view.TimeOfDay != nil || view.Timezone != "UTC" || view.DayOfWeek != nil {
		t.Fatalf("view = %+v, want no chosen time and UTC", view)
	}
	now := time.Now()
	within(t, "next_due_at", f.row(t).NextDueAt, now.Add(24*time.Hour), now.Add(24*time.Hour+jitterMax))
}

// With no chosen time, a time zone (or a weekday) changes nothing: the next
// scan stays where it was, and the weekday is not stored unused.
func TestTimezoneWithoutTimeKeepsTheNextScan(t *testing.T) {
	f := newFixture(t)
	f.put(t, true, 10080)
	before := f.row(t).NextDueAt
	if _, err := f.putTimed(t, true, 10080, &services.ScheduleTiming{Timezone: strp("Asia/Kolkata"), DayOfWeek: intp(3)}); err != nil {
		t.Fatal(err)
	}
	r := f.row(t)
	if before == nil || r.NextDueAt == nil || !r.NextDueAt.Equal(*before) {
		t.Fatalf("next scan moved from %v to %v on a time-zone-only change", before, r.NextDueAt)
	}
	var dow *int
	if err := f.db.Raw(`SELECT day_of_week FROM cloud_scan_schedule WHERE connector_id = ?`, f.id).Scan(&dow).Error; err != nil {
		t.Fatal(err)
	}
	if dow != nil {
		t.Fatalf("day_of_week %d stored without a time of day", *dow)
	}
}
