// Package scanslot works out WHEN an automatic scan is due once an
// administrator has chosen a time of day (and, for weekly, a weekday) in a
// timezone. It is pure: no database, no clock, no AWS. The scheduler and the
// schedule service both call it, and it is tested on its own, including
// daylight-saving days.
//
// A schedule without a chosen time keeps the older behaviour (one interval
// after it was turned on) and never reaches this package.
package scanslot

import (
	"fmt"
	"strings"
	"time"

	// Embed the timezone database so a named zone resolves on every host, in
	// the container image and on a Windows developer machine alike.
	_ "time/tzdata"
)

// StepMinutes is the granularity of the time picker. Slots are quarter hours.
const StepMinutes = 15

const (
	day  = 24 * time.Hour
	week = 7 * day
)

// Spec is a chosen schedule: scan every Interval at TimeOfDay local time in
// Location, and, when the interval is a week or longer, on Weekday.
type Spec struct {
	Interval time.Duration
	// TimeOfDay is minutes after local midnight, 0..1439.
	TimeOfDay int
	Location  *time.Location
	// Weekday applies only when Interval >= one week.
	Weekday time.Weekday
}

// ParseTimeOfDay reads "HH:MM" (24 hour) and returns minutes after midnight.
// Only quarter hours are accepted.
func ParseTimeOfDay(s string) (int, error) {
	s = strings.TrimSpace(s)
	var h, m int
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("time_of_day must look like 02:30")
	}
	if _, err := fmt.Sscanf(s, "%02d:%02d", &h, &m); err != nil {
		return 0, fmt.Errorf("time_of_day must look like 02:30")
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("time_of_day must be between 00:00 and 23:45")
	}
	if m%StepMinutes != 0 {
		return 0, fmt.Errorf("time_of_day must be on a quarter hour (:00, :15, :30, :45)")
	}
	return h*60 + m, nil
}

// FormatTimeOfDay is the inverse of ParseTimeOfDay.
func FormatTimeOfDay(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/60, minutes%60)
}

// LoadLocation resolves an IANA zone name such as "Asia/Kolkata". An empty name
// is UTC. "Local" is refused: it would mean the server's zone, not the
// administrator's.
func LoadLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return time.UTC, nil
	}
	if strings.EqualFold(name, "local") {
		return nil, fmt.Errorf("timezone must be a named zone such as Europe/London")
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("timezone %q is not a known zone", name)
	}
	return loc, nil
}

// NextDue returns the first due time strictly after `after`: a slot's wall-clock
// time plus `jitter`. The jitter is the scheduler's stable per-connector offset
// (at most 30 minutes), so connectors that chose the same time do not all hit
// AWS in the same second.
//
// Slots are whole local days, so a clock change never makes a day run twice or
// not at all: a time that does not exist on the day clocks go forward runs
// shortly after the gap, and a time that occurs twice when clocks go back runs
// once.
func NextDue(s Spec, after time.Time, jitter time.Duration) time.Time {
	loc := s.Location
	if loc == nil {
		loc = time.UTC
	}
	weekly := s.Interval >= week
	h, m := s.TimeOfDay/60, s.TimeOfDay%60

	// Start a day early: the jitter can carry the previous day's slot past
	// midnight, and `after` is an instant, not a local date.
	y, mo, d := after.In(loc).Date()
	first := time.Date(y, mo, d, 12, 0, 0, 0, loc).AddDate(0, 0, -1)

	// 15 days is more than enough: the next weekly slot is at most 7 days away.
	for i := 0; i < 15; i++ {
		date := first.AddDate(0, 0, i)
		if weekly && date.Weekday() != s.Weekday {
			continue
		}
		cy, cm, cd := date.Date()
		due := slotOn(cy, cm, cd, h, m, loc).Add(jitter)
		if due.After(after) {
			return due
		}
	}
	// Unreachable for a valid Spec. Fail towards running soon, not never.
	return after.Add(time.Hour)
}

// slotOn is the instant of h:m on the given local date. On an ordinary day that
// is just time.Date. When clocks go forward and h:m does not exist that day,
// time.Date answers with an instant BEFORE the gap (and, for a time just after
// midnight, on the previous date), which would run the slot early and give the
// previous day two scans. So a slot that lands before its own wall-clock time
// is moved forward, a quarter hour at a time, to the first instant that is at or
// after it: the end of the gap.
func slotOn(y int, mo time.Month, d, h, m int, loc *time.Location) time.Time {
	t := time.Date(y, mo, d, h, m, 0, 0, loc)
	want := h*60 + m
	for i := 0; i < 12; i++ { // a gap is at most a couple of hours
		ly, lmo, ld := t.In(loc).Date()
		if ly == y && lmo == mo && ld == d {
			lt := t.In(loc)
			if lt.Hour()*60+lt.Minute() >= want {
				return t
			}
		} else if time.Date(ly, lmo, ld, 12, 0, 0, 0, loc).After(time.Date(y, mo, d, 12, 0, 0, 0, loc)) {
			return t
		}
		t = t.Add(StepMinutes * time.Minute)
	}
	return t
}
