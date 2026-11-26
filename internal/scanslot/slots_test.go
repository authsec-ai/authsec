package scanslot

import (
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := LoadLocation(name)
	if err != nil {
		t.Fatalf("LoadLocation(%q): %v", name, err)
	}
	return loc
}

func TestParseTimeOfDay(t *testing.T) {
	good := map[string]int{"00:00": 0, "02:30": 150, "23:45": 1425, "09:15": 555}
	for in, want := range good {
		got, err := ParseTimeOfDay(in)
		if err != nil || got != want {
			t.Errorf("ParseTimeOfDay(%q) = %d, %v; want %d", in, got, err, want)
		}
		if FormatTimeOfDay(got) != in {
			t.Errorf("FormatTimeOfDay(%d) = %q; want %q", got, FormatTimeOfDay(got), in)
		}
	}
	for _, in := range []string{"", "2:30", "24:00", "12:60", "12:10", "ab:cd", "12:30:00", "12-30", "-1:00"} {
		if _, err := ParseTimeOfDay(in); err == nil {
			t.Errorf("ParseTimeOfDay(%q) accepted; want an error", in)
		}
	}
}

func TestLoadLocation(t *testing.T) {
	if loc, err := LoadLocation(""); err != nil || loc != time.UTC {
		t.Errorf("empty name should be UTC, got %v, %v", loc, err)
	}
	for _, name := range []string{"Asia/Kolkata", "Europe/London", "America/New_York", "UTC"} {
		if _, err := LoadLocation(name); err != nil {
			t.Errorf("LoadLocation(%q): %v", name, err)
		}
	}
	for _, name := range []string{"Local", "local", "Mars/Olympus", "../etc/passwd", "IST5"} {
		if _, err := LoadLocation(name); err == nil {
			t.Errorf("LoadLocation(%q) accepted; want an error", name)
		}
	}
}

func TestDailyNextSlotSameDayAndNextDay(t *testing.T) {
	loc := mustLoc(t, "Asia/Kolkata") // +05:30, no daylight saving
	s := Spec{Interval: day, TimeOfDay: 2*60 + 30, Location: loc}

	// Before 02:30 local: today's slot.
	after := time.Date(2026, 10, 20, 1, 0, 0, 0, loc)
	if got, want := NextDue(s, after, 0), time.Date(2026, 10, 20, 2, 30, 0, 0, loc); !got.Equal(want) {
		t.Errorf("before slot: got %v want %v", got, want)
	}
	// After 02:30 local: tomorrow's.
	after = time.Date(2026, 10, 20, 3, 0, 0, 0, loc)
	if got, want := NextDue(s, after, 0), time.Date(2026, 10, 21, 2, 30, 0, 0, loc); !got.Equal(want) {
		t.Errorf("after slot: got %v want %v", got, want)
	}
	// Exactly on the slot: strictly after, so tomorrow (a slot is never served twice).
	after = time.Date(2026, 10, 20, 2, 30, 0, 0, loc)
	if got, want := NextDue(s, after, 0), time.Date(2026, 10, 21, 2, 30, 0, 0, loc); !got.Equal(want) {
		t.Errorf("on slot: got %v want %v", got, want)
	}
}

func TestJitterIsAfterTheChosenTime(t *testing.T) {
	loc := mustLoc(t, "UTC")
	s := Spec{Interval: day, TimeOfDay: 120, Location: loc}
	jit := 17*time.Minute + 9*time.Second
	after := time.Date(2026, 10, 20, 0, 0, 0, 0, loc)
	got := NextDue(s, after, jit)
	if want := time.Date(2026, 10, 20, 2, 17, 9, 0, loc); !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
	// Served at the jittered time: the next one is tomorrow, not a repeat.
	got2 := NextDue(s, got, jit)
	if want := time.Date(2026, 10, 21, 2, 17, 9, 0, loc); !got2.Equal(want) {
		t.Errorf("after serving: got %v want %v", got2, want)
	}
}

// The previous day's slot, carried past midnight by jitter, is still ahead of
// `after`: it must not be skipped.
func TestJitterPastMidnight(t *testing.T) {
	loc := mustLoc(t, "UTC")
	s := Spec{Interval: day, TimeOfDay: 23*60 + 45, Location: loc}
	jit := 25 * time.Minute // slot 23:45 -> due 00:10 the next day
	after := time.Date(2026, 10, 21, 0, 5, 0, 0, loc)
	got := NextDue(s, after, jit)
	if want := time.Date(2026, 10, 21, 0, 10, 0, 0, loc); !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestWeeklyUsesTheChosenWeekday(t *testing.T) {
	loc := mustLoc(t, "Europe/London")
	s := Spec{Interval: week, TimeOfDay: 6 * 60, Location: loc, Weekday: time.Wednesday}
	// Tue 2026-10-20 -> Wed 2026-10-21 06:00.
	after := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)
	if got, want := NextDue(s, after, 0), time.Date(2026, 10, 21, 6, 0, 0, 0, loc); !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
	// Wed after 06:00 -> the following Wed.
	after = time.Date(2026, 10, 21, 7, 0, 0, 0, loc)
	if got, want := NextDue(s, after, 0), time.Date(2026, 10, 28, 6, 0, 0, 0, loc); !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
	for i := 0; i < 400; i++ {
		after = time.Date(2026, 1, 1, 0, 0, 0, 0, loc).Add(time.Duration(i) * 17 * time.Hour)
		got := NextDue(s, after, 0).In(loc)
		if got.Weekday() != time.Wednesday || got.Hour() != 6 || got.Minute() != 0 {
			t.Fatalf("after %v: got %v, not Wednesday 06:00", after, got)
		}
		if !got.After(after) || got.Sub(after) > week {
			t.Fatalf("after %v: got %v, not within the next week", after, got)
		}
	}
}

// Walk a whole year in several zones, one scan per slot, and prove: every local
// day gets exactly one scan, at the chosen wall-clock time, and no gap is
// shorter than 23h or longer than 25h.
func TestEveryLocalDayRunsOnceAcrossDaylightSaving(t *testing.T) {
	zones := []string{
		"UTC", "Asia/Kolkata", "Europe/London", "America/New_York",
		"Australia/Lord_Howe", // 30-minute daylight saving
		"Australia/Sydney", "America/Sao_Paulo", "Pacific/Auckland",
	}
	times := []int{0, 60, 120, 150, 180, 23*60 + 45}
	for _, zone := range zones {
		loc := mustLoc(t, zone)
		for _, tod := range times {
			s := Spec{Interval: day, TimeOfDay: tod, Location: loc}
			cur := time.Date(2018, 1, 1, 0, 0, 0, 0, loc)
			seen := map[string]int{}
			var prev time.Time
			for n := 0; n < 3*366; n++ {
				due := NextDue(s, cur, 0)
				if !due.After(cur) {
					t.Fatalf("%s %s: due %v not after %v", zone, FormatTimeOfDay(tod), due, cur)
				}
				if !prev.IsZero() {
					if gap := due.Sub(prev); gap < 23*time.Hour || gap > 25*time.Hour {
						t.Fatalf("%s %s: gap %v between %v and %v", zone, FormatTimeOfDay(tod), gap, prev, due)
					}
				}
				seen[due.In(loc).Format("2006-01-02")]++
				prev, cur = due, due
			}
			for date, n := range seen {
				if n != 1 {
					t.Fatalf("%s %s: %s ran %d times", zone, FormatTimeOfDay(tod), date, n)
				}
			}
			if len(seen) != 3*366 {
				t.Fatalf("%s %s: %d distinct days for %d scans (a day was skipped)",
					zone, FormatTimeOfDay(tod), len(seen), 3*366)
			}
		}
	}
}

// The wall-clock time holds on ordinary days on both sides of a clock change.
func TestWallClockTimeHoldsAcrossDaylightSaving(t *testing.T) {
	loc := mustLoc(t, "America/New_York")
	s := Spec{Interval: day, TimeOfDay: 9 * 60, Location: loc}
	for _, d := range []time.Time{
		time.Date(2026, 3, 7, 12, 0, 0, 0, loc),
		time.Date(2026, 3, 9, 12, 0, 0, 0, loc),
		time.Date(2026, 10, 31, 12, 0, 0, 0, loc),
		time.Date(2026, 11, 2, 12, 0, 0, 0, loc),
	} {
		got := NextDue(s, d, 0).In(loc)
		if got.Hour() != 9 || got.Minute() != 0 {
			t.Errorf("after %v: next slot %v is not 09:00 local", d, got)
		}
	}
}

// A chosen time that does not exist on the day clocks go forward (02:30 on
// 2026-03-08 in New York) still runs that day, shortly after the gap, once.
func TestNonexistentLocalTimeStillRunsOnce(t *testing.T) {
	loc := mustLoc(t, "America/New_York")
	s := Spec{Interval: day, TimeOfDay: 2*60 + 30, Location: loc}
	after := time.Date(2026, 3, 8, 0, 30, 0, 0, loc)
	got := NextDue(s, after, 0).In(loc)
	if got.Format("2006-01-02") != "2026-03-08" {
		t.Fatalf("got %v; want a slot on 2026-03-08", got)
	}
	if got.Hour() < 2 || got.Hour() > 3 {
		t.Errorf("got %v; want shortly after the gap", got)
	}
	next := NextDue(s, got, 0).In(loc)
	if next.Format("2006-01-02") != "2026-03-09" || next.Hour() != 2 || next.Minute() != 30 {
		t.Errorf("next after the gap day: got %v; want 2026-03-09 02:30", next)
	}
}

// A time that occurs twice when clocks go back (01:30 on 2026-11-01 in New
// York) runs once.
func TestRepeatedLocalTimeRunsOnce(t *testing.T) {
	loc := mustLoc(t, "America/New_York")
	s := Spec{Interval: day, TimeOfDay: 60 + 30, Location: loc}
	cur := time.Date(2026, 10, 31, 12, 0, 0, 0, loc)
	var runs []time.Time
	for i := 0; i < 4; i++ {
		due := NextDue(s, cur, 0)
		runs = append(runs, due)
		cur = due
	}
	count := 0
	for _, r := range runs {
		if r.In(loc).Format("2006-01-02") == "2026-11-01" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("2026-11-01 ran %d times: %v", count, runs)
	}
}

// After an outage the next slot is the next FUTURE slot: one catch-up run, not a
// replay of every missed day.
func TestNextSlotAfterAnOutageIsInTheFuture(t *testing.T) {
	loc := mustLoc(t, "Asia/Kolkata")
	s := Spec{Interval: day, TimeOfDay: 120, Location: loc}
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, loc) // served 5 days late
	got := NextDue(s, now, 0)
	if want := time.Date(2026, 10, 21, 2, 0, 0, 0, loc); !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
}
