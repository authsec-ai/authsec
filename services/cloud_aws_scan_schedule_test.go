package services

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// The pure decisions of automatic rescans: where a connector lands in the day,
// when the next slot is, and when a failing schedule pauses. The database and
// scheduler loop are covered where a Postgres is available.

func TestScheduleJitter_StableAndBounded(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	for _, interval := range []time.Duration{6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour} {
		j1 := scheduleJitter(id, interval)
		j2 := scheduleJitter(id, interval)
		if j1 != j2 {
			t.Fatalf("jitter is not stable for %v: %v then %v", interval, j1, j2)
		}
		window := interval / 10
		if window > schedMaxJitter {
			window = schedMaxJitter
		}
		if j1 < 0 || j1 >= window {
			t.Fatalf("jitter %v outside [0, %v) for interval %v", j1, window, interval)
		}
	}
}

func TestScheduleJitter_SpreadsConnectors(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[scheduleJitter(uuid.New(), 24*time.Hour)] = true
	}
	// 200 random connectors over a 30-minute window in seconds: all landing on
	// a handful of values would mean the hash is not spreading them.
	if len(seen) < 100 {
		t.Fatalf("only %d distinct offsets for 200 connectors", len(seen))
	}
}

func TestNextDueAfter(t *testing.T) {
	now := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	jitter := 10 * time.Minute

	t.Run("on time anchors on the previous slot, no drift", func(t *testing.T) {
		prev := now.Add(-2 * time.Minute) // served 2 minutes late
		got := nextDueAfter(prev, now, day, jitter)
		if want := prev.Add(day); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("a whole interval late starts over from now, with jitter", func(t *testing.T) {
		prev := now.Add(-3 * day) // outage
		got := nextDueAfter(prev, now, day, jitter)
		if want := now.Add(day + jitter); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("no previous slot starts from now, with jitter", func(t *testing.T) {
		got := nextDueAfter(time.Time{}, now, day, jitter)
		if want := now.Add(day + jitter); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("the next slot is always in the future", func(t *testing.T) {
		for _, late := range []time.Duration{0, time.Minute, 23 * time.Hour, 24 * time.Hour, 5 * day} {
			if got := nextDueAfter(now.Add(-late), now, day, jitter); !got.After(now) {
				t.Fatalf("late=%v: next slot %v is not after now %v", late, got, now)
			}
		}
	})
}

func runWith(status string) models.CloudScanRun { return models.CloudScanRun{Status: status} }

func TestShouldPause(t *testing.T) {
	f, a, p, q := models.CloudScanRunFailed, models.CloudScanRunAbandoned,
		models.CloudScanRunPublished, models.CloudScanRunQueued
	cases := []struct {
		name string
		runs []models.CloudScanRun
		want bool
	}{
		{"no runs", nil, false},
		{"two failures is not enough", []models.CloudScanRun{runWith(f), runWith(f)}, false},
		{"three failures", []models.CloudScanRun{runWith(f), runWith(f), runWith(f)}, true},
		{"failed and abandoned both count", []models.CloudScanRun{runWith(a), runWith(f), runWith(a)}, true},
		{"a published run in the window means it works", []models.CloudScanRun{runWith(f), runWith(p), runWith(f)}, false},
		{"a run still queued means it has not failed yet", []models.CloudScanRun{runWith(q), runWith(f), runWith(f)}, false},
		{"only the newest three decide", []models.CloudScanRun{runWith(f), runWith(f), runWith(f), runWith(p)}, true},
	}
	for _, c := range cases {
		if got := shouldPause(c.runs); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPauseReason(t *testing.T) {
	if got := pauseReason(models.CloudScanRun{}); got != "repeated_failures" {
		t.Fatalf("empty error: got %q", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	got := pauseReason(models.CloudScanRun{LastError: string(long)})
	if len(got) > len("repeated_failures: ")+200 {
		t.Fatalf("reason not capped: %d chars", len(got))
	}
}

func TestSchedulerActiveFollowsTheRunningLoop(t *testing.T) {
	t.Cleanup(func() { schedulerRunning.Store(false) })
	schedulerRunning.Store(false)
	if scheduleViewOf(nil).SchedulerActive {
		t.Fatal("not running must read as inactive")
	}
	schedulerRunning.Store(true)
	if !scheduleViewOf(nil).SchedulerActive {
		t.Fatal("running must read as active")
	}
}
