package models

import (
	"testing"
	"time"
)

// Staleness means the OPPOSITE thing in the two evidence modes, and this is the
// test that pins it.
//
//	a workflow file untouched for six months is STABLE
//	a pod unseen for six months is GONE
//
// Same elapsed time, opposite meaning. Treating them identically makes a stale
// badge actively misleading on half the inventory — and the half it misleads on
// is the half a customer is most likely to act on.
func TestStalenessBranchesOnEvidenceMode(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour // a 30-day freshness window

	sixMonthsAgo := now.Add(-180 * 24 * time.Hour)
	yesterday := now.Add(-24 * time.Hour)

	cases := []struct {
		name      string
		mode      string
		lastSeen  time.Time
		wantStale bool
		why       string
	}{
		{
			name: "declared and old is STABLE", mode: EvidenceDeclared,
			lastSeen: sixMonthsAgo, wantStale: false,
			why: "nobody was expected to touch the file. An untouched declaration " +
				"is a settled one, not a disappearing one",
		},
		{
			name: "observed and old is GONE", mode: EvidenceObserved,
			lastSeen: sixMonthsAgo, wantStale: true,
			why: "a collector that stopped seeing a workload is telling us " +
				"something: absence of a sighting is meaningful here",
		},
		{
			name: "declared and recent is still not stale", mode: EvidenceDeclared,
			lastSeen: yesterday, wantStale: false,
			why: "a declaration never goes stale on elapsed time alone",
		},
		{
			name: "observed and recent is fresh", mode: EvidenceObserved,
			lastSeen: yesterday, wantStale: false,
			why: "inside the freshness window",
		},
		{
			name: "inferred follows observed", mode: EvidenceInferred,
			lastSeen: sixMonthsAgo, wantStale: true,
			why: "an inference drawn from signal that stopped arriving has expired",
		},
		{
			name: "an unknown mode fails toward stale", mode: "something-new",
			lastSeen: sixMonthsAgo, wantStale: true,
			why: "for something we cannot classify, 'possibly gone' is the safer " +
				"error than 'definitely fine'",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := DiscoveredAgent{EvidenceMode: c.mode, LastSeenAt: c.lastSeen}
			if got := a.IsStale(now, window); got != c.wantStale {
				t.Fatalf("expected stale=%v, got %v\nwhy: %s", c.wantStale, got, c.why)
			}
			t.Logf("PASS: %s", c.why)
		})
	}
}

// A declared row's runtime timestamp is NULL, and that NULL is the answer.
//
// Anything in a UI implying liveness must read LastObservedRunningAt and never
// LastSeenAt. This test states the distinction in code so the two fields cannot
// quietly become interchangeable.
func TestDeclaredRowHasNoRuntimeObservation(t *testing.T) {
	seen := time.Date(2026, 8, 25, 11, 58, 0, 0, time.UTC)

	declared := DiscoveredAgent{
		EvidenceMode:     EvidenceDeclared,
		LastSeenAt:       seen, // we read the file two minutes ago
		DeploymentOrigin: DeploymentOriginUnknown,
	}
	if declared.LastObservedRunningAt != nil {
		t.Fatal("a declared row must carry no runtime observation")
	}
	if declared.DeploymentOrigin != DeploymentOriginUnknown {
		t.Fatalf("a declaration does not establish how anything was deployed, got %q",
			declared.DeploymentOrigin)
	}
	// The trap this guards: last_seen_at is recent, so a UI reading THAT column
	// would render "nightly-audit | 2 min ago" and every human would read a
	// live process. It is a file.
	if declared.LastSeenAt.IsZero() {
		t.Fatal("evidence-seen should still be recent for a declared row")
	}

	observed := DiscoveredAgent{
		EvidenceMode:          EvidenceObserved,
		LastSeenAt:            seen,
		LastObservedRunningAt: &seen,
	}
	if observed.LastObservedRunningAt == nil {
		t.Fatal("an observed row is exactly the case that HAS a runtime timestamp")
	}
	t.Log("PASS: declared has evidence-seen but no runtime; observed has both")
}

func TestEvidenceModeVocabulary(t *testing.T) {
	modes := ValidEvidenceModes()
	if len(modes) != 3 {
		t.Fatalf("expected exactly three evidence modes, got %v", modes)
	}
	want := map[string]bool{EvidenceObserved: false, EvidenceDeclared: false, EvidenceInferred: false}
	for _, m := range modes {
		if _, ok := want[m]; !ok {
			t.Fatalf("unexpected evidence mode %q", m)
		}
		want[m] = true
	}
	for m, seen := range want {
		if !seen {
			t.Fatalf("evidence mode %q missing from the vocabulary", m)
		}
	}
	t.Logf("PASS: %v", modes)
}
