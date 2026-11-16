package services

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
)

// GCP-1: the scan's coverage is whatever surfaces it registered, and nothing
// else. These tests need no database: buildCoverage and the accumulators are
// pure.

func reachedAcc(count int) *gcpSurfaceAcc {
	a := newGCPSurfaceAcc()
	a.observe(nil, count)
	return a
}

func coverageOf(surfaces []gcpNamedAcc) models.ScanCoverage {
	return (&GCPScanner{}).buildCoverage(1, time.Now(), models.CloudScanTriggerManual, surfaces, gcp.NewGovernor(), 2)
}

// "Adding a surface is a one-line change": the extra surface appears in the
// report, with its counter, and the report is still Complete() when it was reached.
func TestBuildCoverage_AddingASurfaceIsOneRegisteredLine(t *testing.T) {
	base := []gcpNamedAcc{
		{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: reachedAcc(5)},
		{surface: gcp.SurfaceKeys, counter: "secrets_upserted", acc: reachedAcc(2)},
	}
	if got := len(coverageOf(base).Surfaces); got != 2 {
		t.Fatalf("baseline coverage lists %d surfaces, want 2", got)
	}

	// The one line a later ticket adds.
	extended := append(base, gcpNamedAcc{surface: gcp.SurfaceHMACKeys, counter: "hmac_keys_upserted", acc: reachedAcc(7)})
	cov := coverageOf(extended)

	if got := len(cov.Surfaces); got != 3 {
		t.Fatalf("coverage lists %d surfaces, want 3: %v", got, cov.Surfaces)
	}
	if s := cov.Surfaces[gcp.SurfaceHMACKeys]; s.State != models.CloudCoverageReached || s.Count != 7 {
		t.Fatalf("hmac_keys = %+v, want reached with count 7", s)
	}
	if cov.Counters["hmac_keys_upserted"] != 7 {
		t.Fatalf("counter hmac_keys_upserted = %d, want 7", cov.Counters["hmac_keys_upserted"])
	}
	if !cov.Complete() {
		t.Fatal("every registered surface was reached, so the report must be Complete()")
	}
}

// The other half: one surface that was not reached makes the whole report
// incomplete, which is what stops reconciliation in every table.
func TestBuildCoverage_AnyUnreachedSurfaceBlocksComplete(t *testing.T) {
	for name, state := range map[string]error{
		"denied":    errors.New("permission denied"),
		"truncated": fmt.Errorf("%w: too deep", gcp.ErrScopeTreeTruncated),
		"throttled": gcp.ErrThrottled,
		"deadline":  errors.New("context deadline exceeded"),
	} {
		t.Run(name, func(t *testing.T) {
			bad := newGCPSurfaceAcc()
			bad.fail(state)
			cov := coverageOf([]gcpNamedAcc{
				{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: reachedAcc(3)},
				{surface: gcp.SurfaceScopeTree, counter: "scope_nodes", acc: bad},
			})
			if cov.Complete() {
				t.Fatalf("a %s surface must make coverage incomplete, got %+v", name, cov.Surfaces)
			}
		})
	}
}

// A surface nothing touched is unknown, never an empty success.
func TestBuildCoverage_UntouchedSurfaceIsUnknownAndBlocksComplete(t *testing.T) {
	cov := coverageOf([]gcpNamedAcc{
		{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: reachedAcc(1)},
		{surface: gcp.SurfaceKeys, counter: "secrets_upserted", acc: newGCPSurfaceAcc()},
	})
	if got := cov.Surfaces[gcp.SurfaceKeys].State; got != models.CloudCoverageUnknown {
		t.Fatalf("untouched surface = %q, want unknown", got)
	}
	if cov.Complete() {
		t.Fatal("an untouched surface must not read as complete")
	}
}

// A truncated scope tree is unknown (the tree is real but not known to be whole),
// not denied: it is not a permission problem and granting a role would not fix it.
func TestClassify_TruncatedScopeTreeIsUnknownNotDenied(t *testing.T) {
	if got := classifyGCPSurfaceError(fmt.Errorf("%w: x", gcp.ErrScopeTreeTruncated)); got != models.CloudCoverageUnknown {
		t.Fatalf("truncated tree classified %q, want unknown", got)
	}
	if got := classifyGCPSurfaceError(errors.New("403 forbidden")); got != models.CloudCoverageDenied {
		t.Fatalf("a plain refusal classified %q, want denied", got)
	}
	if got := classifyGCPSurfaceError(nil); got != models.CloudCoverageReached {
		t.Fatalf("nil classified %q, want reached", got)
	}
}

// The per-project counters come from the FIRST registered surface, so the first
// one must be a per-project surface; an empty list is safe and reports zeros.
func TestBuildCoverage_ProjectTalliesComeFromTheFirstSurface(t *testing.T) {
	first := newGCPSurfaceAcc()
	first.observe(nil, 1)
	first.observe(nil, 1)
	denied := errors.New("403")
	first.observe(denied, 0)
	cov := coverageOf([]gcpNamedAcc{{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: first}})
	if cov.Counters["projects_reached"] != 2 || cov.Counters["projects_denied"] != 1 {
		t.Fatalf("project tallies = %+v, want 2 reached and 1 denied", cov.Counters)
	}
	if cov.Counters["projects_total"] != 2 {
		t.Fatalf("projects_total = %d, want the 2 passed in", cov.Counters["projects_total"])
	}

	empty := coverageOf(nil)
	if len(empty.Surfaces) != 0 || empty.Complete() {
		t.Fatalf("no registered surfaces must be empty and not Complete(), got %+v", empty)
	}
}

func TestGCPDiscoveryIntervalFromEnv(t *testing.T) {
	cases := map[string]time.Duration{
		"":       12 * time.Hour,
		"30m":    30 * time.Minute,
		"0":      0,
		"off":    0,
		"banana": 12 * time.Hour,
		"-5m":    12 * time.Hour,
	}
	for raw, want := range cases {
		t.Setenv(GCPDiscoveryIntervalEnv, raw)
		if got := GCPDiscoveryIntervalFromEnv(); got != want {
			t.Errorf("%q: interval = %v, want %v", raw, got, want)
		}
	}
}
