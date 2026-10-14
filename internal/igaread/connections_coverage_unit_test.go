package igaread

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// A connection that scans one region of seventeen read everything it was
// asked to: the sixteen regions left out of scope are scope, not gaps, so
// the connection is complete and names no gap. Before this, each unselected
// region became a "stale" gap and the connection read "Coverage partial".
func TestConnCloudCoverageTreatsNotSelectedAsOutOfScope(t *testing.T) {
	surfaces := map[string]models.SurfaceCoverage{
		"iam":               {State: models.CloudCoverageReached},
		"compute:us-east-1": {State: models.CloudCoverageReached},
		"organizations":     {State: models.CloudCoverageUnsupported},
	}
	for _, r := range []string{
		"us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3",
		"eu-central-1", "eu-north-1", "ap-south-1", "ap-northeast-1", "ap-northeast-2",
		"ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "sa-east-1",
	} {
		surfaces["compute:"+r] = models.SurfaceCoverage{State: models.CloudCoverageNotSelected}
	}

	got := connCloudCoverage(models.ScanCoverage{Surfaces: surfaces}, nil)
	if got.State != connCovComplete {
		t.Fatalf("state = %q, want %q", got.State, connCovComplete)
	}
	if len(got.Gaps) != 0 {
		t.Fatalf("gaps = %v, want none", got.Gaps)
	}
}

// Real gaps still count: a denied surface beside a reached one is partial,
// and the unselected regions next to it add nothing to the gap list.
func TestConnCloudCoverageStillReportsRealGaps(t *testing.T) {
	got := connCloudCoverage(models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
		"iam":               {State: models.CloudCoverageReached},
		"compute:us-east-1": {State: models.CloudCoverageDenied},
		"compute:eu-west-1": {State: models.CloudCoverageNotSelected},
	}}, nil)
	if got.State != connCovPartial {
		t.Fatalf("state = %q, want %q", got.State, connCovPartial)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].Surface != "compute:us-east-1" || got.Gaps[0].State != models.CloudCoverageDenied {
		t.Fatalf("gaps = %v, want only the denied compute:us-east-1", got.Gaps)
	}
}

// Only unselected regions, nothing attempted: unknown, never complete.
func TestConnCloudCoverageNothingAttemptedIsUnknown(t *testing.T) {
	got := connCloudCoverage(models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
		"compute:eu-west-1": {State: models.CloudCoverageNotSelected},
	}}, nil)
	if got.State != connCovUnknown {
		t.Fatalf("state = %q, want %q", got.State, connCovUnknown)
	}
}

// A region selected before and since taken out of scope keeps its earlier
// results, stale (D-58): that is still a gap, reported as stale. A region
// never selected beside it is not.
func TestConnCloudCoverageDeselectedRegionIsStillAStaleGap(t *testing.T) {
	got := connCloudCoverage(models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
		"iam":                {State: models.CloudCoverageReached},
		"compute:us-east-1":  {State: models.CloudCoverageReached},
		"compute:eu-west-1":  {State: models.CloudCoverageNotSelected},
		"compute:ap-south-1": {State: models.CloudCoverageNotSelected},
	}}, []string{"eu-west-1"})
	if got.State != connCovPartial {
		t.Fatalf("state = %q, want %q", got.State, connCovPartial)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].Surface != "compute:eu-west-1" || got.Gaps[0].State != models.CloudCoverageStale {
		t.Fatalf("gaps = %v, want only compute:eu-west-1 as stale", got.Gaps)
	}
}

func TestNotSelectedIsGap(t *testing.T) {
	for _, tc := range []struct {
		surface    string
		deselected []string
		want       bool
	}{
		{"compute:eu-west-1", []string{"eu-west-1"}, true},
		{"compute:eu-west-1", nil, false},
		{"compute:eu-west-1", []string{"us-east-1"}, false},
		{"iam", []string{"eu-west-1"}, false},
	} {
		if got := notSelectedIsGap(tc.surface, tc.deselected); got != tc.want {
			t.Errorf("notSelectedIsGap(%q, %v) = %v, want %v", tc.surface, tc.deselected, got, tc.want)
		}
	}
}
