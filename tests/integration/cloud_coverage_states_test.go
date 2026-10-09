package integration

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// Complete() decides whether reconciliation may delete rows this scan did not
// see. Two of the surface states mean "never attempted, by design"; the rest
// mean "we meant to read this and did not". Confusing the two categories either
// deletes real data or switches reconciliation off forever.

func coverage(states map[string]string) models.ScanCoverage {
	surfaces := map[string]models.SurfaceCoverage{}
	for name, st := range states {
		surfaces[name] = models.SurfaceCoverage{State: st}
	}
	return models.ScanCoverage{Surfaces: surfaces}
}

func TestNotSelectedAndUnsupportedDoNotBlockReconciliation(t *testing.T) {
	// Recording these states at all would otherwise make every scan incomplete
	// forever, silently switching reconciliation off — a regression that would
	// look like nothing happening.
	c := coverage(map[string]string{
		"iam_roles":         models.CloudCoverageReached,
		"compute:eu-west-3": models.CloudCoverageNotSelected,
		"cloudtrail_events": models.CloudCoverageUnsupported,
	})
	if !c.Complete() {
		t.Fatalf("a scan that read everything it intended is complete; got incomplete: %+v", c.Surfaces)
	}
	if got := len(c.IntendedIncomplete()); got != 0 {
		t.Errorf("IntendedIncomplete = %d surfaces, want 0", got)
	}
}

func TestAnIntendedReadThatFellShortBlocksReconciliation(t *testing.T) {
	for _, state := range []string{
		models.CloudCoverageDenied,
		models.CloudCoverageThrottled,
		models.CloudCoveragePartial,
		models.CloudCoverageConstrained,
		models.CloudCoverageStale,
		models.CloudCoverageUnknown,
	} {
		c := coverage(map[string]string{
			"iam_roles":  models.CloudCoverageReached,
			"iam_users":  state,
			"not_chosen": models.CloudCoverageNotSelected,
		})
		if c.Complete() {
			t.Errorf("state %q must not license deletion", state)
		}
		if _, ok := c.IntendedIncomplete()["iam_users"]; !ok {
			t.Errorf("state %q should be reported as an intended read that fell short", state)
		}
	}
}

func TestAScanThatAttemptedNothingIsNotComplete(t *testing.T) {
	// Every surface skipped establishes nothing, and must not license deleting
	// what an earlier real scan found.
	c := coverage(map[string]string{
		"compute:eu-west-3": models.CloudCoverageNotSelected,
		"cloudtrail_events": models.CloudCoverageUnsupported,
	})
	if c.Complete() {
		t.Fatal("a scan with no attempted surface must not be complete")
	}
}

func TestEmptyCoverageIsNotComplete(t *testing.T) {
	if (models.ScanCoverage{}).Complete() {
		t.Fatal("absent coverage is not proof of a complete read")
	}
}

func TestOnlyAReachedSurfaceIsAuthoritative(t *testing.T) {
	for _, st := range models.SurfaceStates {
		got := models.SurfaceCoverage{State: st}.Authoritative()
		want := st == models.CloudCoverageReached
		if got != want {
			t.Errorf("state %q: Authoritative() = %v, want %v", st, got, want)
		}
	}
}
