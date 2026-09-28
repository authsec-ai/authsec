package services

import (
	"fmt"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// A read that stopped at its page cap is partial, not denied: nothing was
// refused. Like denied it is not authoritative, so it still blocks deletion.
func TestSurfaceResultClassifiesPageCapAsPartial(t *testing.T) {
	capped := surfaceResult(10000, fmt.Errorf("%w: read the first 10000 CloudTrail events", awsdiscovery.ErrTooManyPages))
	if capped.State != models.CloudCoveragePartial || capped.Count != 10000 {
		t.Fatalf("page cap: got %+v", capped)
	}
	if capped.Authoritative() {
		t.Fatal("a partial read must never license reconciliation")
	}
	if got := surfaceResult(3, fmt.Errorf("%w: slow down", awsdiscovery.ErrThrottled)); got.State != models.CloudCoverageThrottled {
		t.Fatalf("throttle: got %s", got.State)
	}
	if got := surfaceResult(0, fmt.Errorf("%w: AccessDenied", awsdiscovery.ErrNotAssumable)); got.State != models.CloudCoverageDenied {
		t.Fatalf("a real refusal must stay denied, got %s", got.State)
	}
	if got := surfaceResult(5, nil); got.State != models.CloudCoverageReached {
		t.Fatalf("success: got %s", got.State)
	}
}
