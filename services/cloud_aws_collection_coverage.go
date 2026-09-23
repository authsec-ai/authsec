package services

import (
	"errors"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// The coverage states only a regional or per-item read can produce (T3.6,
// T3.7, T3.8), shared by every AWS scanner through surfaceResult so each
// surface is classified once, the same way:
//
//	awsdiscovery.ErrServiceNotInRegion  -> unsupported  nothing there is claimed
//	*awsdiscovery.ItemFailures, detail  -> partial      listed; some detail calls failed
//	*awsdiscovery.ItemFailures, per-item-> throttled    if any item was throttled
//	                                       denied       if no item could be read
//	                                       partial      otherwise
//
// §1.4: partial, denied and throttled all keep what the surface last
// confirmed (stale); unsupported and reached do not. The Error always names
// the failed call and the AWS error code, never a guessed permission
// (§2.14.13).

// collectionCoverage returns the coverage for the two collection-honesty
// errors, and false for anything else (surfaceResult's own switch decides).
func collectionCoverage(count int, err error) (models.SurfaceCoverage, bool) {
	if err == nil {
		return models.SurfaceCoverage{}, false
	}
	var items *awsdiscovery.ItemFailures
	switch {
	case errors.Is(err, awsdiscovery.ErrServiceNotInRegion):
		return models.SurfaceCoverage{State: models.CloudCoverageUnsupported, Count: count, Error: err.Error()}, true
	case errors.As(err, &items):
		return itemFailureCoverage(count, items), true
	}
	return models.SurfaceCoverage{}, false
}

// itemFailureCoverage maps a per-item failure tally to a state. A DETAIL
// failure is always partial -- the listing succeeded, so the set of items is
// known and only their detail is not (§1.4: "a failed detail call makes its
// surface partial"). A per-item surface has no listing of its own, so a
// throttle is reported as throttled and a total failure as denied (§1.3).
func itemFailureCoverage(count int, f *awsdiscovery.ItemFailures) models.SurfaceCoverage {
	state := models.CloudCoveragePartial
	if !f.Detail {
		switch {
		case f.Throttled > 0:
			state = models.CloudCoverageThrottled
		case f.Failed >= f.Total:
			state = models.CloudCoverageDenied
		}
	}
	return models.SurfaceCoverage{State: state, Count: count, Error: f.Error()}
}
