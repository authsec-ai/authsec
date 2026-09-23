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
// resource_policies is the one per-item surface with its own mapping (D-93,
// resourcePolicyCoverage below).
//
// §1.4: partial, denied and throttled all keep what the surface last
// confirmed (stale); unsupported and reached do not. The Error always names
// the failed call and the AWS error code, never a guessed permission
// (§2.14.13), and API / ErrorCode carry the same two facts for GET /coverage
// (D-71): the FIRST failing call, and AWS's own code for it or nothing.

// collectionCoverage returns the coverage for the two collection-honesty
// errors, and false for anything else (surfaceResult's own switch decides).
func collectionCoverage(count int, err error) (models.SurfaceCoverage, bool) {
	if err == nil {
		return models.SurfaceCoverage{}, false
	}
	var items *awsdiscovery.ItemFailures
	switch {
	case errors.Is(err, awsdiscovery.ErrServiceNotInRegion):
		// No error_code: AWS returned none -- the endpoint does not exist.
		return models.SurfaceCoverage{State: models.CloudCoverageUnsupported, Count: count,
			Error: err.Error(), API: awsdiscovery.CallName(err)}, true
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
	return withFirstFailure(models.SurfaceCoverage{State: state, Count: count, Error: f.Error()}, f)
}

// resourcePolicyCoverage is resource_policies' coverage, exactly as D-93
// records it: every read succeeded -> reached (count = reads; a
// NoSuchBucketPolicy / no key policy is a SUCCESSFUL read, the answer "none");
// some failed -> partial; all failed -> denied; and whenever it is not
// reached, count = the FAILED reads. A throttled read is a failed read here --
// D-93 gives this surface no throttled state -- and its Error still names
// ThrottlingException, so nothing is misattributed to a permission.
//
// It never gates the permission scan's reconciliation (bonus evidence; no
// partition requires it). An error that is not a per-resource tally -- the
// reader could not even be built -- is an ordinary surfaceResult.
func resourcePolicyCoverage(reads int, err error) models.SurfaceCoverage {
	var items *awsdiscovery.ItemFailures
	if err == nil || !errors.As(err, &items) {
		return surfaceResult(reads, err)
	}
	state := models.CloudCoveragePartial
	if items.Failed >= items.Total {
		state = models.CloudCoverageDenied
	}
	return withFirstFailure(models.SurfaceCoverage{State: state, Count: items.Failed, Error: items.Error()}, items)
}

// withFirstFailure stamps the first failing call and its AWS error code
// (D-71), leaving both empty when the tally recorded none.
func withFirstFailure(cov models.SurfaceCoverage, f *awsdiscovery.ItemFailures) models.SurfaceCoverage {
	if len(f.Calls) > 0 {
		cov.API, cov.ErrorCode = f.Calls[0].Call, f.Calls[0].AWSCode
	}
	return cov
}
