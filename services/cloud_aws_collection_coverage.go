package services

import (
	"errors"
	"fmt"
	"strings"

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
//	a named listing failure             -> throttled / denied, as surfaceResult
//	                                       always did, with api and error_code
//
// resource_policies is the one per-item surface with its own mapping (D-93,
// resourcePolicyCoverage below), and eks_pod_identity the one surface read by
// many readers at once (podIdentityCoverage, at the end of this file).
//
// §1.4: partial, denied and throttled all keep what the surface last
// confirmed (stale); unsupported and reached do not. The Error always names
// the failed call and the AWS error code, never a guessed permission
// (§2.14.13), and API / ErrorCode carry the same two facts for GET /coverage
// (D-71): the FIRST failing call, and AWS's own code for it or nothing.

// collectionCoverage returns the coverage for the two collection-honesty
// errors, and for any failure whose reader NAMED the call (awsdiscovery's
// listErr / withCallName); false for anything else (surfaceResult's own switch
// decides, exactly as before).
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
	case awsdiscovery.CallName(err) != "":
		// An ordinary listing failure: the SAME state surfaceResult gives it
		// (throttled on a throttle, else denied), plus the two facts D-71
		// stamps at collection -- the call, and AWS's own code or nothing.
		cov := models.SurfaceCoverage{State: models.CloudCoverageDenied, Count: count, Error: err.Error(),
			API: awsdiscovery.CallName(err), ErrorCode: awsdiscovery.AWSErrorCode(err)}
		if errors.Is(err, awsdiscovery.ErrThrottled) {
			cov.State = models.CloudCoverageThrottled
		}
		return cov, true
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

// podIdentityFailures is everything eks_pod_identity could not read in ONE
// run, across every selected region and every cluster. The surface is read by
// one EKS reader per region and one association listing per cluster, and each
// returns its own error; keeping only the first of them undercounted the
// report ("the report names how many", §1.4) and let a later region's denied
// or throttled listing read as an earlier region's partial.
type podIdentityFailures struct {
	// listings are the reads that returned no list at all -- a session that
	// could not be created, eks:ListClusters, eks:ListPodIdentityAssociations
	// -- in the order they failed, each naming its call.
	listings []podIdentityListing
	// clusters and associations tally the DETAIL calls behind listings that
	// succeeded (eks:DescribeCluster, eks:DescribePodIdentityAssociation),
	// summed over every region and cluster.
	clusters, associations *awsdiscovery.ItemFailures
}

// podIdentityListing is one listing that failed outright. why, when set, is
// appended to the error's own text: the reason a non-resolving endpoint is
// reported as a failure rather than skipped as "not offered here".
type podIdentityListing struct {
	err error
	why string
}

func newPodIdentityFailures() *podIdentityFailures {
	return &podIdentityFailures{
		clusters:     awsdiscovery.NewItemFailures("clusters could not be read in detail", true),
		associations: awsdiscovery.NewItemFailures("pod identity associations could not be read in detail", true),
	}
}

func (f *podIdentityFailures) addListing(err error, why string) {
	if err != nil {
		f.listings = append(f.listings, podIdentityListing{err: err, why: why})
	}
}

// addClusters and addAssociations take one reader call's error: its detail
// tally (*awsdiscovery.ItemFailures) is merged into the surface's, and
// anything else is a listing that returned nothing.
func (f *podIdentityFailures) addClusters(err error)     { f.add(f.clusters, err) }
func (f *podIdentityFailures) addAssociations(err error) { f.add(f.associations, err) }

func (f *podIdentityFailures) add(tally *awsdiscovery.ItemFailures, err error) {
	var items *awsdiscovery.ItemFailures
	switch {
	case err == nil:
	case errors.As(err, &items):
		tally.Merge(items)
	default:
		f.addListing(err, "")
	}
}

// err is f when anything failed, else nil -- never a typed nil, which would
// read as a failure.
func (f *podIdentityFailures) err() error {
	if len(f.listings) == 0 && f.clusters.Failed == 0 && f.associations.Failed == 0 {
		return nil
	}
	return f
}

// Error names every failure: each failed listing with its call and code, then
// "N of M clusters ..." and "N of M pod identity associations ..." for the
// detail calls.
func (f *podIdentityFailures) Error() string {
	var parts []string
	for _, l := range f.listings {
		parts = append(parts, l.err.Error()+l.why)
	}
	if n := len(f.listings); n > 1 {
		parts[0] = fmt.Sprintf("%d listings failed: %s", n, parts[0])
	}
	for _, t := range []*awsdiscovery.ItemFailures{f.clusters, f.associations} {
		if t.Failed > 0 {
			parts = append(parts, t.Error())
		}
	}
	return strings.Join(parts, "; ")
}

// podIdentityCoverage is eks_pod_identity's coverage. A listing that failed
// outright outranks every detail failure -- the region or cluster it covers
// was not read at all -- and is denied, or throttled when every failed
// listing was a throttle; with only detail calls failing, the surface is
// partial (§1.4: "a failed detail call makes its surface partial"). All three
// block. API and ErrorCode name the listing the state came from, else the
// first failing detail call (D-71). Count is the edges written, a floor
// whenever the state is not reached. Any other error is surfaceResult's.
func podIdentityCoverage(count int, err error) models.SurfaceCoverage {
	var f *podIdentityFailures
	if !errors.As(err, &f) {
		return surfaceResult(count, err)
	}
	if len(f.listings) > 0 {
		lead, state := f.listings[0], models.CloudCoverageThrottled
		for _, l := range f.listings {
			if !errors.Is(l.err, awsdiscovery.ErrThrottled) {
				lead, state = l, models.CloudCoverageDenied
				break
			}
		}
		return models.SurfaceCoverage{State: state, Count: count, Error: f.Error(),
			API: awsdiscovery.CallName(lead.err), ErrorCode: awsdiscovery.AWSErrorCode(lead.err)}
	}
	cov := models.SurfaceCoverage{State: models.CloudCoveragePartial, Count: count, Error: f.Error()}
	for _, t := range []*awsdiscovery.ItemFailures{f.clusters, f.associations} {
		if t.Failed > 0 {
			return withFirstFailure(cov, t)
		}
	}
	return cov
}
