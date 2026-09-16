package gcp

import (
	"context"
	"os"
	"strconv"

	"golang.org/x/time/rate"
)

/* limits.go governs how hard a GCP scan is allowed to push, on the way OUT.

   NOT TO BE CONFUSED WITH THE INBOUND LIMITERS. middlewares/ratelimit.go,
   middlewares/redis_ratelimit.go and internal/spire/middleware/ratelimit.go
   all limit requests arriving AT AuthSec. Nothing here touches those. This is
   the opposite direction: requests AuthSec makes to Google.

   WHY PER-SURFACE AND NOT ONE GLOBAL NUMBER. GCP's read APIs do not share a
   rate-limit convention. Cloud Asset Inventory's search methods are quota'd per
   organization AND per project; iam.serviceAccounts.list is project-scoped with
   its own separate limit and has no organization-wide form at all. A single
   "requests per second" for the connector would either throttle the org-wide
   sweep down to the per-project surface's budget, or let the per-project
   fan-out run at the org-wide surface's. Neither is what anyone wants.

   THESE NUMBERS ARE BUDGETS, NOT PROVIDER QUOTAS. They are what AuthSec allows
   itself, chosen conservatively, and they are NOT transcribed from Google's
   quota documentation. The one quota figure the GCP plan does cite for
   searchAllResources is explicitly flagged there as needing live confirmation
   against a real quota dashboard before any capacity claim rests on it, and no
   figure at all was found for searchAllIamPolicies. Treating a documented
   number as measured is how a scan discovers at a customer's expense that the
   number did not apply to its tier. So: start low, make it configurable, and
   raise it when a benchmark says what the real ceiling is.

   WHAT HAPPENS WHEN A BUDGET IS TOO LOW: the scan takes longer. What happens
   when it is too high: GCP throttles, retry.go backs off, and if that does not
   recover the surface is recorded throttled and nothing is reconciled. Both
   failure modes are safe; only one of them is slow. */

// Environment overrides. Unset or unparseable falls back to the default, so a
// typo slows a scan down rather than removing the governor entirely.
const (
	EnvMaxProjectConcurrency = "GCP_DISCOVERY_MAX_PROJECT_CONCURRENCY"
	EnvIAMQPS                = "GCP_DISCOVERY_IAM_QPS"
	EnvCAIQPS                = "GCP_DISCOVERY_CAI_QPS"
)

// Defaults.
const (
	// defaultMaxProjectConcurrency bounds how many projects are read at once
	// during fan-out. An org with hundreds of projects must not open hundreds
	// of concurrent calls: that is how a scan turns itself into the incident.
	defaultMaxProjectConcurrency = 4

	// defaultIAMQPS covers iam.serviceAccounts.list and
	// serviceAccounts.keys.list, which share an API and therefore a budget.
	defaultIAMQPS = 8.0

	// defaultCAIQPS covers Cloud Asset Inventory's search methods. Lower than
	// IAM because each call is org-wide and expensive, and because the quota
	// ceiling here is the one the plan explicitly says is unconfirmed.
	defaultCAIQPS = 2.0

	// burstFactor lets a limiter absorb a short opening burst rather than
	// pacing the very first calls of a scan. Kept small so a burst cannot be
	// the thing that trips a quota.
	burstFactor = 2
)

// Governor is the outbound budget for one scan.
//
// One Governor per scan rather than a package-level singleton: two connectors
// scanning concurrently are two different customers' quota, and sharing a
// limiter between them would make one customer's large estate throttle
// another's small one.
type Governor struct {
	// IAM paces iam.googleapis.com reads.
	IAM *rate.Limiter
	// CAI paces cloudasset.googleapis.com search reads.
	CAI *rate.Limiter
	// ResourceManager paces project/folder/org enumeration. Shares the IAM
	// budget's shape -- it is the same class of cheap metadata read -- but its
	// own bucket, so enumeration cannot starve identity reads.
	ResourceManager *rate.Limiter

	// projectSlots bounds fan-out concurrency. A buffered channel rather than
	// x/sync/semaphore to avoid adding a dependency for a counter.
	projectSlots chan struct{}
}

// NewGovernor builds the budget for one scan from the environment.
func NewGovernor() *Governor {
	iamQPS := floatFromEnv(EnvIAMQPS, defaultIAMQPS)
	caiQPS := floatFromEnv(EnvCAIQPS, defaultCAIQPS)
	concurrency := intFromEnv(EnvMaxProjectConcurrency, defaultMaxProjectConcurrency)

	return &Governor{
		IAM:             rate.NewLimiter(rate.Limit(iamQPS), burst(iamQPS)),
		CAI:             rate.NewLimiter(rate.Limit(caiQPS), burst(caiQPS)),
		ResourceManager: rate.NewLimiter(rate.Limit(iamQPS), burst(iamQPS)),
		projectSlots:    make(chan struct{}, concurrency),
	}
}

// AcquireProject blocks until a fan-out slot is free, or ctx is done.
//
// The release function is always safe to call, including after an error return,
// so a caller can defer it unconditionally without checking.
func (g *Governor) AcquireProject(ctx context.Context) (release func(), err error) {
	select {
	case g.projectSlots <- struct{}{}:
		var done bool
		return func() {
			if done {
				return
			}
			done = true
			<-g.projectSlots
		}, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// ProjectConcurrency reports the configured fan-out width, for the scan report.
func (g *Governor) ProjectConcurrency() int { return cap(g.projectSlots) }

func burst(qps float64) int {
	b := int(qps) * burstFactor
	if b < 1 {
		return 1
	}
	return b
}

func floatFromEnv(key string, fallback float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		// A misconfigured budget must not become an unlimited one.
		return fallback
	}
	return v
}

func intFromEnv(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
