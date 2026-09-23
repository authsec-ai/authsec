package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Workloads and activity: the compute that runs as a discovered identity, and
// the evidence that an identity actually used a service.
//
// Like AWSPermissionScanner, this runs from an IAMSnapshot rather than
// re-reading IAM: the identities it attributes workloads to were written by
// that scan moments earlier, and it must be stamped with the SAME generation so
// reconciliation ages a role and its workloads out together rather than on
// separate schedules.
//
// What it writes: cloud_workload (Lambda, ECS, EC2, Bedrock agents, AgentCore
// runtimes) and cloud_usage (service-last-accessed). It writes no identities:
// a workload naming a role that identity discovery never recorded is stored
// unattributed, because inventing the role would create an identity no scan
// observed.

// workloadScanRegionTimeout is not imposed here: the caller's context already
// carries the scan's budget, and every reader in awsdiscovery respects it.

// AWSWorkloadScanner reads workloads and activity for one connector.
type AWSWorkloadScanner struct {
	db         *gorm.DB
	identities repositories.CloudIdentityRepository
	workloads  repositories.CloudWorkloadRepository
	onboarding *AWSOnboardingService

	// Test seams. Each is optional and, when set, replaces the real client for
	// every region.
	evidence *ObservationWriter

	lambdaAPI     awsdiscovery.LambdaAPI
	regionalAPIs  RegionalAPIs
	ecsAPI        awsdiscovery.ECSAPI
	ec2API        awsdiscovery.EC2API
	profileAPI    awsdiscovery.InstanceProfileAPI
	bedrockAPI    awsdiscovery.BedrockAgentAPI
	agentCoreAPI  awsdiscovery.AgentCoreAPI
	cloudTrailAPI awsdiscovery.CloudTrailAPI
	activityAPI   awsdiscovery.ServiceLastAccessedAPI
	// activitySleep replaces the polling delay, so a test does not wait.
	activitySleep func(context.Context, time.Duration) error
}

// NewAWSWorkloadScanner constructs the scanner.
func NewAWSWorkloadScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSWorkloadScanner {
	return &AWSWorkloadScanner{
		db:         db,
		identities: repositories.NewCloudIdentityRepository(db),
		workloads:  repositories.NewCloudWorkloadRepository(db),
		onboarding: onboarding,
	}
}

// WithWorkloadAPIs installs compute clients for every region, bypassing
// assume-role. Any may be nil, which skips that surface.
func (s *AWSWorkloadScanner) WithWorkloadAPIs(
	l awsdiscovery.LambdaAPI, e awsdiscovery.ECSAPI,
	c awsdiscovery.EC2API, p awsdiscovery.InstanceProfileAPI,
) *AWSWorkloadScanner {
	s.lambdaAPI, s.ecsAPI, s.ec2API, s.profileAPI = l, e, c, p
	return s
}

// RegionalAPIs returns the compute clients for ONE region. A test seam: the
// clients WithWorkloadAPIs installs stand in for every region, which cannot
// express "one region denied, another clean" (§6.3).
type RegionalAPIs func(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
	awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
	awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI)

// WithRegionalAPIs installs per-region compute clients; it wins over
// WithWorkloadAPIs.
func (s *AWSWorkloadScanner) WithRegionalAPIs(f RegionalAPIs) *AWSWorkloadScanner {
	s.regionalAPIs = f
	return s
}

// WithBedrockAPIs installs the managed-agent clients for every region.
func (s *AWSWorkloadScanner) WithBedrockAPIs(
	b awsdiscovery.BedrockAgentAPI, c awsdiscovery.AgentCoreAPI,
) *AWSWorkloadScanner {
	s.bedrockAPI, s.agentCoreAPI = b, c
	return s
}

// WithCloudTrailAPI installs the CloudTrail client for every region.
func (s *AWSWorkloadScanner) WithCloudTrailAPI(c awsdiscovery.CloudTrailAPI) *AWSWorkloadScanner {
	s.cloudTrailAPI = c
	return s
}

// WithActivityAPI installs the service-last-accessed client, and optionally a
// sleep function so the polling loop does not wait in tests.
func (s *AWSWorkloadScanner) WithActivityAPI(
	a awsdiscovery.ServiceLastAccessedAPI, sleep func(context.Context, time.Duration) error,
) *AWSWorkloadScanner {
	s.activityAPI, s.activitySleep = a, sleep
	return s
}

// WorkloadSnapshot is what one workload-and-activity scan wrote.
type WorkloadSnapshot struct {
	ConnectorID uuid.UUID
	Generation  int

	WorkloadsWritten int
	// Unattributed counts workloads whose role was not in inventory. A real
	// finding -- compute nobody can tie to an identity -- reported rather than
	// hidden among the total.
	Unattributed int
	// DetailIncomplete counts workloads that were listed but whose detail call
	// failed (T3.6). Kept apart from Unattributed: their role is UNKNOWN this
	// run, which is not the finding "attributed to nothing".
	DetailIncomplete int
	UsageWritten     int

	// ByKind counts workloads per runtime kind, so "we found no Bedrock agents"
	// is distinguishable from "we never looked".
	ByKind map[string]int

	// Complete is true only when BOTH tables this scanner reconciles were read
	// authoritatively: every compute surface (WorkloadsComplete) and activity
	// (UsageComplete), for the reason the rest of this schema follows:
	// unreached is not missing.
	//
	// UsageComplete gates ReconcileUsage. WorkloadsComplete does NOT gate
	// workload deletion any more -- it reports whether the whole table was
	// read. Deletion is per surface (ReconciledSurfaces): one partial surface
	// blocks deletion "for that surface" (§1.4), never for the connector.
	Complete          bool
	WorkloadsComplete bool
	UsageComplete     bool
	// ReconciledSurfaces are the compute surfaces ("lambda:us-east-1") whose
	// rows ReconcileWorkloads was licensed to age out this run: every one
	// reached, with the IAM baseline complete. Sorted.
	ReconciledSurfaces []string
	// Errors carries what went wrong per surface, for the coverage report.
	// Only surfaces whose state BLOCKS are listed: an unsupported surface
	// (the service is not offered in that region) is not an error.
	Errors map[string]string
	// Surfaces is the same information as Errors, but in the connector-level
	// coverage shape (state + count, not just an error string), so the caller
	// can fold it into the overall report instead of dropping it. Keyed
	// "<surface>:<region>" per compute surface, plus "activity" globally.
	Surfaces map[string]models.SurfaceCoverage
}

// ScanFromSnapshot reads workloads and activity for the identities a
// just-completed IAM scan recorded.
func (s *AWSWorkloadScanner) ScanFromSnapshot(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
) (*WorkloadSnapshot, error) {

	if snapshot == nil {
		return nil, errors.New("workload scan needs an IAM snapshot to attribute against")
	}

	out := &WorkloadSnapshot{
		ConnectorID: snapshot.ConnectorID,
		Generation:  snapshot.Generation,
		ByKind:      map[string]int{},
		Errors:      map[string]string{},
		Surfaces:    map[string]models.SurfaceCoverage{},
	}

	connector, err := s.connector(workspaceID, snapshot.ConnectorID)
	if err != nil {
		return nil, err
	}
	connAttrs := connector.AWSAttrs()
	regions := connAttrs.Regions
	// The scope a constructed ARN is built in (T3.6): the connector's own
	// partition and account, never assumed.
	scope := arnScope{partition: connAttrs.Partition, account: snapshot.AccountID}
	if scope.account == "" {
		scope.account = connector.ScopeID
	}

	// ---- regional compute --------------------------------------------------
	for _, region := range regions {
		s.scanRegion(ctx, workspaceID, snapshot, scope, region, out)
	}

	// Regions the operator did NOT select are recorded, not omitted.
	//
	// An absent surface and a surface that returned nothing look identical to a
	// reader, and only one of them means the estate is clean. "Nobody looked,
	// and nobody was meant to" is a different answer from both, and it is the
	// honest one for an unselected region.
	//
	// That includes every region this connector's selection ever held, and
	// every region it holds workloads in: a region can be selected (PATCH
	// .../connectors/:id accepts any ENABLED region, not only
	// awsRegionsWithCompute) and later deselected, and without its stand-in
	// its earlier results would stay "current" forever instead of kept and
	// marked stale (§2.14.13). The selection's history, not the rows, is what
	// makes the stand-in LAST: this scan's reconciliation deletes the
	// deselected region's workloads below, and a region that held none never
	// left a row -- yet an earlier run reached it, and without a stand-in the
	// revision keeps showing that run's "reached" for a region nobody reads.
	previously, err := s.workloads.RegionsForConnector(workspaceID, snapshot.ConnectorID)
	if err != nil {
		return nil, err
	}
	previously = append(previously, connector.AWSAttrs().DeselectedRegions()...)
	for _, region := range unselectedRegions(regions, previously...) {
		out.Surfaces[models.SurfaceCompute(region)] = models.SurfaceCoverage{
			State: models.CloudCoverageNotSelected,
			Error: "region not in the connector's selected scope",
		}
	}

	// ---- activity, which is global because IAM is -------------------------
	activity := s.scanActivity(ctx, workspaceID, snapshot, out)
	out.setSurface(models.SurfaceActivity, activity)

	// Each table is reconciled on the surfaces it depends on, and only those
	// (T3.7). The IAM baseline gates both, as before: a workload or a usage
	// row is attributed to an identity that scan must have read.
	//
	// Workloads are reconciled PER SURFACE: only the rows of a (runtime kind,
	// region) whose surface was reached this run can be absent. A surface
	// that is partial, denied or throttled keeps its own rows and costs no
	// other surface anything -- one gateway whose GetGateway the stack does
	// not grant must not stop a deleted Lambda from ever leaving Cloud
	// Inventory: the connector-wide veto §1.3 removes for unoffered regions.
	iamComplete := snapshot.Coverage.Complete()
	out.WorkloadsComplete = iamComplete && out.computeAuthoritative()
	out.UsageComplete = iamComplete && activity.State == models.CloudCoverageReached
	out.Complete = out.WorkloadsComplete && out.UsageComplete

	if iamComplete {
		if scopes, reached := out.reachedWorkloadScopes(); len(scopes) > 0 {
			if _, err := s.workloads.ReconcileWorkloads(
				workspaceID, snapshot.ConnectorID, snapshot.Generation, scopes); err != nil {
				return out, err
			}
			out.ReconciledSurfaces = reached
		}
	}
	if out.UsageComplete {
		if _, err := s.workloads.ReconcileUsage(
			workspaceID, snapshot.ConnectorID, snapshot.Generation); err != nil {
			return out, err
		}
	}
	return out, nil
}

// arnScope is what a constructed workload ARN is built in: the connector's
// partition ("" is aws) and account.
type arnScope struct {
	partition, account string
}

// setSurface records one surface's coverage. Only a state that BLOCKS is also
// written to Errors: unsupported and not_selected are not errors, and reached
// is not either.
func (out *WorkloadSnapshot) setSurface(key string, cov models.SurfaceCoverage) {
	out.Surfaces[key] = cov
	if !nonBlocking(cov.State) {
		out.Errors[key] = cov.Error
	}
}

// nonBlocking is the set of states that do not block ending a relationship or
// deleting a row (§1.4): reached, and the two that mean nothing there is
// claimed. Everything else -- partial, denied, throttled -- keeps what the
// surface last confirmed.
func nonBlocking(state string) bool {
	switch state {
	case models.CloudCoverageReached, models.CloudCoverageNotSelected, models.CloudCoverageUnsupported:
		return true
	}
	return false
}

// computeSurfaceKinds maps each surface cloud_workload rows come from to the
// runtime kind its rows are stored under. They, and only they, license
// deleting workloads -- each its own kind in its own region. The bonus
// surfaces (AgentCore workload identities and credential providers,
// CloudTrail) have no reconciled table and never gate it.
var computeSurfaceKinds = map[string]string{
	models.SurfaceLambdaPrefix:            models.WorkloadLambdaFunction,
	models.SurfaceECSPrefix:               models.WorkloadECSTaskDefinition,
	models.SurfaceEC2Prefix:               models.WorkloadEC2Instance,
	models.SurfaceBedrockAgentsPrefix:     models.WorkloadBedrockAgent,
	models.SurfaceBedrockAgentCorePrefix:  models.WorkloadBedrockAgentCoreRT,
	models.SurfaceAgentCoreGatewaysPrefix: models.WorkloadBedrockAgentCoreGW,
}

// computeStandIn is the per-region stand-in's prefix, models.SurfaceCompute
// without its colon. It speaks for no runtime kind -- it is written when the
// region's services never ran -- so it licenses no deletion, but it does make
// the table as a whole unauthoritative (computeAuthoritative).
var computeStandIn = strings.TrimSuffix(models.SurfaceComputePrefix, ":")

// splitSurface splits "lambda:us-east-1" into its prefix and region.
func splitSurface(key string) (prefix, region string) {
	if i := strings.Index(key, ":"); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// reachedWorkloadScopes is the one place workload absence is inferred: the
// (runtime kind, region) of every compute surface REACHED this run, with the
// surface keys they came from, sorted. Only reached -- "absence is only ever
// inferred from reached" (§1.4). Partial, denied and throttled keep their
// rows; not_selected keeps them too ("earlier results are kept and marked
// stale", §2.14.13); unsupported has none to delete (regionalCoverage reports
// a kind an earlier scan found in that region as denied, never unsupported).
func (out *WorkloadSnapshot) reachedWorkloadScopes() ([]repositories.WorkloadScope, []string) {
	var keys []string
	for key, cov := range out.Surfaces {
		prefix, region := splitSurface(key)
		if _, ok := computeSurfaceKinds[prefix]; ok && region != "" && cov.State == models.CloudCoverageReached {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	scopes := make([]repositories.WorkloadScope, 0, len(keys))
	for _, key := range keys {
		prefix, region := splitSurface(key)
		scopes = append(scopes, repositories.WorkloadScope{RuntimeKind: computeSurfaceKinds[prefix], Region: region})
	}
	return scopes, keys
}

// computeAuthoritative reports whether every compute surface this run reported
// is in a non-blocking state -- derived from the coverage itself, so a
// detail-call failure (partial) counts against it and a service not offered in
// a region (unsupported) does not (§1.3). It reports on the whole table
// (WorkloadsComplete); the deletion gate is per surface, reachedWorkloadScopes.
//
// And at least one compute surface must have been READ: a run whose every
// compute surface was not selected or unsupported established nothing -- the
// same rule ScanCoverage.Complete applies ("attempted > 0"). It is what keeps a
// resolver that answers NXDOMAIN for everything from reading as an empty
// estate.
func (out *WorkloadSnapshot) computeAuthoritative() bool {
	read := false
	for key, cov := range out.Surfaces {
		prefix, _ := splitSurface(key)
		if _, ok := computeSurfaceKinds[prefix]; !ok && prefix != computeStandIn {
			continue
		}
		if !nonBlocking(cov.State) {
			return false
		}
		read = read || cov.State == models.CloudCoverageReached
	}
	return read
}

// awsRegionsWithCompute is every region AuthSec can read compute in, as a
// default "not selected" list. Kept here rather than fetched per scan: the
// template grants ec2:DescribeRegions (2026-09-23) for region SELECTION, but a
// scan must not fail -- or cost a call per run -- to report an absence.
var awsRegionsWithCompute = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ca-central-1", "sa-east-1",
}

func unselectedRegions(selected []string, alsoKnown ...string) []string {
	chosen := make(map[string]bool, len(selected))
	for _, r := range selected {
		chosen[r] = true
	}
	var out []string
	for _, r := range append(append([]string{}, awsRegionsWithCompute...), alsoKnown...) {
		if !chosen[r] {
			chosen[r] = true // each region once
			out = append(out, r)
		}
	}
	return out
}

// scanRegion reads every compute surface in one region.
//
// Each surface is independent: a denied ECS read must not cost the Lambda
// functions already found, so failures are recorded per surface and the next is
// attempted.
func (s *AWSWorkloadScanner) scanRegion(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	scope arnScope, region string, out *WorkloadSnapshot,
) {
	cfgFor := func() (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI, awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI, awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI, error) {
		if s.regionalAPIs != nil {
			l, e, c, p, b, ac, ct := s.regionalAPIs(region)
			return l, e, c, p, b, ac, ct, nil
		}
		// Injected clients win, and stand in for every region.
		if s.lambdaAPI != nil || s.ecsAPI != nil || s.ec2API != nil ||
			s.bedrockAPI != nil || s.agentCoreAPI != nil || s.cloudTrailAPI != nil {
			return s.lambdaAPI, s.ecsAPI, s.ec2API, s.profileAPI, s.bedrockAPI, s.agentCoreAPI, s.cloudTrailAPI, nil
		}
		if s.onboarding == nil {
			return nil, nil, nil, nil, nil, nil, nil,
				errors.New("no compute clients and no onboarding service to assume a role with")
		}
		cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, snapshot.ConnectorID, region)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return awsdiscovery.NewLambdaClient(cfg), awsdiscovery.NewECSClient(cfg),
			awsdiscovery.NewEC2Client(cfg), awsdiscovery.NewInstanceProfileClient(cfg),
			awsdiscovery.NewBedrockAgentClient(cfg), awsdiscovery.NewAgentCoreClient(cfg),
			awsdiscovery.NewCloudTrailClient(cfg), nil
	}

	l, e, c, p, b, ac, ct, err := cfgFor()
	if err != nil {
		// Nothing in this region was even attempted -- one surface entry
		// stands in for the services that never ran, so computeAuthoritative
		// and the graph's region gate see this region as unreached instead of
		// silently passing it.
		out.setSurface(models.SurfaceCompute(region), models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Error: err.Error(),
		})
		return
	}

	compute := awsdiscovery.NewWorkloadReader(l, e, c, p)
	// Scoped, so an agent or gateway whose detail call fails is still keyed by
	// its ARN, constructed in the connector's partition (T3.6).
	bedrock := awsdiscovery.NewBedrockReader(b, ac).WithScope(scope.partition, region, scope.account)
	trail := awsdiscovery.NewCloudTrailReader(ct)

	surfaces := []struct {
		prefix      string
		runtimeKind string
		read        func(context.Context) ([]awsdiscovery.Workload, error)
	}{
		{models.SurfaceLambdaPrefix, models.WorkloadLambdaFunction, compute.LambdaFunctions},
		{models.SurfaceECSPrefix, models.WorkloadECSTaskDefinition, compute.ECSTaskDefinitions},
		{models.SurfaceEC2Prefix, models.WorkloadEC2Instance, compute.EC2Instances},
		{models.SurfaceBedrockAgentsPrefix, models.WorkloadBedrockAgent, bedrock.Agents},
		{models.SurfaceBedrockAgentCorePrefix, models.WorkloadBedrockAgentCoreRT, bedrock.AgentRuntimes},
	}

	for _, surface := range surfaces {
		key := models.SurfaceRegional(surface.prefix, region)
		// err is a listing failure (denied, throttled, not offered here) or an
		// *awsdiscovery.ItemFailures: listed, but some detail calls failed.
		// Whatever was read is real and still worth recording either way;
		// surfaceResult decides what the surface may claim.
		found, err := surface.read(ctx)
		for _, w := range found {
			if _, werr := s.recordWorkload(workspaceID, snapshot, key, region, w, out); werr != nil {
				err = werr
				break
			}
		}
		out.setSurface(key, s.regionalCoverage(workspaceID, snapshot.ConnectorID,
			surface.runtimeKind, region, len(found), err))
	}

	s.scanGateways(ctx, workspaceID, snapshot, region, bedrock, out)
	s.scanWorkloadIdentities(ctx, workspaceID, snapshot, region, bedrock, out)
	s.scanCredentialProviders(ctx, workspaceID, snapshot, region, bedrock, out)
	s.scanCloudTrail(ctx, workspaceID, snapshot, region, trail, out)
	s.scanTrailStatus(ctx, workspaceID, snapshot, region, trail, out)
}

// scanGateways reads AgentCore Gateways and their targets. Gateways are
// written to cloud_workload through the same recordWorkload path as Lambda,
// ECS, EC2 and the other managed-agent surfaces. Targets are ATTRIBUTES of the
// gateway (§1.4): carried on its row (attrs.gateway_targets, with id, name,
// status and type) and recorded as evidence under it, keyed by the target id so
// a target's observation never stands in for the gateway's own.
func (s *AWSWorkloadScanner) scanGateways(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, bedrock *awsdiscovery.BedrockReader, out *WorkloadSnapshot,
) {
	key := models.SurfaceRegional(models.SurfaceAgentCoreGatewaysPrefix, region)
	// A failed GetGateway or ListGatewayTargets comes back as ItemFailures:
	// agentcore-gateways:<region> partial, never silently reached (T3.6).
	workloads, _, err := bedrock.Gateways(ctx)

	for _, w := range workloads {
		stored, werr := s.recordWorkload(workspaceID, snapshot, key, region, w, out)
		if werr != nil {
			err = werr
			continue
		}
		if s.evidence == nil || stored == nil {
			continue
		}
		for _, t := range w.Targets {
			if rerr := s.evidence.Record(
				WorkloadSubject(stored.ID), "bedrock-agentcore:ListGatewayTargets",
				key, "", time.Now(), t.TargetID,
				map[string]any{
					"gateway_native_id": t.GatewayNativeID,
					"target_id":         t.TargetID,
					"name":              t.Name,
					"status":            t.Status,
					"type":              t.Type,
				},
			); rerr != nil {
				log.Printf("aws workload scan: gateway target evidence for %s: %v", t.TargetID, rerr)
			}
		}
	}
	out.setSurface(key, s.regionalCoverage(workspaceID, snapshot.ConnectorID,
		models.WorkloadBedrockAgentCoreGW, region, len(workloads), err))
}

// regionalCoverage is surfaceResult for one compute surface in one region,
// with one extra guard on "unsupported".
//
// An endpoint that does not resolve means the service is not offered there
// (ErrServiceNotInRegion), and unsupported blocks nothing. But if an earlier
// scan COLLECTED this runtime kind in this region, the service evidently is
// offered there, and a resolver failure is the likelier story; unsupported
// would then tell every reader that nothing there is claimed -- coverage
// "complete", no conclusion prevented (D-58) -- over rows that scan found. So
// it is reported denied instead -- the call failed -- with the reason spelled
// out. Never claim more than the data proves. (It is also why unsupported
// never has rows of its own for reachedWorkloadScopes to leave out.)
func (s *AWSWorkloadScanner) regionalCoverage(
	workspaceID, connectorID uuid.UUID, runtimeKind, region string, count int, err error,
) models.SurfaceCoverage {
	cov := surfaceResult(count, err)
	if cov.State != models.CloudCoverageUnsupported || runtimeKind == "" {
		return cov
	}
	prior, cerr := s.workloads.CountWorkloads(workspaceID, connectorID, runtimeKind, region)
	switch {
	case cerr != nil:
		return models.SurfaceCoverage{State: models.CloudCoverageDenied, Count: count, API: cov.API,
			Error: fmt.Sprintf("%s (and whether earlier scans found %s here could not be checked: %v)",
				cov.Error, runtimeKind, cerr)}
	case prior > 0:
		return models.SurfaceCoverage{State: models.CloudCoverageDenied, Count: count, API: cov.API,
			Error: fmt.Sprintf("%s, but an earlier scan collected %d %s here; not treated as unsupported",
				cov.Error, prior, runtimeKind)}
	}
	cov.Error = fmt.Sprintf("not offered in %s (%s)", region, cov.Error)
	return cov
}

// scanWorkloadIdentities reads AgentCore's own workload identities and
// records each as evidence, not as a cloud_identity row -- see
// AgentCoreAPI.ListWorkloadIdentities for why writing into that table from
// here would fight IAM scanning's own reconciliation of it.
func (s *AWSWorkloadScanner) scanWorkloadIdentities(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, bedrock *awsdiscovery.BedrockReader, out *WorkloadSnapshot,
) {
	// Deliberately NOT a compute surface (computeSurfaceKinds), so it never
	// counts against out.WorkloadsComplete nor licenses or blocks any
	// ReconcileWorkloads scope: this surface is bonus evidence with no
	// reconciled table of its own, and a
	// customer whose deployed role predates this permission must not have
	// their otherwise-complete Lambda/ECS/EC2 scan refuse to age out stale
	// rows over a surface those rows have nothing to do with. Its coverage is
	// still reported exactly (and unsupported where AgentCore is not offered).
	key := models.SurfaceRegional(models.SurfaceAgentCoreIdentitiesPrefix, region)
	identities, err := bedrock.WorkloadIdentities(ctx)
	if s.evidence != nil {
		for _, wi := range identities {
			if wi.NativeID == "" {
				continue
			}
			// No ObservationSubject constructor fits: a workload identity is
			// not an IAM identity, permission, resource or workload row.
			// ObservationSubject's zero value -- every field nil -- is exactly
			// the "at most one, possibly none" shape D3 relaxed the subject
			// check to allow, used here deliberately rather than as the
			// after-the-fact result of a subject being reconciled away.
			//
			// Deduped by migration 025's partial index
			// (uq_cloud_observation_dedupe_no_subject), scoped to exactly the
			// rows that fall through migration 022's COALESCE-based one: an
			// unchanged re-read confirms the existing row instead of growing
			// the table.
			if rerr := s.evidence.Record(
				ObservationSubject{}, "bedrock-agentcore:ListWorkloadIdentities",
				key, "", time.Now(), wi.NativeID,
				map[string]any{"name": wi.Name, "arn": wi.NativeID},
			); rerr != nil {
				log.Printf("aws workload scan: workload identity evidence for %s: %v", wi.NativeID, rerr)
			}
		}
	}
	out.Surfaces[key] = surfaceResult(len(identities), err)
}

// scanCredentialProviders reads AgentCore's OAuth2 and API-key credential
// providers and records each as subject-less evidence, same reasoning and
// same dedupe key as scanWorkloadIdentities just above: a credential
// provider is not an IAM identity, permission, resource or workload, has no
// reconciled table of its own, and must not gate Lambda/ECS/EC2's own
// otherwise-complete reconciliation.
func (s *AWSWorkloadScanner) scanCredentialProviders(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, bedrock *awsdiscovery.BedrockReader, out *WorkloadSnapshot,
) {
	key := models.SurfaceRegional(models.SurfaceAgentCoreCredProviderPrefix, region)
	providers, err := bedrock.CredentialProviders(ctx)
	if s.evidence != nil {
		for _, p := range providers {
			if p.NativeID == "" {
				continue
			}
			facts := map[string]any{"name": p.Name, "arn": p.NativeID, "kind": p.Kind}
			if p.Vendor != "" {
				facts["vendor"] = p.Vendor
			}
			if rerr := s.evidence.Record(
				ObservationSubject{}, p.SourceAPI, key, "", time.Now(), p.NativeID, facts,
			); rerr != nil {
				log.Printf("aws workload scan: credential provider evidence for %s: %v", p.NativeID, rerr)
			}
		}
	}
	out.Surfaces[key] = surfaceResult(len(providers), err)
}

// scanCloudTrail reads recent management events and records each as evidence
// against the identity it best-effort matches, per the caveats on
// CloudTrailReader.RecentEvents. Events that match nothing recorded are
// still counted in the surface's total -- the read succeeded even where the
// match did not -- but are not written as evidence with no subject, since
// evidence with nothing to be evidence FOR is not useful evidence.
func (s *AWSWorkloadScanner) scanCloudTrail(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, trail *awsdiscovery.CloudTrailReader, out *WorkloadSnapshot,
) {
	// Not a compute surface -- same reasoning as scanWorkloadIdentities just
	// above: bonus evidence, no reconciled table, must not block
	// Lambda/ECS/EC2's own otherwise-complete reconciliation.
	key := models.SurfaceRegional(models.SurfaceCloudTrailEventsPrefix, region)
	events, err := trail.RecentEvents(ctx)
	if s.evidence != nil && len(events) > 0 {
		// Matched by NAME, not NativeID: CloudTrail's Username is the IAM
		// user's bare name for a direct IAM-user call, never the identity's
		// ARN -- matching against NativeID, as every other reader in this
		// package keys identities, would never hit even the one case this
		// CAN confidently resolve. It still will not match an assumed-role
		// call, where Username is a session name -- see the file header.
		//
		// Bounded to 500 identities (clampLimit's own ceiling): matching
		// against every identity a large account has is this function's job,
		// not a reason to add pagination to a best-effort join.
		byName := make(map[string]models.CloudIdentity)
		if identities, _, ierr := s.identities.ListIdentities(workspaceID,
			repositories.CloudIdentityFilter{ConnectorID: &snapshot.ConnectorID, Limit: 500}); ierr == nil {
			for _, id := range identities {
				if id.Name != "" {
					byName[id.Name] = id
				}
			}
		}
		for _, e := range events {
			identity, matched := byName[e.Username]
			if !matched {
				// No confident match. Recorded in the surface's count above,
				// not as an orphaned observation -- see the function comment.
				continue
			}
			// Keyed by the event, not by the identity's ARN: an event is
			// activity, and must not become supporting evidence on every edge
			// the identity holds (igagraph.CloudTrailEventEvidenceKey). The
			// typed subject is still the identity, which is what Cloud
			// Inventory reads it by.
			if rerr := s.evidence.Record(
				IdentitySubject(identity.ID), "cloudtrail:LookupEvents",
				key, "", e.EventTime, igagraph.CloudTrailEventEvidenceKey(identity.NativeID, e.EventID),
				map[string]any{
					"event_id":     e.EventID,
					"event_name":   e.EventName,
					"event_source": e.EventSource,
					"username":     e.Username,
					"denied":       e.Denied,
					"error_code":   e.ErrorCode,
				},
			); rerr != nil {
				log.Printf("aws workload scan: cloudtrail evidence for %s: %v", e.EventID, rerr)
			}
		}
	}
	out.Surfaces[key] = surfaceResult(len(events), err)
}

// scanTrailStatus reads each trail's configuration and whether it is
// actually logging, and records both as subject-less evidence. This is what
// tells scanCloudTrail's own silence apart from a blind account: RecentEvents
// finding nothing is unremarkable for a quiet identity but alarming for an
// account with no trail logging at all, and only this surface can say which
// one happened.
//
// Recorded under two source APIs, matching the two AWS calls Trails makes:
// DescribeTrails for the configuration, GetTrailStatus for whether it is
// live. Same reasoning as scanCredentialProviders for why this is bonus
// evidence with no reconciled table, and not a compute surface.
func (s *AWSWorkloadScanner) scanTrailStatus(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, trail *awsdiscovery.CloudTrailReader, out *WorkloadSnapshot,
) {
	key := models.SurfaceRegional(models.SurfaceCloudTrailStatusPrefix, region)
	trails, err := trail.Trails(ctx)
	if s.evidence != nil {
		for _, t := range trails {
			if t.NativeID == "" {
				continue
			}
			if rerr := s.evidence.Record(
				ObservationSubject{}, "cloudtrail:DescribeTrails", key, "", time.Now(), t.NativeID,
				map[string]any{
					"name":                          t.Name,
					"arn":                           t.NativeID,
					"home_region":                   t.HomeRegion,
					"is_multi_region_trail":         t.IsMultiRegionTrail,
					"is_organization_trail":         t.IsOrganizationTrail,
					"include_global_service_events": t.IncludeGlobalServiceEvents,
					"log_file_validation_enabled":   t.LogFileValidationEnabled,
				},
			); rerr != nil {
				log.Printf("aws workload scan: trail config evidence for %s: %v", t.NativeID, rerr)
			}
			if t.IsLogging == nil {
				// GetTrailStatus failed for this trail -- unknown, not "not
				// logging". Nothing worth recording under this source API.
				continue
			}
			if rerr := s.evidence.Record(
				ObservationSubject{}, "cloudtrail:GetTrailStatus", key, "", time.Now(), t.NativeID,
				map[string]any{"arn": t.NativeID, "is_logging": *t.IsLogging},
			); rerr != nil {
				log.Printf("aws workload scan: trail status evidence for %s: %v", t.NativeID, rerr)
			}
		}
	}
	out.Surfaces[key] = surfaceResult(len(trails), err)
}

// recordWorkload writes one workload, attributing it to a discovered identity
// where possible. Returns the stored row so a caller with more evidence to
// attach under the same subject -- a gateway's targets, say -- does not have
// to re-fetch it.
//
// surface is the per-service coverage key the row came from (lambda:<region>,
// ...), stamped on its evidence.
func (s *AWSWorkloadScanner) recordWorkload(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, surface, region string,
	w awsdiscovery.Workload, out *WorkloadSnapshot,
) (*models.CloudWorkload, error) {

	workload := &models.CloudWorkload{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		RuntimeKind:        w.RuntimeKind,
		NativeID:           w.NativeID,
		Name:               w.Name,
		Region:             region,
		LastSeenGeneration: snapshot.Generation,
	}

	attrs := models.AWSWorkloadAttrs{
		ExecutionRoleARN:   w.ExecutionRoleARN,
		InstanceProfileARN: w.InstanceProfileARN,
		EnvVarNames:        w.EnvVarNames,
		EnvVarsUnread:      w.EnvVarsUnread,
		FoundationModel:    w.FoundationModel,
		Status:             w.Status,
		DetailIncomplete:   w.DetailIncomplete,
		DetailError:        w.DetailError,
		TargetsIncomplete:  w.TargetsIncomplete,
	}
	for _, t := range w.Targets {
		attrs.GatewayTargets = append(attrs.GatewayTargets, models.AWSGatewayTarget{
			TargetID: t.TargetID, Name: t.Name, Status: t.Status, Type: t.Type,
		})
	}

	// Attribution. A role the IAM scan never recorded leaves identity_id NULL
	// and the ARN in attrs, so the row still says which role it was looking
	// for -- that is a finding, not a defect.
	//
	// A workload whose detail call FAILED is neither: its role is unknown this
	// run. It is not counted unattributed, and UpsertWorkload keeps the
	// previous attribution rather than clearing it (D-53).
	switch {
	case w.DetailIncomplete:
		out.DetailIncomplete++
	case w.RoleARN != "":
		identity, err := s.identities.GetIdentityByNativeID(workspaceID, w.RoleARN)
		switch {
		case err == nil:
			workload.IdentityID = &identity.ID
		case errors.Is(err, repositories.ErrCloudIdentityNotFound):
			attrs.UnresolvedRoleARN = w.RoleARN
			out.Unattributed++
		default:
			return nil, err
		}
	default:
		out.Unattributed++
	}

	if err := workload.SetAWSAttrs(attrs); err != nil {
		return nil, err
	}
	stored, _, err := s.workloads.UpsertWorkload(workload)
	if err != nil {
		return nil, fmt.Errorf("record workload %s: %w", w.NativeID, err)
	}
	out.WorkloadsWritten++

	// Evidence for "this compute runs as that identity" -- the single most
	// consequential edge the inventory draws, and the one a reviewer is most
	// likely to challenge. `identity_native_id` is recorded even when the
	// identity was not found, because "names a role we never discovered" is
	// itself the finding for an unattributed workload.
	if s.evidence != nil && stored != nil {
		facts := map[string]any{
			"runtime_kind": w.RuntimeKind,
			"native_id":    w.NativeID,
			"name":         w.Name,
			"region":       region,
		}
		if w.DetailIncomplete {
			// Only what the LISTING proved, and which call failed: no
			// attribution fact at all, because none was read (D-53).
			facts["detail_incomplete"] = true
			facts["detail_error"] = w.DetailError
		} else {
			// Unchanged keys for a complete read, so an unchanged workload
			// keeps deduping onto the observation it already has.
			facts["identity_native_id"] = w.RoleARN
			facts["attributed"] = workload.IdentityID != nil
		}
		if err := s.evidence.Record(
			WorkloadSubject(stored.ID),
			// The call that actually produced this row (the listing, when the
			// detail read failed) and the per-service surface it came from --
			// what the Evidence panel names (§2.14.7). The compute:<region>
			// stand-in is a coverage marker, not a source.
			workloadSourceAPI(w), surface, "",
			time.Now(), w.NativeID, facts,
		); err != nil {
			log.Printf("aws workload scan: evidence for %s: %v", w.NativeID, err)
		}
	}
	out.ByKind[w.RuntimeKind]++
	return stored, nil
}

// WithEvidence attaches an observation writer for this run.
func (s *AWSWorkloadScanner) WithEvidence(w *ObservationWriter) *AWSWorkloadScanner {
	s.evidence = w
	return s
}

// WithFence fences the workload and usage writes so a superseded worker
// cannot land them (§2.10A, part 3).
func (s *AWSWorkloadScanner) WithFence(f repositories.ScanFence) *AWSWorkloadScanner {
	s.workloads = s.workloads.Fenced(f)
	return s
}

// workloadSourceAPI names the call a row came from, so evidence points at
// something a reader can re-issue themselves: the reader's own SourceAPI --
// the call that actually returned the data, the listing when a detail call
// failed -- else the kind's usual call. Gateways had no entry here and every
// one was labelled aws:unknown (§1.3, T3.5).
func workloadSourceAPI(w awsdiscovery.Workload) string {
	if w.SourceAPI != "" {
		return w.SourceAPI
	}
	switch w.RuntimeKind {
	case models.WorkloadLambdaFunction:
		return "lambda:ListFunctions"
	case models.WorkloadECSTaskDefinition:
		return "ecs:DescribeTaskDefinition"
	case models.WorkloadEC2Instance:
		return "ec2:DescribeInstances"
	case models.WorkloadBedrockAgent:
		return "bedrock:GetAgent"
	case models.WorkloadBedrockAgentCoreRT:
		return "bedrock-agentcore:GetAgentRuntime"
	case models.WorkloadBedrockAgentCoreGW:
		return "bedrock-agentcore:GetGateway"
	default:
		return "aws:unknown"
	}
}

// scanActivity reads service-last-accessed for the connector's identities and
// returns the activity surface's coverage (T3.7).
//
// One report job per identity, each of which is a submit plus polling, so this
// is the most expensive surface in the whole AWS connector, and it is capped
// (activityIdentityCap). The coverage says exactly what that cost:
//
//   - reached    every identity's report was read;
//   - partial    the cap applied ("500 of 1234 identities"), or some reports
//     failed while others were read;
//   - throttled  AWS throttled a report past the retry budget ("throttled on
//     throttle", §1.3 -- it used to be reported denied);
//   - denied     no attempted report could be read.
//
// Count is the usage rows written, a floor whenever the state is not reached;
// the Error names the identities, and above the cap CappedAfter names the last
// ARN sampled. Anything but reached keeps every usage row the last good read
// wrote (UsageComplete gates ReconcileUsage), and none of it blocks workload
// reconciliation any more.
func (s *AWSWorkloadScanner) scanActivity(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot, out *WorkloadSnapshot,
) models.SurfaceCoverage {
	api := s.activityAPI
	if api == nil {
		if s.onboarding == nil {
			return models.SurfaceCoverage{State: models.CloudCoverageDenied,
				Error: "no service-last-accessed client and no onboarding service to assume a role with"}
		}
		cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, snapshot.ConnectorID, "")
		if err != nil {
			return surfaceResult(0, err)
		}
		api = awsdiscovery.NewServiceLastAccessedClient(cfg)
	}

	reader := awsdiscovery.NewActivityReader(api)
	if s.activitySleep != nil {
		reader = reader.WithSleep(s.activitySleep)
	}

	// The total is kept, not discarded: an account above the cap must say so,
	// or the identities past it silently read as having no activity (§1.3).
	// The sample is the first activityIdentityCap identities by ARN (D-86):
	// the same identities every scan while the inventory is unchanged, and a
	// set a reader can name from CappedAfter below.
	identities, total, err := s.workloads.ActivitySample(workspaceID, snapshot.ConnectorID, activityIdentityCap)
	if err != nil {
		return models.SurfaceCoverage{State: models.CloudCoverageDenied, Error: err.Error()}
	}

	reads := awsdiscovery.NewItemFailures("identities' activity reports could not be read", false)
	var writeErr error
	for _, identity := range identities {
		reads.Attempt()
		activity, err := reader.ServiceActivityFor(ctx, identity.NativeID)
		if err != nil {
			// One identity's report failing does not mean the rest will. It is
			// counted, so nothing is reconciled away, and the remaining
			// identities are still attempted.
			reads.Fail(identity.NativeID, activityCall(err), err)
			continue
		}
		for _, svc := range activity {
			usage := &models.CloudUsage{
				WorkspaceID:        workspaceID,
				ConnectorID:        snapshot.ConnectorID,
				IdentityID:         identity.ID,
				Service:            svc.Service,
				LastUsedAt:         svc.LastUsedAt,
				GeneratedAt:        svc.GeneratedAt,
				Source:             models.UsageSourceServiceLastAccessed,
				LastSeenGeneration: snapshot.Generation,
			}
			if _, _, err := s.workloads.UpsertUsage(usage); err != nil {
				if writeErr == nil {
					writeErr = err
				}
				break
			}
			out.UsageWritten++
		}
	}
	if writeErr != nil {
		// Our own write failed: nothing about the account, but this run's usage
		// is not whole, and it must not be reconciled as if it were.
		return models.SurfaceCoverage{State: models.CloudCoverageDenied, Count: out.UsageWritten,
			Error: "recording activity: " + writeErr.Error()}
	}

	cov := surfaceResult(out.UsageWritten, reads.Err(nil))
	if total > int64(len(identities)) && len(identities) > 0 {
		capped := fmt.Sprintf("activity was read for %d of %d identities (Access Advisor is capped at %d identities per scan)",
			len(identities), total, activityIdentityCap)
		if cov.State == models.CloudCoverageReached {
			cov = models.SurfaceCoverage{State: models.CloudCoveragePartial, Count: out.UsageWritten, Error: capped}
		} else {
			// throttled / denied / partial already block; the cap is named too.
			cov.Error += "; " + capped
		}
		// Where the sample ended (D-86): every identity whose ARN sorts after
		// this one was not read this run -- "not collected", never "no attempt
		// reported".
		cov.CappedAfter = identities[len(identities)-1].NativeID
	}
	return cov
}

// activityCall is the call an activity read failed on, for the coverage text;
// the reader names it on every error it returns.
func activityCall(err error) string {
	if call := awsdiscovery.CallName(err); call != "" {
		return call
	}
	return "iam:GetServiceLastAccessedDetails"
}

// activityIdentityCap bounds how many identities one scan will submit report
// jobs for.
//
// Each one costs a submit plus polling, so an account with thousands of roles
// would otherwise turn this surface into the whole scan. The cap is high enough
// for any account seen so far and exists to make the cost bounded rather than
// to express a limit anyone should hit; an account above it reports activity for
// the identities it did reach and the surface reads partial, naming both
// counts (T3.7).
const activityIdentityCap = 500

func (s *AWSWorkloadScanner) connector(
	workspaceID, connectorID uuid.UUID,
) (*models.CloudConnector, error) {
	if s.onboarding == nil {
		return nil, errors.New("no onboarding service to read the connector's regions from")
	}
	return s.onboarding.Connector(workspaceID, connectorID)
}
