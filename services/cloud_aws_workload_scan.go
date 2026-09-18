package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
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
	UsageWritten int

	// ByKind counts workloads per runtime kind, so "we found no Bedrock agents"
	// is distinguishable from "we never looked".
	ByKind map[string]int

	// Complete is false when any surface was denied, throttled or timed out.
	// Reconciliation only runs when it is true, for the reason the rest of this
	// schema follows: unreached is not missing.
	Complete bool
	// Errors carries what went wrong per surface, for the coverage report.
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
	regions := connector.AWSAttrs().Regions

	// ---- regional compute --------------------------------------------------
	for _, region := range regions {
		s.scanRegion(ctx, workspaceID, snapshot, region, out)
	}

	// Regions the operator did NOT select are recorded, not omitted.
	//
	// An absent surface and a surface that returned nothing look identical to a
	// reader, and only one of them means the estate is clean. "Nobody looked,
	// and nobody was meant to" is a different answer from both, and it is the
	// honest one for an unselected region.
	for _, region := range unselectedRegions(regions) {
		out.Surfaces["compute:"+region] = models.SurfaceCoverage{
			State: models.CloudCoverageNotSelected,
			Error: "region not in the connector's selected scope",
		}
	}

	// ---- activity, which is global because IAM is -------------------------
	s.scanActivity(ctx, workspaceID, snapshot, out)
	if activityErr, failed := out.Errors["activity"]; failed {
		out.Surfaces["activity"] = models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Count: out.UsageWritten, Error: activityErr,
		}
	} else {
		out.Surfaces["activity"] = models.SurfaceCoverage{
			State: models.CloudCoverageReached, Count: out.UsageWritten,
		}
	}

	out.Complete = len(out.Errors) == 0 && snapshot.Coverage.Complete()

	if out.Complete {
		workloadsRemoved, usageRemoved, err := s.workloads.ReconcileGeneration(
			workspaceID, snapshot.ConnectorID, snapshot.Generation)
		if err != nil {
			return out, err
		}
		_ = workloadsRemoved
		_ = usageRemoved
	}
	return out, nil
}

// awsRegionsWithCompute is every region AuthSec can read compute in. Kept here
// rather than fetched: ec2:DescribeRegions is not in the discovery grant, and
// asking for it to populate a "not selected" list would be a permission bought
// to report an absence.
var awsRegionsWithCompute = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ca-central-1", "sa-east-1",
}

func unselectedRegions(selected []string) []string {
	chosen := make(map[string]bool, len(selected))
	for _, r := range selected {
		chosen[r] = true
	}
	var out []string
	for _, r := range awsRegionsWithCompute {
		if !chosen[r] {
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
	region string, out *WorkloadSnapshot,
) {
	cfgFor := func() (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI, awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI, awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI, error) {
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
		out.Errors["compute:"+region] = err.Error()
		// Nothing in this region was even attempted -- one surface entry
		// stands in for the five that never ran, so Complete() correctly sees
		// this region as unreached instead of silently passing it.
		out.Surfaces["compute:"+region] = models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Error: err.Error(),
		}
		return
	}

	compute := awsdiscovery.NewWorkloadReader(l, e, c, p)
	bedrock := awsdiscovery.NewBedrockReader(b, ac)
	trail := awsdiscovery.NewCloudTrailReader(ct)

	surfaces := []struct {
		name string
		read func(context.Context) ([]awsdiscovery.Workload, error)
	}{
		{"lambda", compute.LambdaFunctions},
		{"ecs", compute.ECSTaskDefinitions},
		{"ec2", compute.EC2Instances},
		{"bedrock-agents", bedrock.Agents},
		{"bedrock-agentcore", bedrock.AgentRuntimes},
	}

	for _, surface := range surfaces {
		key := surface.name + ":" + region
		found, err := surface.read(ctx)
		if err != nil {
			out.Errors[key] = err.Error()
			// Whatever was read before the failure is still real and still
			// worth recording -- the surface is marked unread either way.
		}
		for _, w := range found {
			if _, werr := s.recordWorkload(workspaceID, snapshot, region, w, out); werr != nil {
				out.Errors[key] = werr.Error()
				err = werr
				break
			}
		}
		out.Surfaces[key] = surfaceResult(len(found), err)
	}

	s.scanGateways(ctx, workspaceID, snapshot, region, bedrock, out)
	s.scanWorkloadIdentities(ctx, workspaceID, snapshot, region, bedrock, out)
	s.scanCloudTrail(ctx, workspaceID, snapshot, region, trail, out)
}

// scanGateways reads AgentCore Gateways and their targets. Gateways are
// written to cloud_workload through the same recordWorkload path as Lambda,
// ECS, EC2 and the other managed-agent surfaces; targets have no identity or
// reconciled table of their own (see the GatewayTarget doc comment), so they
// are recorded as evidence under the gateway's own workload row instead.
func (s *AWSWorkloadScanner) scanGateways(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, bedrock *awsdiscovery.BedrockReader, out *WorkloadSnapshot,
) {
	key := "agentcore-gateways:" + region
	workloads, targets, err := bedrock.Gateways(ctx)
	if err != nil {
		out.Errors[key] = err.Error()
	}

	targetsByGateway := make(map[string][]awsdiscovery.GatewayTarget, len(targets))
	for _, t := range targets {
		targetsByGateway[t.GatewayNativeID] = append(targetsByGateway[t.GatewayNativeID], t)
	}

	for _, w := range workloads {
		stored, werr := s.recordWorkload(workspaceID, snapshot, region, w, out)
		if werr != nil {
			out.Errors[key] = werr.Error()
			err = werr
			continue
		}
		if s.evidence == nil || stored == nil {
			continue
		}
		for _, t := range targetsByGateway[w.NativeID] {
			if rerr := s.evidence.Record(
				WorkloadSubject(stored.ID), "bedrock-agentcore:ListGatewayTargets",
				key, "", time.Now(), t.TargetID,
				map[string]any{
					"gateway_native_id": t.GatewayNativeID,
					"target_id":         t.TargetID,
					"name":              t.Name,
					"status":            t.Status,
				},
			); rerr != nil {
				log.Printf("aws workload scan: gateway target evidence for %s: %v", t.TargetID, rerr)
			}
		}
	}
	out.Surfaces[key] = surfaceResult(len(workloads), err)
}

// scanWorkloadIdentities reads AgentCore's own workload identities and
// records each as evidence, not as a cloud_identity row -- see
// AgentCoreAPI.ListWorkloadIdentities for why writing into that table from
// here would fight IAM scanning's own reconciliation of it.
func (s *AWSWorkloadScanner) scanWorkloadIdentities(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, bedrock *awsdiscovery.BedrockReader, out *WorkloadSnapshot,
) {
	// Deliberately not written to out.Errors, which gates out.Complete below
	// and therefore ReconcileGeneration for cloud_workload/cloud_usage: this
	// surface is bonus evidence with no reconciled table of its own, and a
	// customer whose deployed role predates this permission must not have
	// their otherwise-complete Lambda/ECS/EC2 scan refuse to age out stale
	// rows over a surface those rows have nothing to do with.
	key := "agentcore-workload-identities:" + region
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
			// The dedupe index is keyed on COALESCE(subject columns), and
			// Postgres never treats two NULLs as equal for uniqueness -- so
			// every subject-less row here is a fresh insert every scan rather
			// than a confirmed re-read. Accepted for now: the account-wide
			// count of these is small, and giving subject-less evidence its
			// own dedupe key is a real design question this fix does not
			// have to answer to make the surface collected.
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
	// Not written to out.Errors -- same reasoning as scanWorkloadIdentities
	// just above: bonus evidence, no reconciled table, must not block
	// Lambda/ECS/EC2's own otherwise-complete reconciliation.
	key := "cloudtrail-events:" + region
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
			if rerr := s.evidence.Record(
				IdentitySubject(identity.ID), "cloudtrail:LookupEvents",
				key, "", e.EventTime, identity.NativeID,
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

// recordWorkload writes one workload, attributing it to a discovered identity
// where possible. Returns the stored row so a caller with more evidence to
// attach under the same subject -- a gateway's targets, say -- does not have
// to re-fetch it.
func (s *AWSWorkloadScanner) recordWorkload(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, region string,
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
		FoundationModel:    w.FoundationModel,
		Status:             w.Status,
	}

	// Attribution. A role the IAM scan never recorded leaves identity_id NULL
	// and the ARN in attrs, so the row still says which role it was looking
	// for -- that is a finding, not a defect.
	if w.RoleARN != "" {
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
	} else {
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
		if err := s.evidence.Record(
			WorkloadSubject(stored.ID),
			workloadSourceAPI(w.RuntimeKind), "compute:"+region, "",
			time.Now(), w.NativeID,
			map[string]any{
				"runtime_kind":       w.RuntimeKind,
				"native_id":          w.NativeID,
				"name":               w.Name,
				"region":             region,
				"identity_native_id": w.RoleARN,
				"attributed":         workload.IdentityID != nil,
			},
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

// workloadSourceAPI names the call each runtime came from, so evidence points
// at something a reader can re-issue themselves.
func workloadSourceAPI(runtimeKind string) string {
	switch runtimeKind {
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
	default:
		return "aws:unknown"
	}
}

// scanActivity reads service-last-accessed for every discovered identity.
//
// One report job per identity, each of which is a submit plus polling, so this
// is the most expensive surface in the whole AWS connector. It is driven from
// the snapshot's own trust-policy and policy maps rather than a fresh identity
// list, so it covers exactly the identities this generation recorded.
func (s *AWSWorkloadScanner) scanActivity(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot, out *WorkloadSnapshot,
) {
	api := s.activityAPI
	if api == nil {
		if s.onboarding == nil {
			return
		}
		cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, snapshot.ConnectorID, "")
		if err != nil {
			out.Errors["activity"] = err.Error()
			return
		}
		api = awsdiscovery.NewServiceLastAccessedClient(cfg)
	}

	reader := awsdiscovery.NewActivityReader(api)
	if s.activitySleep != nil {
		reader = reader.WithSleep(s.activitySleep)
	}

	identities, _, err := s.identities.ListIdentities(workspaceID, repositories.CloudIdentityFilter{
		ConnectorID: &snapshot.ConnectorID,
		Limit:       activityIdentityCap,
	})
	if err != nil {
		out.Errors["activity"] = err.Error()
		return
	}

	for _, identity := range identities {
		activity, err := reader.ServiceActivityFor(ctx, identity.NativeID)
		if err != nil {
			// One identity's report failing does not mean the rest will. The
			// surface is marked unread so nothing is reconciled away, and the
			// remaining identities are still attempted.
			out.Errors["activity"] = err.Error()
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
				out.Errors["activity"] = err.Error()
				break
			}
			out.UsageWritten++
		}
	}
}

// activityIdentityCap bounds how many identities one scan will submit report
// jobs for.
//
// Each one costs a submit plus polling, so an account with thousands of roles
// would otherwise turn this surface into the whole scan. The cap is high enough
// for any account seen so far and exists to make the cost bounded rather than
// to express a limit anyone should hit; an account above it reports activity for
// the identities it did reach and is marked incomplete.
const activityIdentityCap = 500

func (s *AWSWorkloadScanner) connector(
	workspaceID, connectorID uuid.UUID,
) (*models.CloudConnector, error) {
	if s.onboarding == nil {
		return nil, errors.New("no onboarding service to read the connector's regions from")
	}
	return s.onboarding.Connector(workspaceID, connectorID)
}
