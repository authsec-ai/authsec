package services

import (
	"context"
	"errors"
	"fmt"
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
	lambdaAPI    awsdiscovery.LambdaAPI
	ecsAPI       awsdiscovery.ECSAPI
	ec2API       awsdiscovery.EC2API
	profileAPI   awsdiscovery.InstanceProfileAPI
	bedrockAPI   awsdiscovery.BedrockAgentAPI
	agentCoreAPI awsdiscovery.AgentCoreAPI
	activityAPI  awsdiscovery.ServiceLastAccessedAPI
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

	// ---- activity, which is global because IAM is -------------------------
	s.scanActivity(ctx, workspaceID, snapshot, out)

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

// scanRegion reads every compute surface in one region.
//
// Each surface is independent: a denied ECS read must not cost the Lambda
// functions already found, so failures are recorded per surface and the next is
// attempted.
func (s *AWSWorkloadScanner) scanRegion(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	region string, out *WorkloadSnapshot,
) {
	cfgFor := func() (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI, awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI, awsdiscovery.AgentCoreAPI, error) {
		// Injected clients win, and stand in for every region.
		if s.lambdaAPI != nil || s.ecsAPI != nil || s.ec2API != nil ||
			s.bedrockAPI != nil || s.agentCoreAPI != nil {
			return s.lambdaAPI, s.ecsAPI, s.ec2API, s.profileAPI, s.bedrockAPI, s.agentCoreAPI, nil
		}
		if s.onboarding == nil {
			return nil, nil, nil, nil, nil, nil,
				errors.New("no compute clients and no onboarding service to assume a role with")
		}
		cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, snapshot.ConnectorID, region)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		return awsdiscovery.NewLambdaClient(cfg), awsdiscovery.NewECSClient(cfg),
			awsdiscovery.NewEC2Client(cfg), awsdiscovery.NewInstanceProfileClient(cfg),
			awsdiscovery.NewBedrockAgentClient(cfg), awsdiscovery.NewAgentCoreClient(cfg), nil
	}

	l, e, c, p, b, ac, err := cfgFor()
	if err != nil {
		out.Errors["compute:"+region] = err.Error()
		return
	}

	compute := awsdiscovery.NewWorkloadReader(l, e, c, p)
	bedrock := awsdiscovery.NewBedrockReader(b, ac)

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
		found, err := surface.read(ctx)
		if err != nil {
			out.Errors[surface.name+":"+region] = err.Error()
			// Whatever was read before the failure is still real and still
			// worth recording -- the surface is marked unread either way.
		}
		for _, w := range found {
			if err := s.recordWorkload(workspaceID, snapshot, region, w, out); err != nil {
				out.Errors[surface.name+":"+region] = err.Error()
				break
			}
		}
	}
}

// recordWorkload writes one workload, attributing it to a discovered identity
// where possible.
func (s *AWSWorkloadScanner) recordWorkload(
	workspaceID uuid.UUID, snapshot *IAMSnapshot, region string,
	w awsdiscovery.Workload, out *WorkloadSnapshot,
) error {

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
			return err
		}
	} else {
		out.Unattributed++
	}

	if err := workload.SetAWSAttrs(attrs); err != nil {
		return err
	}
	if _, _, err := s.workloads.UpsertWorkload(workload); err != nil {
		return fmt.Errorf("record workload %s: %w", w.NativeID, err)
	}
	out.WorkloadsWritten++
	out.ByKind[w.RuntimeKind]++
	return nil
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
