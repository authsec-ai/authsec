package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// The AWS side of agent containment. Every write goes through the account's
// enforcement credential exactly as access policies and R2 do
// (AWSEnforcementAccess.EnforcementIAM: verified binding, ExternalId from
// Vault, session authsec-enforce-<containment 16hex>, 900 s, SDK retries
// off); IAM policy reads go through the discovery role (§3.5). The preview's
// live reads (the ECS services of a task definition, a function's event
// source mappings) go through the discovery role too: discovery credentials
// never write (spec §5.9).

// AgentContainAccess builds one containment's AWS clients.
type AgentContainAccess interface {
	// Open is the engine's AWS for one run in the connector's account.
	Open(ctx context.Context, ws, connectorID, runID uuid.UUID) (agentcontain.AWS, error)
	// ECSServicesOf lists the ECS services in region whose task definition
	// is of family (discovery role).
	ECSServicesOf(ctx context.Context, ws, connectorID uuid.UUID, region, family string) ([]agentcontain.ECSService, error)
	// EventSourceMappings counts a function's event source mappings
	// (discovery role).
	EventSourceMappings(ctx context.Context, ws, connectorID uuid.UUID, functionARN string) (int, error)
}

var (
	agentContainAccessMu       sync.RWMutex
	agentContainAccessOverride AgentContainAccess
)

// SetAgentContainAccess installs the containment AWS access (tests: a fake
// account). nil restores the production one (the deployment environment's).
func SetAgentContainAccess(a AgentContainAccess) {
	agentContainAccessMu.Lock()
	agentContainAccessOverride = a
	agentContainAccessMu.Unlock()
}

// agentContainAccessInstalled is the access a test installed, or nil.
func agentContainAccessInstalled() AgentContainAccess {
	agentContainAccessMu.RLock()
	defer agentContainAccessMu.RUnlock()
	return agentContainAccessOverride
}

// agentContainAccess is the installed access, else the production one built
// from the deployment environment, else nil (not configured).
func agentContainAccess() AgentContainAccess {
	agentContainAccessMu.RLock()
	o := agentContainAccessOverride
	agentContainAccessMu.RUnlock()
	if o != nil {
		return o
	}
	if a, ok := currentGovDeployEnv().AWS.(*AWSEnforcementAccess); ok && a != nil {
		return liveContainAccess{a: a}
	}
	return nil
}

// liveContainAccess is production: AWSEnforcementAccess's two identities.
type liveContainAccess struct{ a *AWSEnforcementAccess }

func (l liveContainAccess) Open(ctx context.Context, ws, connectorID, runID uuid.UUID) (agentcontain.AWS, error) {
	enf, err := l.a.EnforcementIAM(ctx, ws, connectorID, runID)
	if err != nil {
		return nil, err
	}
	v2, ok := awsenforce.AsIAMv2(enf)
	if !ok {
		return nil, errors.New("the enforcement client has no template v2 operations")
	}
	wc, _ := awsenforce.AsWorkloadContainer(enf)
	disc, err := l.a.DiscoveryIAM(ctx, ws, connectorID)
	if err != nil {
		return nil, err
	}
	return &containAWS{v2: v2, wc: wc, disc: disc}, nil
}

// discoveryConfig is the connector's discovery session in region.
func (l liveContainAccess) discoveryConfig(ctx context.Context, ws, connectorID uuid.UUID, region string) (aws.Config, error) {
	c, err := l.a.connectors.Get(ws, connectorID)
	if err != nil {
		return aws.Config{}, err
	}
	if c.Provider != models.CloudProviderAWS || c.Status != models.CloudConnectorActive {
		return aws.Config{}, enfErr(http.StatusConflict, EnfCodeDiscoveryUnavailable, "The account's discovery connector is not active.", nil)
	}
	if l.a.onboarding == nil {
		return aws.Config{}, errors.New("AWS onboarding is not configured")
	}
	cfg, _, err := l.a.onboarding.ConfigForConnector(ctx, ws, connectorID, region)
	return cfg, err
}

func (l liveContainAccess) ECSServicesOf(ctx context.Context, ws, connectorID uuid.UUID, region, family string) ([]agentcontain.ECSService, error) {
	cfg, err := l.discoveryConfig(ctx, ws, connectorID, region)
	if err != nil {
		return nil, err
	}
	c := ecs.NewFromConfig(cfg)
	var clusters []string
	cp := ecs.NewListClustersPaginator(c, &ecs.ListClustersInput{})
	for cp.HasMorePages() {
		page, err := cp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecs:ListClusters: %w", err)
		}
		clusters = append(clusters, page.ClusterArns...)
	}
	var out []agentcontain.ECSService
	for _, cl := range clusters {
		var arns []string
		sp := ecs.NewListServicesPaginator(c, &ecs.ListServicesInput{Cluster: aws.String(cl)})
		for sp.HasMorePages() {
			page, err := sp.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ecs:ListServices: %w", err)
			}
			arns = append(arns, page.ServiceArns...)
		}
		for i := 0; i < len(arns); i += 10 {
			end := i + 10
			if end > len(arns) {
				end = len(arns)
			}
			d, err := c.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(cl), Services: arns[i:end],
				Include: []ecstypes.ServiceField{ecstypes.ServiceFieldTags}})
			if err != nil {
				return nil, fmt.Errorf("ecs:DescribeServices: %w", err)
			}
			for _, s := range d.Services {
				td := aws.ToString(s.TaskDefinition)
				if agentcontain.TaskDefinitionFamily(td) != family || aws.ToString(s.Status) == "INACTIVE" {
					continue
				}
				tags := map[string]string{}
				for _, t := range s.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
				out = append(out, agentcontain.ECSService{ClusterARN: cl, ServiceARN: aws.ToString(s.ServiceArn), TaskDefinition: td,
					DesiredCount: s.DesiredCount, RunningCount: s.RunningCount, Tags: tags})
			}
		}
	}
	return out, nil
}

func (l liveContainAccess) EventSourceMappings(ctx context.Context, ws, connectorID uuid.UUID, functionARN string) (int, error) {
	region := agentcontain.LambdaRegion(functionARN)
	if region == "" {
		return 0, fmt.Errorf("%q is not a Lambda function ARN", functionARN)
	}
	cfg, err := l.discoveryConfig(ctx, ws, connectorID, region)
	if err != nil {
		return 0, err
	}
	n := 0
	p := lambda.NewListEventSourceMappingsPaginator(lambda.NewFromConfig(cfg), &lambda.ListEventSourceMappingsInput{FunctionName: aws.String(functionARN)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		n += len(page.EventSourceMappings)
	}
	return n, nil
}

// containAWS adapts the enforcement session (v2 IAM and, with the
// parameter, the workload calls) and the discovery reads to agentcontain.AWS.
type containAWS struct {
	v2   awsenforce.IAMv2
	wc   awsenforce.WorkloadContainer // nil: the client cannot (never: the live client can)
	disc awsenforce.DiscoveryIAM
}

var errNoWorkloadCalls = fmt.Errorf("%w: the enforcement client has no workload containment operations", agentcontain.ErrDenied)

func mapNotFound(err error) error {
	if err != nil && awsenforce.IsNotFound(err) {
		return fmt.Errorf("%w: %v", agentcontain.ErrNotFound, err)
	}
	return err
}

func (c *containAWS) GetFunctionConcurrency(ctx context.Context, fn string) (*int32, error) {
	if c.wc == nil {
		return nil, errNoWorkloadCalls
	}
	n, err := c.wc.GetFunctionConcurrency(ctx, fn)
	return n, mapNotFound(err)
}

func (c *containAWS) PutFunctionConcurrency(ctx context.Context, fn string, n int32) error {
	if c.wc == nil {
		return errNoWorkloadCalls
	}
	return mapNotFound(c.wc.PutFunctionConcurrency(ctx, fn, n))
}

func (c *containAWS) DeleteFunctionConcurrency(ctx context.Context, fn string) error {
	if c.wc == nil {
		return errNoWorkloadCalls
	}
	return mapNotFound(c.wc.DeleteFunctionConcurrency(ctx, fn))
}

func (c *containAWS) DescribeService(ctx context.Context, cluster, service string) (*agentcontain.ECSService, error) {
	if c.wc == nil {
		return nil, errNoWorkloadCalls
	}
	s, err := c.wc.DescribeECSService(ctx, cluster, service)
	if err != nil {
		if awsenforce.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	return &agentcontain.ECSService{ClusterARN: s.ClusterARN, ServiceARN: s.ServiceARN, TaskDefinition: s.TaskDefinition,
		DesiredCount: s.DesiredCount, RunningCount: s.RunningCount}, nil
}

func (c *containAWS) SetServiceDesiredCount(ctx context.Context, cluster, service string, n int32) error {
	if c.wc == nil {
		return errNoWorkloadCalls
	}
	return mapNotFound(c.wc.UpdateECSServiceDesiredCount(ctx, cluster, service, n))
}

func (c *containAWS) DescribeScalableTarget(ctx context.Context, region, resourceID string) (*agentcontain.ScalableTarget, error) {
	if c.wc == nil {
		return nil, errNoWorkloadCalls
	}
	t, err := c.wc.DescribeECSScalableTarget(ctx, region, resourceID)
	if err != nil || t == nil {
		return nil, mapNotFound(err)
	}
	return &agentcontain.ScalableTarget{MinCapacity: t.MinCapacity, MaxCapacity: t.MaxCapacity,
		Suspended: agentcontain.Suspended{DynamicIn: t.DynamicIn, DynamicOut: t.DynamicOut, Scheduled: t.ScheduledSuspended}}, nil
}

func (c *containAWS) SetScalableTargetSuspended(ctx context.Context, region, resourceID string, s agentcontain.Suspended) error {
	if c.wc == nil {
		return errNoWorkloadCalls
	}
	return mapNotFound(c.wc.SetECSScalingSuspended(ctx, region, resourceID, s.DynamicIn, s.DynamicOut, s.Scheduled))
}

func (c *containAWS) CreatePolicy(ctx context.Context, name, document string, tags map[string]string) (string, error) {
	return c.v2.CreatePolicy(ctx, awsenforce.CreatePolicyInput{Path: igagov.AuthSecPolicyPath, Name: name, Document: document, Tags: tags})
}

func (c *containAWS) DeletePolicy(ctx context.Context, arn string) error {
	return mapNotFound(c.v2.DeletePolicy(ctx, arn))
}

func (c *containAWS) AttachPolicy(ctx context.Context, p agentcontain.Principal, arn string) error {
	if p.Kind == agentcontain.IdentityUser {
		if c.wc == nil {
			return errNoWorkloadCalls
		}
		return c.wc.AttachUserPolicy(ctx, p.Name, arn)
	}
	return c.v2.AttachRolePolicy(ctx, p.Name, arn)
}

func (c *containAWS) DetachPolicy(ctx context.Context, p agentcontain.Principal, arn string) error {
	if p.Kind == agentcontain.IdentityUser {
		if c.wc == nil {
			return errNoWorkloadCalls
		}
		return mapNotFound(c.wc.DetachUserPolicy(ctx, p.Name, arn))
	}
	return mapNotFound(c.v2.DetachRolePolicy(ctx, p.Name, arn))
}

// ReadPolicy reads an AuthSec policy and its attachments through the
// discovery role (GetPolicy, GetPolicyVersion, ListPolicyVersions,
// ListEntitiesForPolicy).
func (c *containAWS) ReadPolicy(ctx context.Context, arn string, p agentcontain.Principal) (*agentcontain.PolicyRead, error) {
	pol, _, err := awsenforce.ReadPolicy(ctx, c.disc, arn)
	if err != nil {
		return nil, err
	}
	if pol == nil {
		return &agentcontain.PolicyRead{}, nil
	}
	out := &agentcontain.PolicyRead{Exists: true, Tags: pol.Tags}
	if h, err := pol.DocumentHash(); err == nil {
		out.DocumentHash = h
	}
	kind := "role"
	if p.Kind == agentcontain.IdentityUser {
		kind = "user"
	}
	for _, e := range pol.AttachmentSet {
		mine := e.Kind == kind && e.Usage == igagov.UsagePermissions &&
			((p.UniqueID != "" && e.ID == p.UniqueID) || (p.UniqueID == "" && strings.EqualFold(e.Name, p.Name)))
		if mine {
			out.AttachedToPrincipal = true
			continue
		}
		out.OtherEntities++
	}
	return out, nil
}

// containRoleReader reads a role's current RoleId (discovery role); ""
// when the role does not exist.
type containRoleReader interface {
	RoleID(ctx context.Context, roleName string) (string, error)
}

func (c *containAWS) RoleID(ctx context.Context, roleName string) (string, error) {
	r, err := awsenforce.ReadRole(ctx, c.disc, roleName)
	if err != nil || r == nil {
		return "", err
	}
	return r.RoleID, nil
}

func (c *containAWS) ListAccessKeys(ctx context.Context, user string) ([]agentcontain.AccessKey, error) {
	if c.wc == nil {
		return nil, errNoWorkloadCalls
	}
	keys, err := c.wc.ListAccessKeys(ctx, user)
	if err != nil {
		return nil, mapNotFound(err)
	}
	out := make([]agentcontain.AccessKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, agentcontain.AccessKey{ID: k.ID, Active: k.Active})
	}
	return out, nil
}

func (c *containAWS) SetAccessKeyStatus(ctx context.Context, user, key string, active bool) error {
	if c.wc == nil {
		return errNoWorkloadCalls
	}
	return mapNotFound(c.wc.UpdateAccessKey(ctx, user, key, active))
}
