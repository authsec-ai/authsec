package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Workloads and activity, against a real database.
//
// Two traps are asserted here because getting either wrong reports the wrong
// permissions for the wrong thing, silently:
//
//   - ECS names TWO roles. taskRoleArn is what the application acts as;
//     executionRoleArn is ECS pulling images. Attributing a container's
//     permissions to the execution role is a real, plausible bug.
//   - EC2 names an instance profile, not a role, and resolving it needs a
//     second IAM call.
//
// The third guarantee asserted here is the one IAM cannot enforce: Lambda
// returns environment variable VALUES, and only the names may be stored.

/* --------------------------------- fakes ---------------------------------- */

const (
	fakeSecretEnvValue = "super-secret-database-password-do-not-store"
	lambdaRoleARN      = plainRoleARN
	ecsTaskRoleARN     = agentRoleARN
	ecsExecRoleARN     = "arn:aws:iam::429418377036:role/ecsTaskExecutionRole"
	instanceProfileARN = "arn:aws:iam::429418377036:instance-profile/web-tier"
	instanceRoleARN    = "arn:aws:iam::429418377036:role/summarizer-agent"
)

type fakeLambda struct {
	functions []lambdatypes.FunctionConfiguration
	fail      error
}

func (f *fakeLambda) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &lambda.ListFunctionsOutput{Functions: f.functions}, nil
}

type fakeECS struct {
	defs map[string]ecstypes.TaskDefinition
	fail error
}

func (f *fakeECS) ListTaskDefinitions(_ context.Context, _ *ecs.ListTaskDefinitionsInput, _ ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	arns := make([]string, 0, len(f.defs))
	for arn := range f.defs {
		arns = append(arns, arn)
	}
	return &ecs.ListTaskDefinitionsOutput{TaskDefinitionArns: arns}, nil
}

func (f *fakeECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	def, ok := f.defs[aws.ToString(in.TaskDefinition)]
	if !ok {
		return nil, denied("ecs:DescribeTaskDefinition")
	}
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &def}, nil
}

type fakeEC2 struct {
	instances []ec2types.Instance
	fail      error
}

func (f *fakeEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: f.instances}},
	}, nil
}

type fakeInstanceProfile struct {
	roleByProfileName map[string]string
	calls             int
}

func (f *fakeInstanceProfile) GetInstanceProfile(_ context.Context, in *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	f.calls++
	role, ok := f.roleByProfileName[aws.ToString(in.InstanceProfileName)]
	if !ok {
		return nil, denied("iam:GetInstanceProfile")
	}
	return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{
		Roles: []iamtypes.Role{{Arn: aws.String(role)}},
	}}, nil
}

type fakeBedrock struct {
	agents map[string]bedrockagenttypes.Agent
}

func (f *fakeBedrock) ListAgents(_ context.Context, _ *bedrockagent.ListAgentsInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error) {
	var summaries []bedrockagenttypes.AgentSummary
	for id, a := range f.agents {
		summaries = append(summaries, bedrockagenttypes.AgentSummary{
			AgentId: aws.String(id), AgentName: a.AgentName,
		})
	}
	return &bedrockagent.ListAgentsOutput{AgentSummaries: summaries}, nil
}

func (f *fakeBedrock) GetAgent(_ context.Context, in *bedrockagent.GetAgentInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error) {
	a, ok := f.agents[aws.ToString(in.AgentId)]
	if !ok {
		return nil, denied("bedrock:GetAgent")
	}
	return &bedrockagent.GetAgentOutput{Agent: &a}, nil
}

type fakeAgentCore struct {
	runtimes []agentcoretypes.AgentRuntime
	roleByID map[string]string

	gateways           []agentcoretypes.GatewaySummary
	gatewayRoleByID    map[string]string
	targetsByGateway   map[string][]agentcoretypes.TargetSummary
	workloadIdentities []agentcoretypes.WorkloadIdentityType

	oauth2Providers []agentcoretypes.Oauth2CredentialProviderItem
	apiKeyProviders []agentcoretypes.ApiKeyCredentialProviderItem
}

func (f *fakeAgentCore) ListAgentRuntimes(_ context.Context, _ *bedrockagentcorecontrol.ListAgentRuntimesInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error) {
	return &bedrockagentcorecontrol.ListAgentRuntimesOutput{AgentRuntimes: f.runtimes}, nil
}

func (f *fakeAgentCore) GetAgentRuntime(_ context.Context, in *bedrockagentcorecontrol.GetAgentRuntimeInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	role, ok := f.roleByID[aws.ToString(in.AgentRuntimeId)]
	if !ok {
		return nil, denied("bedrock-agentcore:GetAgentRuntime")
	}
	return &bedrockagentcorecontrol.GetAgentRuntimeOutput{RoleArn: aws.String(role)}, nil
}

// Gateways and workload identities: empty by default. Fixture-specific tests
// that need one set fields on fakeAgentCore for it, per the pattern
// runtimes/roleByID already establish.
func (f *fakeAgentCore) ListGateways(_ context.Context, _ *bedrockagentcorecontrol.ListGatewaysInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error) {
	return &bedrockagentcorecontrol.ListGatewaysOutput{Items: f.gateways}, nil
}

func (f *fakeAgentCore) GetGateway(_ context.Context, in *bedrockagentcorecontrol.GetGatewayInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error) {
	role, ok := f.gatewayRoleByID[aws.ToString(in.GatewayIdentifier)]
	if !ok {
		return nil, denied("bedrock-agentcore:GetGateway")
	}
	return &bedrockagentcorecontrol.GetGatewayOutput{
		GatewayArn: aws.String("arn:aws:bedrock-agentcore:us-east-1:491056652413:gateway/" + aws.ToString(in.GatewayIdentifier)),
		RoleArn:    aws.String(role),
	}, nil
}

func (f *fakeAgentCore) ListGatewayTargets(_ context.Context, in *bedrockagentcorecontrol.ListGatewayTargetsInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error) {
	return &bedrockagentcorecontrol.ListGatewayTargetsOutput{
		Items: f.targetsByGateway[aws.ToString(in.GatewayIdentifier)],
	}, nil
}

func (f *fakeAgentCore) ListWorkloadIdentities(_ context.Context, _ *bedrockagentcorecontrol.ListWorkloadIdentitiesInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListWorkloadIdentitiesOutput, error) {
	return &bedrockagentcorecontrol.ListWorkloadIdentitiesOutput{WorkloadIdentities: f.workloadIdentities}, nil
}

func (f *fakeAgentCore) ListOauth2CredentialProviders(_ context.Context, _ *bedrockagentcorecontrol.ListOauth2CredentialProvidersInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput, error) {
	return &bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput{CredentialProviders: f.oauth2Providers}, nil
}

func (f *fakeAgentCore) ListApiKeyCredentialProviders(_ context.Context, _ *bedrockagentcorecontrol.ListApiKeyCredentialProvidersInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput, error) {
	return &bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput{CredentialProviders: f.apiKeyProviders}, nil
}

// fakeActivity models the asynchronous job: the first poll reports IN_PROGRESS
// so the polling loop is genuinely exercised, and the second COMPLETED.
type fakeActivity struct {
	polls    int
	services []iamtypes.ServiceLastAccessed
	failJob  bool
}

func (f *fakeActivity) GenerateServiceLastAccessedDetails(_ context.Context, _ *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("job-1")}, nil
}

func (f *fakeActivity) GetServiceLastAccessedDetails(_ context.Context, _ *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	f.polls++
	if f.failJob {
		return &iam.GetServiceLastAccessedDetailsOutput{
			JobStatus: iamtypes.JobStatusTypeFailed,
			Error:     &iamtypes.ErrorDetails{Message: aws.String("report unavailable")},
		}, nil
	}
	if f.polls == 1 {
		return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeInProgress}, nil
	}
	completed := time.Now().Add(-2 * time.Hour)
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus:            iamtypes.JobStatusTypeCompleted,
		JobCompletionDate:    &completed,
		ServicesLastAccessed: f.services,
	}, nil
}

// Compile-time proof each fake satisfies the real interface.
var (
	_ awsdiscovery.LambdaAPI              = (*fakeLambda)(nil)
	_ awsdiscovery.ECSAPI                 = (*fakeECS)(nil)
	_ awsdiscovery.EC2API                 = (*fakeEC2)(nil)
	_ awsdiscovery.InstanceProfileAPI     = (*fakeInstanceProfile)(nil)
	_ awsdiscovery.BedrockAgentAPI        = (*fakeBedrock)(nil)
	_ awsdiscovery.AgentCoreAPI           = (*fakeAgentCore)(nil)
	_ awsdiscovery.ServiceLastAccessedAPI = (*fakeActivity)(nil)
)

/* -------------------------------- fixtures -------------------------------- */

func populatedWorkloads() (*fakeLambda, *fakeECS, *fakeEC2, *fakeInstanceProfile) {
	l := &fakeLambda{functions: []lambdatypes.FunctionConfiguration{{
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:429418377036:function:summarise"),
		FunctionName: aws.String("summarise"),
		Role:         aws.String(lambdaRoleARN),
		State:        lambdatypes.StateActive,
		// The values here must never reach the database.
		Environment: &lambdatypes.EnvironmentResponse{Variables: map[string]string{
			"DB_PASSWORD": fakeSecretEnvValue,
			"LOG_LEVEL":   "debug",
		}},
	}}}

	e := &fakeECS{defs: map[string]ecstypes.TaskDefinition{
		"arn:aws:ecs:us-east-1:429418377036:task-definition/ledger:7": {
			TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:429418377036:task-definition/ledger:7"),
			Family:            aws.String("ledger"),
			TaskRoleArn:       aws.String(ecsTaskRoleARN),
			ExecutionRoleArn:  aws.String(ecsExecRoleARN),
			Status:            ecstypes.TaskDefinitionStatusActive,
		},
	}}

	c := &fakeEC2{instances: []ec2types.Instance{{
		InstanceId:         aws.String("i-0abc123def456"),
		State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String(instanceProfileARN)},
		Tags:               []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("web-1")}},
	}}}

	p := &fakeInstanceProfile{roleByProfileName: map[string]string{"web-tier": instanceRoleARN}}
	return l, e, c, p
}

// workloadFixture onboards a connector, runs the identity scan so roles exist,
// and returns a workload scanner wired to the given fakes.
func workloadFixture(
	t *testing.T, db *gorm.DB, ws uuid.UUID,
	l awsdiscovery.LambdaAPI, e awsdiscovery.ECSAPI,
	c awsdiscovery.EC2API, p awsdiscovery.InstanceProfileAPI,
) (*services.AWSWorkloadScanner, *services.IAMSnapshot) {
	t.Helper()

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).
		Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	return services.NewAWSWorkloadScanner(db, svc).WithWorkloadAPIs(l, e, c, p), snap
}

func cleanWorkloadTables(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Helper()
	db.Exec(`DELETE FROM cloud_usage WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_workload WHERE workspace_id = ?`, ws)
	cleanPermissionTables(t, db, ws)
}

/* ---------------------------------- tests --------------------------------- */

// The core of the workload surface, and both traps at once.
func TestWorkloadScanAttributesComputeToTheRightRole(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-workloads")
	defer cleanWorkloadTables(t, db, ws)

	l, e, c, p := populatedWorkloads()
	scanner, snap := workloadFixture(t, db, ws, l, e, c, p)

	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if out.WorkloadsWritten != 3 {
		t.Fatalf("expected 3 workloads (lambda, ecs, ec2), got %d: %v", out.WorkloadsWritten, out.ByKind)
	}
	t.Logf("PASS: %d workloads written %v", out.WorkloadsWritten, out.ByKind)

	repo := repositories.NewCloudWorkloadRepository(db)
	workloads, _, err := repo.ListWorkloads(ws, repositories.CloudWorkloadFilter{})
	if err != nil {
		t.Fatalf("list workloads: %v", err)
	}
	byKind := map[string]models.CloudWorkload{}
	for _, w := range workloads {
		byKind[w.RuntimeKind] = w
	}

	identities := repositories.NewCloudIdentityRepository(db)

	// ---- ECS trap: the TASK role, never the execution role ----------------
	task := byKind[models.WorkloadECSTaskDefinition]
	taskRole, err := identities.GetIdentityByNativeID(ws, ecsTaskRoleARN)
	if err != nil {
		t.Fatalf("read task role: %v", err)
	}
	if task.IdentityID == nil || *task.IdentityID != taskRole.ID {
		t.Fatal("an ECS task definition must be attributed to its TASK role")
	}
	if got := task.AWSAttrs().ExecutionRoleARN; got != ecsExecRoleARN {
		t.Fatalf("the execution role must be recorded separately, got %q", got)
	}
	t.Log("PASS: ECS attributed to the task role, execution role kept apart")

	// ---- EC2 trap: instance profile resolved to its role ------------------
	instance := byKind[models.WorkloadEC2Instance]
	instRole, err := identities.GetIdentityByNativeID(ws, instanceRoleARN)
	if err != nil {
		t.Fatalf("read instance role: %v", err)
	}
	if instance.IdentityID == nil || *instance.IdentityID != instRole.ID {
		t.Fatal("an EC2 instance must be attributed to the role inside its instance profile")
	}
	if got := instance.AWSAttrs().InstanceProfileARN; got != instanceProfileARN {
		t.Fatalf("the instance profile must be recorded, got %q", got)
	}
	if p.calls == 0 {
		t.Fatal("resolving the instance profile requires the GetInstanceProfile hop")
	}
	if instance.Name != "web-1" {
		t.Fatalf("the EC2 Name tag is the human label, got %q", instance.Name)
	}
	t.Logf("PASS: EC2 instance profile resolved via %d GetInstanceProfile call(s)", p.calls)

	// ---- the guarantee IAM cannot enforce ---------------------------------
	fn := byKind[models.WorkloadLambdaFunction]
	names := fn.AWSAttrs().EnvVarNames
	if len(names) != 2 || names[0] != "DB_PASSWORD" || names[1] != "LOG_LEVEL" {
		t.Fatalf("env var NAMES must be recorded and sorted, got %v", names)
	}
	if strings.Contains(string(fn.Attrs), fakeSecretEnvValue) {
		t.Fatal("a Lambda environment variable VALUE reached the database")
	}
	// Structural, not just this row: no column anywhere in the table holds it.
	var dump string
	db.Raw(`SELECT coalesce(string_agg(row_to_json(t)::text, ' '), '') FROM cloud_workload t
	        WHERE workspace_id = ?`, ws).Row().Scan(&dump)
	if strings.Contains(dump, fakeSecretEnvValue) {
		t.Fatal("a Lambda environment variable VALUE is present somewhere in cloud_workload")
	}
	t.Log("PASS: env var names stored, values absent from the entire table")
}

// A workload naming a role nothing discovered is recorded unattributed, with
// the role it wanted, and invents no identity.
func TestWorkloadWithUnknownRoleIsRecordedUnattributed(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-workload-unattributed")
	defer cleanWorkloadTables(t, db, ws)

	const foreign = "arn:aws:iam::999988887777:role/SomeoneElsesRole"
	l := &fakeLambda{functions: []lambdatypes.FunctionConfiguration{{
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:429418377036:function:orphan"),
		FunctionName: aws.String("orphan"),
		Role:         aws.String(foreign),
	}}}
	scanner, snap := workloadFixture(t, db, ws, l, nil, nil, nil)

	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if out.Unattributed != 1 {
		t.Fatalf("expected 1 unattributed workload, got %d", out.Unattributed)
	}

	workloads, _, _ := repositories.NewCloudWorkloadRepository(db).ListWorkloads(ws, repositories.CloudWorkloadFilter{})
	if len(workloads) != 1 {
		t.Fatalf("the workload must still be recorded, got %d rows", len(workloads))
	}
	if workloads[0].IdentityID != nil {
		t.Fatal("identity_id must be NULL when the role was never discovered")
	}
	if got := workloads[0].AWSAttrs().UnresolvedRoleARN; got != foreign {
		t.Fatalf("the row must say which role it could not resolve, got %q", got)
	}
	if _, err := repositories.NewCloudIdentityRepository(db).
		GetIdentityByNativeID(ws, foreign); err == nil {
		t.Fatal("the workload surface must never create an identity")
	}
	t.Log("PASS: unattributed workload recorded, names the missing role, invents nothing")
}

// Bedrock: AWS's own agents, each resolved to its execution role.
func TestBedrockAgentsAndRuntimesBecomeWorkloads(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-bedrock")
	defer cleanWorkloadTables(t, db, ws)

	bedrock := &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{
		"AGENT123": {
			AgentId:              aws.String("AGENT123"),
			AgentArn:             aws.String("arn:aws:bedrock:us-east-1:429418377036:agent/AGENT123"),
			AgentName:            aws.String("support-bot"),
			AgentResourceRoleArn: aws.String(agentRoleARN),
			FoundationModel:      aws.String("amazon.titan-text-express-v1"),
			AgentStatus:          bedrockagenttypes.AgentStatusPrepared,
		},
	}}
	core := &fakeAgentCore{
		runtimes: []agentcoretypes.AgentRuntime{{
			AgentRuntimeId:   aws.String("RT1"),
			AgentRuntimeArn:  aws.String("arn:aws:bedrock-agentcore:us-east-1:429418377036:runtime/RT1"),
			AgentRuntimeName: aws.String("ledger-runtime"),
		}},
		roleByID: map[string]string{"RT1": plainRoleARN},
	}

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).
		Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}

	out, err := services.NewAWSWorkloadScanner(db, svc).WithBedrockAPIs(bedrock, core).
		ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if out.ByKind[models.WorkloadBedrockAgent] != 1 || out.ByKind[models.WorkloadBedrockAgentCoreRT] != 1 {
		t.Fatalf("expected one agent and one runtime, got %v", out.ByKind)
	}

	workloads, _, _ := repositories.NewCloudWorkloadRepository(db).ListWorkloads(ws, repositories.CloudWorkloadFilter{})
	for _, w := range workloads {
		if w.IdentityID == nil {
			t.Fatalf("%s (%s) should have resolved to a role", w.RuntimeKind, w.Name)
		}
		if w.RuntimeKind == models.WorkloadBedrockAgent {
			if got := w.AWSAttrs().FoundationModel; got != "amazon.titan-text-express-v1" {
				t.Fatalf("the agent's model is part of its identity, got %q", got)
			}
			// The ARN is preferred over the region-scoped agent id.
			if !strings.HasPrefix(w.NativeID, "arn:aws:bedrock:") {
				t.Fatalf("native_id should be the agent ARN, got %q", w.NativeID)
			}
		}
	}
	t.Log("PASS: Bedrock agent and AgentCore runtime both attributed, model recorded")
}

// Activity: the asynchronous job is polled to completion, and a service AWS
// says was never accessed is stored as NULL rather than a zero time.
func TestActivityScanPollsAndPreservesNeverAccessedAsNull(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-activity")
	defer cleanWorkloadTables(t, db, ws)

	used := time.Now().Add(-400 * 24 * time.Hour)
	activity := &fakeActivity{services: []iamtypes.ServiceLastAccessed{
		{
			ServiceNamespace:           aws.String("s3"),
			ServiceName:                aws.String("Amazon S3"),
			LastAuthenticated:          &used,
			TotalAuthenticatedEntities: aws.Int32(1),
		},
		{
			// Never accessed: AWS omits the date entirely.
			ServiceNamespace:           aws.String("dynamodb"),
			ServiceName:                aws.String("Amazon DynamoDB"),
			TotalAuthenticatedEntities: aws.Int32(0),
		},
	}}

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).
		Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}

	// No real waiting: the sleep seam returns immediately.
	noSleep := func(context.Context, time.Duration) error { return nil }
	out, err := services.NewAWSWorkloadScanner(db, svc).WithActivityAPI(activity, noSleep).
		ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("activity scan: %v", err)
	}

	// Three identities in populatedIAM, two services each.
	if out.UsageWritten != 6 {
		t.Fatalf("expected 6 usage rows (3 identities x 2 services), got %d (errors=%v)",
			out.UsageWritten, out.Errors)
	}
	if activity.polls < 2 {
		t.Fatalf("the IN_PROGRESS poll must be exercised, saw %d poll(s)", activity.polls)
	}
	t.Logf("PASS: %d usage rows across %d polls", out.UsageWritten, activity.polls)

	usage, _, err := repositories.NewCloudWorkloadRepository(db).ListUsage(ws, repositories.CloudWorkloadFilter{})
	if err != nil {
		t.Fatalf("list usage: %v", err)
	}
	var sawNever, sawUsed bool
	for _, u := range usage {
		switch u.Service {
		case "dynamodb":
			sawNever = true
			if u.LastUsedAt != nil {
				t.Fatalf("a never-accessed service must stay NULL, got %v", u.LastUsedAt)
			}
		case "s3":
			sawUsed = true
			if u.LastUsedAt == nil {
				t.Fatal("s3 has a last-used date and must keep it")
			}
			if u.GeneratedAt == nil {
				t.Fatal("the report's own as-of time must be recorded separately")
			}
		}
	}
	if !sawNever || !sawUsed {
		t.Fatalf("expected both an accessed and a never-accessed row, got %d rows", len(usage))
	}
	// Never-accessed sorts first, because it is the row worth acting on.
	if usage[0].LastUsedAt != nil {
		t.Fatal("ListUsage must order never-accessed first")
	}
	t.Log("PASS: never-accessed preserved as NULL and ordered first; report time kept apart")
}

// A denied compute surface must not let reconciliation delete workloads that
// still exist.
func TestWorkloadDeniedSurfaceBlocksReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-workload-denied")
	defer cleanWorkloadTables(t, db, ws)

	l, e, c, p := populatedWorkloads()
	scanner, snap := workloadFixture(t, db, ws, l, e, c, p)

	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	repo := repositories.NewCloudWorkloadRepository(db)
	before, _, _ := repo.ListWorkloads(ws, repositories.CloudWorkloadFilter{})
	if len(before) == 0 {
		t.Fatal("test setup: baseline should have written workloads")
	}

	// Lambda now refuses. The functions still exist; we cannot see them.
	l.fail = denied("lambda:ListFunctions")
	snap.Generation++

	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("a denied surface must not fail the whole scan: %v", err)
	}
	if out.Complete {
		t.Fatalf("a scan with a denied surface must not report complete: %v", out.Errors)
	}
	after, _, _ := repo.ListWorkloads(ws, repositories.CloudWorkloadFilter{})
	if len(after) != len(before) {
		t.Fatalf("a denied read deleted workloads: %d -> %d", len(before), len(after))
	}
	t.Logf("PASS: %d workload(s) preserved after a denied Lambda read", len(after))
}
