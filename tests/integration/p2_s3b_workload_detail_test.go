package integration

// T3.6 (SPEC-iga-phase2-graph.md §1.3 "Silent detail failures", §1.4): a
// failed detail call -- GetAgent, GetGateway, DescribeTaskDefinition,
// GetInstanceProfile, GetAgentRuntime -- keeps the row under the SAME key,
// makes its surface partial, and partial blocks deletion. D-53: the
// execution-role state is left as the previous pass wrote it, never "none".
// Every test runs the REAL scan worker and projector.

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/google/uuid"
)

// s3bWorkloadRow is the collected row and the graph node it projected to.
type s3bWorkloadRow struct {
	ID         uuid.UUID
	NativeID   string
	IdentityID *uuid.UUID
	Attrs      []byte
}

func s3bCloudWorkloads(t *testing.T, l *p2Lab, kind string) []s3bWorkloadRow {
	t.Helper()
	var rows []s3bWorkloadRow
	if err := l.db.Raw(`SELECT id, native_id, identity_id, attrs FROM cloud_workload
	                     WHERE workspace_id = ? AND runtime_kind = ? ORDER BY native_id`, l.ws, kind).
		Scan(&rows).Error; err != nil {
		t.Fatalf("read cloud_workload: %v", err)
	}
	return rows
}

func (w s3bWorkloadRow) attrs(t *testing.T) models.AWSWorkloadAttrs {
	t.Helper()
	cw := models.CloudWorkload{Attrs: w.Attrs}
	return cw.AWSAttrs()
}

type s3bGraphWorkload struct {
	ID                 uuid.UUID
	SourceKey          string
	Lifecycle          string
	ExecutionRoleState string
}

func s3bGraphWorkloads(t *testing.T, l *p2Lab, kind string) []s3bGraphWorkload {
	t.Helper()
	var rows []s3bGraphWorkload
	if err := l.db.Raw(`SELECT id, source_key, lifecycle, execution_role_state FROM iga_workload
	                     WHERE workspace_id = ? AND runtime_kind = ? ORDER BY source_key`, l.ws, kind).
		Scan(&rows).Error; err != nil {
		t.Fatalf("read iga_workload: %v", err)
	}
	return rows
}

type s3bRelRow struct {
	ID          uuid.UUID
	State       string
	EndedReason string
}

func s3bExecutesAs(t *testing.T, l *p2Lab, workloadID uuid.UUID) []s3bRelRow {
	t.Helper()
	var rows []s3bRelRow
	if err := l.db.Raw(`SELECT id, state, ended_reason FROM iga_relationship
	                     WHERE workspace_id = ? AND relationship_type = 'executes_as' AND source_workload_id = ?
	                     ORDER BY valid_from`, l.ws, workloadID).Scan(&rows).Error; err != nil {
		t.Fatalf("read executes_as: %v", err)
	}
	return rows
}

func s3bCloudIdentityID(t *testing.T, l *p2Lab, nativeID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`,
		l.ws, nativeID).Row().Scan(&id); err != nil || id == uuid.Nil {
		t.Fatalf("no cloud_identity %s: %v", nativeID, err)
	}
	return id
}

// E7 / E9, the T3.6 gate: "A failed GetAgent keeps the same key and blocks
// deletion." Scan 1 reads the agent in full; scan 2's GetAgent is denied.
//
// Safeguards this must catch (each mutation-checked, see the report):
//   - the constructed ARN (bedrock.go agentDetail): the bare id would be a
//     second cloud_workload row;
//   - partial on a failed detail call (bedrock.go Agents): reached would let
//     the executes_as partition END the edge;
//   - D-53 in the projector (project.go projectExecution): the edge would be
//     re-asserted current, or the state written 'none';
//   - the attrs/identity merge (cloud_workload_repository.go): the role and
//     model the last good read recorded would be blanked.
func TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-getagent", true)
	a := l.account(accountA)
	role := a.role("support-agent-role", "AROAS3BAGENTROLE01")
	a.attach("support-agent-role", a.managed("TicketRead", docTicketRead))
	// A Lambda in the same region, removed before scan 2: the legacy
	// cloud_workload reconcile is connector-wide, so the partial Bedrock
	// surface must keep its row too.
	a.lambda("us-east-1", "nightly-export", role)

	agentARN := "arn:aws:bedrock:us-east-1:" + a.id + ":agent/AGENTS3B01"
	f := &s3bFakes{bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{
		"AGENTS3B01": {
			AgentId: aws.String("AGENTS3B01"), AgentArn: aws.String(agentARN),
			AgentName: aws.String("support-bot"), AgentResourceRoleArn: aws.String(role),
			FoundationModel: aws.String("amazon.titan-text-express-v1"),
			AgentStatus:     bedrockagenttypes.AgentStatusPrepared,
		},
	}}}

	run1 := s3bScanAndProject(l, a, f)
	if got := s3bSurface(t, s3bRunCoverage(t, l, run1.ID), "bedrock-agents:us-east-1"); got.State != models.CloudCoverageReached {
		t.Fatalf("setup: bedrock-agents after a clean read = %+v", got)
	}
	cw1 := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgent)
	g1 := s3bGraphWorkloads(t, l, models.WorkloadBedrockAgent)
	if len(cw1) != 1 || len(g1) != 1 || cw1[0].NativeID != agentARN {
		t.Fatalf("setup: agent rows collected=%+v graph=%+v", cw1, g1)
	}
	if g1[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Fatalf("setup: execution role state %q, want resolved", g1[0].ExecutionRoleState)
	}
	ex1 := s3bExecutesAs(t, l, g1[0].ID)
	if len(ex1) != 1 || ex1[0].State != models.RelCurrent {
		t.Fatalf("setup: executes_as = %+v, want one current edge", ex1)
	}
	roleID := s3bCloudIdentityID(t, l, role)

	// ---- scan 2: GetAgent denied; the Lambda is gone --------------------------
	f.bedrock.getFail = denied("bedrock:GetAgent")
	a.lambda("us-east-1", "", "")
	run2 := s3bScanAndProject(l, a, f)

	// Coverage: partial, naming the call and the code.
	cov := s3bSurface(t, s3bRunCoverage(t, l, run2.ID), "bedrock-agents:us-east-1")
	if cov.State != models.CloudCoveragePartial {
		t.Fatalf("bedrock-agents after a denied GetAgent = %+v, want partial (a failed detail call is never reached)", cov)
	}
	if !strings.Contains(cov.Error, "bedrock:GetAgent") || !strings.Contains(cov.Error, "AccessDenied") ||
		!strings.Contains(cov.Error, "1 of 1 agents") {
		t.Errorf("partial must name the count, the call and the AWS code, got %q", cov.Error)
	}
	if cov.API != "bedrock:GetAgent" || cov.ErrorCode != "AccessDenied" {
		t.Errorf("partial api/error_code = %q/%q, want bedrock:GetAgent/AccessDenied (D-71)", cov.API, cov.ErrorCode)
	}

	// The SAME key: one collected row, the same ARN, the same graph node.
	cw2 := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgent)
	if len(cw2) != 1 || cw2[0].ID != cw1[0].ID || cw2[0].NativeID != agentARN {
		t.Fatalf("collected agent rows after a failed GetAgent = %+v, want the one row keyed %s", cw2, agentARN)
	}
	g2 := s3bGraphWorkloads(t, l, models.WorkloadBedrockAgent)
	if len(g2) != 1 || g2[0].ID != g1[0].ID || g2[0].SourceKey != g1[0].SourceKey ||
		g2[0].SourceKey != igagraph.Key("aws", agentARN) || g2[0].Lifecycle != models.IGALifecycleActive {
		t.Fatalf("graph agent after a failed GetAgent = %+v, want %+v unchanged and active", g2, g1)
	}

	// D-53: the state the previous pass wrote stands; never 'none'.
	if g2[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Errorf("execution_role_state = %q after a failed GetAgent, want resolved left as it was "+
			"(D-53: never 'none' -- that reads as a real finding)", g2[0].ExecutionRoleState)
	}
	// Blocks deletion: the edge is kept, stale -- not ended, not re-asserted.
	ex2 := s3bExecutesAs(t, l, g2[0].ID)
	if len(ex2) != 1 || ex2[0].ID != ex1[0].ID || ex2[0].State != models.RelStale {
		t.Errorf("executes_as after a failed GetAgent = %+v, want the same edge, stale "+
			"(partial blocks ending; nothing this run read confirms it)", ex2)
	}

	// Attrs merge, never blank: the role and model the last good read recorded.
	at := cw2[0].attrs(t)
	if cw2[0].IdentityID == nil || *cw2[0].IdentityID != roleID {
		t.Errorf("cloud_workload.identity_id = %v, want the previous attribution %s kept", cw2[0].IdentityID, roleID)
	}
	if at.FoundationModel != "amazon.titan-text-express-v1" || !at.DetailIncomplete ||
		at.DetailError != "bedrock:GetAgent AccessDenied" || at.Status != string(bedrockagenttypes.AgentStatusPrepared) {
		t.Errorf("attrs after a failed GetAgent = %+v, want the model kept, the status from the summary, "+
			"detail_incomplete with the call and code", at)
	}

	// Legacy deletion is blocked too: the removed Lambda's row survives
	// because one compute surface was partial.
	if n := len(s3bCloudWorkloads(t, l, models.WorkloadLambdaFunction)); n != 1 {
		t.Errorf("cloud_workload lambda rows = %d, want 1: a partial surface must block ReconcileWorkloads", n)
	}

	// Evidence names the call that actually returned the row.
	obs := s3bObservations(t, l, "bedrock:ListAgents")
	if len(obs) != 1 || obs[0].WorkloadID == nil || *obs[0].WorkloadID != cw1[0].ID ||
		obs[0].SubjectNativeID != agentARN || obs[0].Surface != "bedrock-agents:us-east-1" {
		t.Fatalf("listing evidence = %+v, want one bedrock:ListAgents observation for the agent", obs)
	}
	if facts := obs[0].facts(t); facts["detail_incomplete"] != true || facts["attributed"] != nil {
		t.Errorf("listing evidence facts = %v: must say the detail was not read and claim no attribution", facts)
	}
}

// A new agent whose very first GetAgent fails has nothing to protect and
// nothing true to say about its role: it is kept (collected, under its
// constructed ARN) and the surface is partial, but it is not projected with
// a false "none" (D-53, 029 has no unknown state).
func TestP2S3bNewAgentWithFailedDetailIsNotProjectedAsNone(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-newagent", true)
	a := l.account(accountA)
	a.role("some-role", "AROAS3BSOMEROLE001")
	f := &s3bFakes{bedrock: &fakeBedrock{
		agents: map[string]bedrockagenttypes.Agent{"AGENTNEW01": {
			AgentId: aws.String("AGENTNEW01"), AgentName: aws.String("fresh-bot"),
			AgentStatus: bedrockagenttypes.AgentStatusCreating,
		}},
		getFail: throttled("bedrock:GetAgent"),
	}}
	run := s3bScanAndProject(l, a, f)

	want := "arn:aws:bedrock:us-east-1:" + a.id + ":agent/AGENTNEW01"
	cw := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgent)
	if len(cw) != 1 || cw[0].NativeID != want {
		t.Fatalf("collected rows = %+v, want one keyed by the constructed ARN %s", cw, want)
	}
	if g := s3bGraphWorkloads(t, l, models.WorkloadBedrockAgent); len(g) != 0 {
		t.Fatalf("graph workloads = %+v: an agent whose role was never read must not be projected as 'none'", g)
	}
	if cov := s3bSurface(t, s3bRunCoverage(t, l, run.ID), "bedrock-agents:us-east-1"); cov.State != models.CloudCoveragePartial ||
		!strings.Contains(cov.Error, "Throttling") {
		t.Fatalf("coverage = %+v, want partial naming the throttle", cov)
	}
}

// T3.6: a failed GetGateway -> agentcore-gateways:<region> partial, the gateway
// kept under its constructed ARN (GatewaySummary carries none), its evidence
// labelled with the call that returned it, never aws:unknown (T3.5); target
// type collected and carried on the gateway's row (§1.4).
func TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-getgateway", true)
	a := l.account(accountA)
	role := a.role("gateway-role", "AROAS3BGATEWAY0001")
	core := &fakeAgentCore{
		gateways: []agentcoretypes.GatewaySummary{{
			GatewayId: aws.String("gw-s3b-1"), Name: aws.String("ticket-tools"),
			Status: agentcoretypes.GatewayStatusReady,
		}},
		gatewayRoleByID: map[string]string{"gw-s3b-1": role},
		targetsByGateway: map[string][]agentcoretypes.TargetSummary{"gw-s3b-1": {{
			TargetId: aws.String("tgt-1"), Name: aws.String("ticket-lambda"),
			Status: agentcoretypes.TargetStatusReady, TargetType: agentcoretypes.TargetTypeLambda,
		}}},
	}
	f := &s3bFakes{agentCore: core}
	gwARN := "arn:aws:bedrock-agentcore:us-east-1:" + a.id + ":gateway/gw-s3b-1"

	run1 := s3bScanAndProject(l, a, f)
	if cov := s3bSurface(t, s3bRunCoverage(t, l, run1.ID), "agentcore-gateways:us-east-1"); cov.State != models.CloudCoverageReached {
		t.Fatalf("setup: gateways after a clean read = %+v", cov)
	}
	if obs := s3bObservations(t, l, "aws:unknown"); len(obs) != 0 {
		t.Fatalf("%d observations labelled aws:unknown: the gateway's source_api must be named", len(obs))
	}
	if obs := s3bObservations(t, l, "bedrock-agentcore:GetGateway"); len(obs) != 1 || obs[0].SubjectNativeID != gwARN {
		t.Fatalf("gateway evidence = %+v, want one bedrock-agentcore:GetGateway observation for %s", obs, gwARN)
	}
	tgt := s3bObservations(t, l, "bedrock-agentcore:ListGatewayTargets")
	if len(tgt) != 1 || tgt[0].facts(t)["type"] != "LAMBDA" {
		t.Fatalf("target evidence = %+v, want the target's type recorded", tgt)
	}
	cw1 := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreGW)
	if len(cw1) != 1 || cw1[0].NativeID != gwARN {
		t.Fatalf("setup: gateway rows = %+v", cw1)
	}
	if ts := cw1[0].attrs(t).GatewayTargets; len(ts) != 1 || ts[0].TargetID != "tgt-1" || ts[0].Type != "LAMBDA" ||
		ts[0].Name != "ticket-lambda" || ts[0].Status != "READY" {
		t.Fatalf("gateway attrs targets = %+v, want id, name, status and type", ts)
	}
	g1 := s3bGraphWorkloads(t, l, models.WorkloadBedrockAgentCoreGW)
	if len(g1) != 1 || g1[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Fatalf("setup: graph gateway = %+v", g1)
	}

	// ---- scan 2: GetGateway and ListGatewayTargets denied ---------------------
	core.getGatewayFail = denied("bedrock-agentcore:GetGateway")
	core.listTargetsFail = denied("bedrock-agentcore:ListGatewayTargets")
	run2 := s3bScanAndProject(l, a, f)

	cov := s3bSurface(t, s3bRunCoverage(t, l, run2.ID), "agentcore-gateways:us-east-1")
	if cov.State != models.CloudCoveragePartial || !strings.Contains(cov.Error, "bedrock-agentcore:GetGateway AccessDenied") ||
		!strings.Contains(cov.Error, "bedrock-agentcore:ListGatewayTargets AccessDenied") {
		t.Fatalf("agentcore-gateways after a denied GetGateway = %+v, want partial naming both calls", cov)
	}
	cw2 := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreGW)
	if len(cw2) != 1 || cw2[0].ID != cw1[0].ID || cw2[0].NativeID != gwARN {
		t.Fatalf("gateway rows after a failed GetGateway = %+v, want the same row keyed %s", cw2, gwARN)
	}
	at := cw2[0].attrs(t)
	if !at.DetailIncomplete || len(at.GatewayTargets) != 1 {
		t.Errorf("gateway attrs = %+v, want detail_incomplete and the previous target list kept (unread is not empty)", at)
	}
	g2 := s3bGraphWorkloads(t, l, models.WorkloadBedrockAgentCoreGW)
	if len(g2) != 1 || g2[0].ID != g1[0].ID || g2[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Errorf("graph gateway = %+v, want the same node, its execution role state untouched", g2)
	}
	if ex := s3bExecutesAs(t, l, g2[0].ID); len(ex) != 1 || ex[0].State != models.RelStale {
		t.Errorf("gateway executes_as = %+v, want stale", ex)
	}
	if obs := s3bObservations(t, l, "bedrock-agentcore:ListGateways"); len(obs) != 1 || obs[0].SubjectNativeID != gwARN {
		t.Errorf("listing evidence = %+v, want one bedrock-agentcore:ListGateways observation", obs)
	}
}

// T3.6: an ECS task definition whose DescribeTaskDefinition failed is KEPT
// (ListTaskDefinitions proves it exists) under its listed ARN, marked
// incomplete, and ecs:<region> is partial -- it used to be dropped while the
// surface read reached, which licensed deleting it. EC2's GetInstanceProfile
// follows the same rule.
func TestP2S3bECSDescribeAndInstanceProfileFailuresArePartial(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-ecs", true)
	a := l.account(accountA)
	taskRole := a.role("ledger-task-role", "AROAS3BLEDGERTASK1")
	instRole := a.role("web-tier-role", "AROAS3BWEBTIER0001")
	tdARN := "arn:aws:ecs:us-east-1:" + a.id + ":task-definition/ledger:7"
	ecsFake := &fakeECS{defs: map[string]ecstypes.TaskDefinition{tdARN: {
		TaskDefinitionArn: aws.String(tdARN), Family: aws.String("ledger"),
		TaskRoleArn: aws.String(taskRole), Status: ecstypes.TaskDefinitionStatusActive,
	}}}
	profileARN := "arn:aws:iam::" + a.id + ":instance-profile/web-tier"
	ec2Fake := &fakeEC2{instances: []ec2types.Instance{{
		InstanceId:         aws.String("i-0s3b000000000001"),
		State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String(profileARN)},
	}}}
	profiles := &fakeInstanceProfile{roleByProfileName: map[string]string{"web-tier": instRole}}
	f := &s3bFakes{ecs: ecsFake, ec2: ec2Fake, profiles: profiles}

	s3bScanAndProject(l, a, f)
	g1 := s3bGraphWorkloads(t, l, models.WorkloadECSTaskDefinition)
	if len(g1) != 1 || g1[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Fatalf("setup: ECS node = %+v", g1)
	}

	// ---- scan 2: the describe and the profile both fail -----------------------
	// fakeECS lists what is in defs and describes only what is in describable.
	ecsFake.describeFail = denied("ecs:DescribeTaskDefinition")
	profiles.roleByProfileName = map[string]string{} // GetInstanceProfile now denied
	run2 := s3bScanAndProject(l, a, f)
	cov := s3bRunCoverage(t, l, run2.ID)

	if s := s3bSurface(t, cov, "ecs:us-east-1"); s.State != models.CloudCoveragePartial ||
		!strings.Contains(s.Error, "ecs:DescribeTaskDefinition AccessDenied") || s.Count != 1 {
		t.Fatalf("ecs after a denied describe = %+v, want partial, count 1, naming the call", s)
	}
	if s := s3bSurface(t, cov, "ec2:us-east-1"); s.State != models.CloudCoveragePartial ||
		!strings.Contains(s.Error, "iam:GetInstanceProfile AccessDenied") {
		t.Fatalf("ec2 after a denied GetInstanceProfile = %+v, want partial naming the call", s)
	}
	cw := s3bCloudWorkloads(t, l, models.WorkloadECSTaskDefinition)
	if len(cw) != 1 || cw[0].NativeID != tdARN || !cw[0].attrs(t).DetailIncomplete {
		t.Fatalf("ECS rows = %+v, want the task definition kept under %s, detail incomplete", cw, tdARN)
	}
	g2 := s3bGraphWorkloads(t, l, models.WorkloadECSTaskDefinition)
	if len(g2) != 1 || g2[0].ID != g1[0].ID || g2[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Fatalf("ECS node = %+v, want the same node, its role state untouched", g2)
	}
	if ex := s3bExecutesAs(t, l, g2[0].ID); len(ex) != 1 || ex[0].State != models.RelStale {
		t.Errorf("ECS executes_as = %+v, want stale (never ended on a describe we could not read)", ex)
	}
	inst := s3bGraphWorkloads(t, l, models.WorkloadEC2Instance)
	if len(inst) != 1 || inst[0].ExecutionRoleState != models.ExecRoleResolved {
		t.Errorf("EC2 node = %+v, want its role state untouched by a failed GetInstanceProfile", inst)
	}
}

// §1.4 "bedrock-agentcore: ARN, name, STATUS": the runtime's status is
// collected -- from the list item, and from GetAgentRuntime when it answers.
func TestP2S3bAgentCoreRuntimeStatusIsCollected(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-runtime", true)
	a := l.account(accountA)
	role := a.role("runtime-role", "AROAS3BRUNTIME0001")
	rtARN := "arn:aws:bedrock-agentcore:us-east-1:" + a.id + ":runtime/rt-s3b"
	core := &fakeAgentCore{
		runtimes: []agentcoretypes.AgentRuntime{{
			AgentRuntimeId: aws.String("rt-s3b"), AgentRuntimeArn: aws.String(rtARN),
			AgentRuntimeName: aws.String("ledger-runtime"), Status: agentcoretypes.AgentRuntimeStatusCreating,
		}},
		roleByID:          map[string]string{"rt-s3b": role},
		runtimeStatusByID: map[string]agentcoretypes.AgentRuntimeStatus{"rt-s3b": agentcoretypes.AgentRuntimeStatusReady},
	}
	s3bScanAndProject(l, a, &s3bFakes{agentCore: core})
	cw := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreRT)
	if len(cw) != 1 || cw[0].attrs(t).Status != "READY" {
		t.Fatalf("runtime rows = %+v, want status READY from GetAgentRuntime", cw)
	}

	// Detail denied: the list item's status, detail incomplete, surface partial.
	core.roleByID = map[string]string{}
	run2 := s3bScanAndProject(l, a, &s3bFakes{agentCore: core})
	cw = s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreRT)
	if len(cw) != 1 || cw[0].attrs(t).Status != "CREATING" || !cw[0].attrs(t).DetailIncomplete {
		t.Fatalf("runtime rows = %+v, want the list item's status CREATING and detail incomplete", cw)
	}
	if s := s3bSurface(t, s3bRunCoverage(t, l, run2.ID), "bedrock-agentcore:us-east-1"); s.State != models.CloudCoveragePartial ||
		!strings.Contains(s.Error, "bedrock-agentcore:GetAgentRuntime") {
		t.Fatalf("bedrock-agentcore after a denied GetAgentRuntime = %+v, want partial", s)
	}
}
