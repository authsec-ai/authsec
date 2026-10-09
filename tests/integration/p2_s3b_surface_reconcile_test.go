package integration

// Cloud Inventory's workload deletion, surface by surface (SPEC-iga-phase2-
// graph.md §1.4: partial, denied and throttled block ending "for that
// surface"; "absence is only ever inferred from reached"), and the keys it
// deletes by: the constructed ARN is built in the connector's partition, and a
// row an earlier collector keyed by a bare id is adopted by its ARN rather
// than listed beside it. Every scenario runs the REAL scan worker and
// projector.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

/* ------------------------- per-surface deletion ---------------------------- */

// s3bSurfaceLab is one account holding two workloads on EVERY compute surface
// in us-east-1: one that stays, one that is deleted in AWS before scan 2.
type s3bSurfaceLab struct {
	l        *p2Lab
	a        *p2Account
	f        *s3bFakes
	lambdaFn *fakeLambda
	gone     map[string]string // runtime kind -> the native id deleted before scan 2
}

func s3bNewSurfaceLab(t *testing.T, name string) *s3bSurfaceLab {
	t.Helper()
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	role := a.role("fleet-role", "AROAS3BFLEETROLE01")
	p := func(kind, id string) string { return "arn:aws:" + kind + ":us-east-1:" + a.id + ":" + id }

	lam := &fakeLambda{}
	for _, fn := range []string{"keep-fn", "gone-fn"} {
		lam.functions = append(lam.functions, lambdatypes.FunctionConfiguration{
			FunctionArn: aws.String(p("lambda", "function:"+fn)), FunctionName: aws.String(fn),
			Role: aws.String(role), State: lambdatypes.StateActive,
		})
	}
	a.lambdas["us-east-1"] = lam

	defs := map[string]ecstypes.TaskDefinition{}
	for _, fam := range []string{"keep-td", "gone-td"} {
		arn := p("ecs", "task-definition/"+fam+":1")
		defs[arn] = ecstypes.TaskDefinition{TaskDefinitionArn: aws.String(arn), Family: aws.String(fam),
			TaskRoleArn: aws.String(role), Status: ecstypes.TaskDefinitionStatusActive}
	}
	profile := "arn:aws:iam::" + a.id + ":instance-profile/fleet"
	var instances []ec2types.Instance
	for _, id := range []string{"i-0s3bkeep0000001", "i-0s3bgone0000001"} {
		instances = append(instances, ec2types.Instance{InstanceId: aws.String(id),
			State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String(profile)}})
	}
	agents := map[string]bedrockagenttypes.Agent{}
	for _, id := range []string{"AGENTKEEP1", "AGENTGONE1"} {
		agents[id] = bedrockagenttypes.Agent{AgentId: aws.String(id), AgentArn: aws.String(p("bedrock", "agent/"+id)),
			AgentName: aws.String(strings.ToLower(id)), AgentResourceRoleArn: aws.String(role),
			AgentStatus: bedrockagenttypes.AgentStatusPrepared}
	}
	core := &fakeAgentCore{roleByID: map[string]string{}, gatewayRoleByID: map[string]string{}}
	for _, id := range []string{"rt-keep", "rt-gone"} {
		core.runtimes = append(core.runtimes, agentcoretypes.AgentRuntime{AgentRuntimeId: aws.String(id),
			AgentRuntimeArn: aws.String(p("bedrock-agentcore", "runtime/"+id)), AgentRuntimeName: aws.String(id),
			Status: agentcoretypes.AgentRuntimeStatusReady})
		core.roleByID[id] = role
	}
	for _, id := range []string{"gw-keep", "gw-gone"} {
		core.gateways = append(core.gateways, agentcoretypes.GatewaySummary{GatewayId: aws.String(id),
			Name: aws.String(id), Status: agentcoretypes.GatewayStatusReady})
		core.gatewayRoleByID[id] = role
	}

	return &s3bSurfaceLab{l: l, a: a, lambdaFn: lam,
		f: &s3bFakes{
			ecs: &fakeECS{defs: defs}, ec2: &fakeEC2{instances: instances},
			profiles: &fakeInstanceProfile{roleByProfileName: map[string]string{"fleet": role}},
			bedrock:  &fakeBedrock{agents: agents}, agentCore: core,
		},
		gone: map[string]string{
			models.WorkloadLambdaFunction:     p("lambda", "function:gone-fn"),
			models.WorkloadECSTaskDefinition:  p("ecs", "task-definition/gone-td:1"),
			models.WorkloadEC2Instance:        "i-0s3bgone0000001",
			models.WorkloadBedrockAgent:       p("bedrock", "agent/AGENTGONE1"),
			models.WorkloadBedrockAgentCoreRT: p("bedrock-agentcore", "runtime/rt-gone"),
			models.WorkloadBedrockAgentCoreGW: p("bedrock-agentcore", "gateway/gw-gone"),
		}}
}

// deleteGone removes every "gone" workload from AWS: from each listing.
func (s *s3bSurfaceLab) deleteGone() {
	s.lambdaFn.functions = s.lambdaFn.functions[:1]
	delete(s.f.ecs.defs, s.gone[models.WorkloadECSTaskDefinition])
	s.f.ec2.instances = s.f.ec2.instances[:1]
	delete(s.f.bedrock.agents, "AGENTGONE1")
	s.f.agentCore.runtimes = s.f.agentCore.runtimes[:1]
	s.f.agentCore.gateways = s.f.agentCore.gateways[:1]
}

// s3bFailure makes one compute surface fail, and undoes it.
type s3bFailure struct {
	surface string // the surface prefix
	state   string // the state the surface must report while failing
	apply   func(s *s3bSurfaceLab)
	undo    func(s *s3bSurfaceLab)
}

// s3bFailures: every compute surface, by LISTING failure (the surface is not
// read at all) and by DETAIL failure (listed; some items not read in full).
var s3bFailures = map[string]s3bFailure{
	"lambda/listing": {models.SurfaceLambdaPrefix, models.CloudCoverageDenied,
		func(s *s3bSurfaceLab) { s.lambdaFn.fail = denied("lambda:ListFunctions") },
		func(s *s3bSurfaceLab) { s.lambdaFn.fail = nil }},
	"ecs/listing": {models.SurfaceECSPrefix, models.CloudCoverageDenied,
		func(s *s3bSurfaceLab) { s.f.ecs.fail = denied("ecs:ListTaskDefinitions") },
		func(s *s3bSurfaceLab) { s.f.ecs.fail = nil }},
	"ecs/detail": {models.SurfaceECSPrefix, models.CloudCoveragePartial,
		func(s *s3bSurfaceLab) { s.f.ecs.describeFail = denied("ecs:DescribeTaskDefinition") },
		func(s *s3bSurfaceLab) { s.f.ecs.describeFail = nil }},
	"ec2/listing": {models.SurfaceEC2Prefix, models.CloudCoverageThrottled,
		func(s *s3bSurfaceLab) { s.f.ec2.fail = throttled("ec2:DescribeInstances") },
		func(s *s3bSurfaceLab) { s.f.ec2.fail = nil }},
	"ec2/detail": {models.SurfaceEC2Prefix, models.CloudCoveragePartial,
		func(s *s3bSurfaceLab) { s.f.profiles.roleByProfileName = map[string]string{} },
		func(s *s3bSurfaceLab) {
			s.f.profiles.roleByProfileName = map[string]string{"fleet": s.a.roleARN("fleet-role")}
		}},
	"bedrock-agents/listing": {models.SurfaceBedrockAgentsPrefix, models.CloudCoverageDenied,
		func(s *s3bSurfaceLab) { s.f.bedrock.listFail = denied("bedrock:ListAgents") },
		func(s *s3bSurfaceLab) { s.f.bedrock.listFail = nil }},
	"bedrock-agents/detail": {models.SurfaceBedrockAgentsPrefix, models.CloudCoveragePartial,
		func(s *s3bSurfaceLab) { s.f.bedrock.getFail = throttled("bedrock:GetAgent") },
		func(s *s3bSurfaceLab) { s.f.bedrock.getFail = nil }},
	"bedrock-agentcore/listing": {models.SurfaceBedrockAgentCorePrefix, models.CloudCoverageDenied,
		func(s *s3bSurfaceLab) {
			s.f.agentCore.listRuntimesFail = denied("bedrock-agentcore:ListAgentRuntimes")
		},
		func(s *s3bSurfaceLab) { s.f.agentCore.listRuntimesFail = nil }},
	"bedrock-agentcore/detail": {models.SurfaceBedrockAgentCorePrefix, models.CloudCoveragePartial,
		func(s *s3bSurfaceLab) { s.f.agentCore.roleByID = map[string]string{} },
		func(s *s3bSurfaceLab) {
			s.f.agentCore.roleByID = map[string]string{"rt-keep": s.a.roleARN("fleet-role")}
		}},
	"agentcore-gateways/listing": {models.SurfaceAgentCoreGatewaysPrefix, models.CloudCoverageDenied,
		func(s *s3bSurfaceLab) { s.f.agentCore.listGatewaysFail = denied("bedrock-agentcore:ListGateways") },
		func(s *s3bSurfaceLab) { s.f.agentCore.listGatewaysFail = nil }},
	"agentcore-gateways/detail": {models.SurfaceAgentCoreGatewaysPrefix, models.CloudCoveragePartial,
		func(s *s3bSurfaceLab) { s.f.agentCore.getGatewayFail = denied("bedrock-agentcore:GetGateway") },
		func(s *s3bSurfaceLab) { s.f.agentCore.getGatewayFail = nil }},
}

// s3bKindOfSurface is the runtime kind each compute surface's rows carry.
var s3bKindOfSurface = map[string]string{
	models.SurfaceLambdaPrefix:            models.WorkloadLambdaFunction,
	models.SurfaceECSPrefix:               models.WorkloadECSTaskDefinition,
	models.SurfaceEC2Prefix:               models.WorkloadEC2Instance,
	models.SurfaceBedrockAgentsPrefix:     models.WorkloadBedrockAgent,
	models.SurfaceBedrockAgentCorePrefix:  models.WorkloadBedrockAgentCoreRT,
	models.SurfaceAgentCoreGatewaysPrefix: models.WorkloadBedrockAgentCoreGW,
}

func s3bHasNative(rows []s3bWorkloadRow, native string) bool {
	for _, r := range rows {
		if r.NativeID == native {
			return true
		}
	}
	return false
}

// T3.6 / E9, the reviewer's gap: EVERY compute surface blocks deletion of its
// own rows while it is partial, denied or throttled -- and ONLY its own. Scan 1
// reads two workloads per surface; before scan 2 one of each is deleted in AWS
// and the failing surfaces fail. Scan 2: the failing surfaces keep their
// deleted workload's row, every reached surface deletes its one. Scan 3, all
// reached: every deleted workload is gone -- which also proves each surface
// licenses deletion at all once it is read.
//
// Three runs, so every surface is failing in one scan 2 and reached in
// another, and every surface with a detail call fails both ways.
//
// Safeguards (mutation-checked): the reached-only test in
// reachedWorkloadScopes; the (runtime_kind, region) scope in
// ReconcileWorkloads; every entry of computeSurfaceKinds (gateways included,
// the reviewer's M-A); and no connector-wide veto -- the reached surfaces
// delete in scan 2.
func TestP2S3bWorkloadDeletionIsPerSurface(t *testing.T) {
	for i, failing := range [][]string{
		{"lambda/listing", "ec2/detail", "agentcore-gateways/detail"},
		{"ecs/detail", "bedrock-agents/detail", "bedrock-agentcore/detail"},
		{"ecs/listing", "ec2/listing", "bedrock-agents/listing", "bedrock-agentcore/listing", "agentcore-gateways/listing"},
	} {
		t.Run(fmt.Sprintf("run%d", i+1), func(t *testing.T) {
			s := s3bNewSurfaceLab(t, fmt.Sprintf("p2-s3b-per-surface-%d", i+1))
			s3bScanAndProject(s.l, s.a, s.f)
			for kind := range s.gone {
				if n := len(s3bCloudWorkloads(t, s.l, kind)); n != 2 {
					t.Fatalf("setup: %d %s rows after scan 1, want 2", n, kind)
				}
			}

			// ---- scan 2: one of each deleted; some surfaces failing ------------
			s.deleteGone()
			failingKinds := map[string]string{}
			for _, name := range failing {
				fl := s3bFailures[name]
				fl.apply(s)
				failingKinds[s3bKindOfSurface[fl.surface]] = name
			}
			run2 := s3bScanAndProject(s.l, s.a, s.f)
			cov := s3bRunCoverage(t, s.l, run2.ID)
			for _, name := range failing {
				fl := s3bFailures[name]
				if got := s3bSurface(t, cov, models.SurfaceRegional(fl.surface, "us-east-1")); got.State != fl.state {
					t.Fatalf("%s: surface = %+v, want %s", name, got, fl.state)
				}
			}
			for kind, native := range s.gone {
				rows := s3bCloudWorkloads(t, s.l, kind)
				if why, fails := failingKinds[kind]; fails {
					if !s3bHasNative(rows, native) {
						t.Errorf("%s: the deleted %s was reconciled away while its surface was not reached "+
							"(%+v) -- absence is only inferred from reached", why, native, rows)
					}
					continue
				}
				if s3bHasNative(rows, native) {
					t.Errorf("%s: the deleted %s survived although its own surface was reached: "+
						"another surface's failure vetoed it (the connector-wide veto)", kind, native)
				}
			}

			// ---- scan 3: everything reached ------------------------------------
			for _, name := range failing {
				s3bFailures[name].undo(s)
			}
			s3bScanAndProject(s.l, s.a, s.f)
			for kind, native := range s.gone {
				rows := s3bCloudWorkloads(t, s.l, kind)
				if len(rows) != 1 || s3bHasNative(rows, native) {
					t.Errorf("%s rows once every surface is reached = %+v, want only the kept one "+
						"(a reached surface must license deleting its own rows)", kind, rows)
				}
			}
		})
	}
}

/* ------------------------- the connector's partition ------------------------ */

// T3.6 / E7: the ARN a failed detail call constructs is built in the
// CONNECTOR'S partition. An aws-us-gov connector's agent and gateway are read
// in full in scan 1 (AWS returns arn:aws-us-gov:...), then their GetAgent and
// GetGateway fail in scan 2: the same one collected row each, keyed by the
// same ARN, and the same graph node. Built in "aws" instead, the key would
// move on a transient failure -- a second row and a second node, exactly the
// E7 defect.
//
// Safeguard (mutation-checked, the reviewer's M-C): ScanFromSnapshot passing
// connAttrs.Partition into the scope the ARN is constructed in.
func TestP2S3bConstructedARNUsesTheConnectorPartition(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-partition", true)
	const region = "us-gov-west-1"
	a := l.account(accountA, region)
	if err := l.db.Exec(`UPDATE cloud_connector SET attrs = attrs || '{"partition": "aws-us-gov"}'::jsonb
	                      WHERE workspace_id = ? AND id = ?`, l.ws, a.conn).Error; err != nil {
		t.Fatalf("set partition: %v", err)
	}
	role := a.role("gov-agent-role", "AROAS3BGOVAGENT001")
	agentARN := "arn:aws-us-gov:bedrock:" + region + ":" + a.id + ":agent/AGENTGOV01"
	gwARN := "arn:aws-us-gov:bedrock-agentcore:" + region + ":" + a.id + ":gateway/gw-gov-1"
	f := &s3bFakes{
		bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"AGENTGOV01": {
			AgentId: aws.String("AGENTGOV01"), AgentArn: aws.String(agentARN), AgentName: aws.String("gov-bot"),
			AgentResourceRoleArn: aws.String(role), AgentStatus: bedrockagenttypes.AgentStatusPrepared,
		}}},
		agentCore: &fakeAgentCore{
			partition: "aws-us-gov", region: region,
			gateways: []agentcoretypes.GatewaySummary{{GatewayId: aws.String("gw-gov-1"),
				Name: aws.String("gov-tools"), Status: agentcoretypes.GatewayStatusReady}},
			gatewayRoleByID: map[string]string{"gw-gov-1": role},
		},
	}

	s3bScanAndProject(l, a, f)
	before := map[string][]s3bWorkloadRow{}
	graph := map[string][]s3bGraphWorkload{}
	for kind, arn := range map[string]string{models.WorkloadBedrockAgent: agentARN, models.WorkloadBedrockAgentCoreGW: gwARN} {
		rows := s3bCloudWorkloads(t, l, kind)
		g := s3bGraphWorkloads(t, l, kind)
		if len(rows) != 1 || rows[0].NativeID != arn || len(g) != 1 || g[0].SourceKey != igagraph.Key("aws", arn) {
			t.Fatalf("setup: %s collected=%+v graph=%+v, want one each keyed %s", kind, rows, g, arn)
		}
		before[kind], graph[kind] = rows, g
	}

	// ---- scan 2: both detail calls fail -----------------------------------
	f.bedrock.getFail = denied("bedrock:GetAgent")
	f.agentCore.getGatewayFail = denied("bedrock-agentcore:GetGateway")
	s3bScanAndProject(l, a, f)
	for kind, arn := range map[string]string{models.WorkloadBedrockAgent: agentARN, models.WorkloadBedrockAgentCoreGW: gwARN} {
		rows := s3bCloudWorkloads(t, l, kind)
		if len(rows) != 1 || rows[0].ID != before[kind][0].ID || rows[0].NativeID != arn || !rows[0].attrs(t).DetailIncomplete {
			t.Errorf("%s after a failed detail call = %+v, want the one row keyed %s (constructed in aws-us-gov), "+
				"detail incomplete", kind, rows, arn)
		}
		g := s3bGraphWorkloads(t, l, kind)
		if len(g) != 1 || g[0].ID != graph[kind][0].ID || g[0].SourceKey != graph[kind][0].SourceKey {
			t.Errorf("%s graph after a failed detail call = %+v, want the same node %+v", kind, g, graph[kind])
		}
	}
}

/* ------------------------------ gateway targets ----------------------------- */

// s3bPagedTargets serves ListGatewayTargets in pages of one target, and can
// fail every page after the first -- a target list cut short.
type s3bPagedTargets struct {
	*fakeAgentCore
	failAfterFirst bool
}

func (f *s3bPagedTargets) ListGatewayTargets(ctx context.Context, in *bedrockagentcorecontrol.ListGatewayTargetsInput, opts ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error) {
	all := f.targetsByGateway[aws.ToString(in.GatewayIdentifier)]
	page := 0
	if in.NextToken != nil {
		if f.failAfterFirst {
			return nil, throttled("bedrock-agentcore:ListGatewayTargets")
		}
		page, _ = strconv.Atoi(aws.ToString(in.NextToken))
	}
	out := &bedrockagentcorecontrol.ListGatewayTargetsOutput{}
	if page < len(all) {
		out.Items = all[page : page+1]
	}
	if page+1 < len(all) {
		out.NextToken = aws.String(fmt.Sprint(page + 1))
	}
	return out, nil
}

// s3bStoredTargets is the gateway row's stored attrs, raw: the keys as written.
func s3bStoredTargets(t *testing.T, l *p2Lab) (targets []map[string]any, detailIncomplete, targetsIncomplete bool) {
	t.Helper()
	rows := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreGW)
	if len(rows) != 1 {
		t.Fatalf("gateway rows = %+v, want one", rows)
	}
	var raw struct {
		GatewayTargets    []map[string]any `json:"gateway_targets"`
		DetailIncomplete  bool             `json:"detail_incomplete"`
		TargetsIncomplete bool             `json:"targets_incomplete"`
	}
	if err := json.Unmarshal(rows[0].Attrs, &raw); err != nil {
		t.Fatalf("decode gateway attrs %s: %v", rows[0].Attrs, err)
	}
	return raw.GatewayTargets, raw.DetailIncomplete, raw.TargetsIncomplete
}

func s3bTargetIDs(targets []map[string]any) string {
	ids := make([]string, 0, len(targets))
	for _, tg := range targets {
		ids = append(ids, fmt.Sprint(tg["id"]))
	}
	return strings.Join(ids, ",")
}

// §1.4 "each target's id, name, status and type", with GetGateway failing --
// on the current role template, every gateway. The target list is its own
// call, so its answer is merged on its own terms even while the gateway's
// detail is incomplete:
//
//   - a list cut short after page 1 keeps the previous FULL list (the partial
//     page never replaces it), flagged targets_incomplete;
//   - a later complete read replaces it and CLEARS the flag -- a stale
//     targets_incomplete must not outlive the read that settled it;
//   - a complete read of no targets empties it -- never the previous list
//     resurrected.
//
// And every stored target carries all four D-85 keys, "" when AWS returned
// none (the second target has no status and no type).
//
// Safeguards (mutation-checked): the targets arm inside the detail_incomplete
// branch of workloadAttrsMerge; its `- 'gateway_targets' - 'targets_incomplete'`;
// the dropped omitempty on AWSGatewayTarget's name, status and type.
func TestP2S3bGatewayTargetsMergeWhileGetGatewayFails(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-gw-targets", true)
	a := l.account(accountA)
	role := a.role("gateway-role", "AROAS3BGWTARGETS01")
	core := &fakeAgentCore{
		gateways: []agentcoretypes.GatewaySummary{{GatewayId: aws.String("gw-t"),
			Name: aws.String("tools"), Status: agentcoretypes.GatewayStatusReady}},
		gatewayRoleByID: map[string]string{"gw-t": role},
		targetsByGateway: map[string][]agentcoretypes.TargetSummary{"gw-t": {
			{TargetId: aws.String("tgt-a"), Name: aws.String("lambda-a"),
				Status: agentcoretypes.TargetStatusReady, TargetType: agentcoretypes.TargetTypeLambda},
			{TargetId: aws.String("tgt-b"), Name: aws.String("bare-b")},
		}},
	}
	paged := &s3bPagedTargets{fakeAgentCore: core}
	f := &s3bFakes{agentCoreAPI: paged}

	s3bScanAndProject(l, a, f)
	targets, _, _ := s3bStoredTargets(t, l)
	if s3bTargetIDs(targets) != "tgt-a,tgt-b" {
		t.Fatalf("setup: stored targets = %v", targets)
	}
	for _, tg := range targets {
		for _, key := range []string{"id", "name", "status", "type"} {
			if _, ok := tg[key]; !ok {
				t.Errorf("stored target %v has no %q key: D-85's shape is [{id, name, status, type}] on every target", tg, key)
			}
		}
	}

	// ---- scan 2: GetGateway denied, and the target list cut after page 1 ----
	core.getGatewayFail = denied("bedrock-agentcore:GetGateway")
	paged.failAfterFirst = true
	s3bScanAndProject(l, a, f)
	targets, detail, incomplete := s3bStoredTargets(t, l)
	if !detail || !incomplete || s3bTargetIDs(targets) != "tgt-a,tgt-b" {
		t.Fatalf("after a failed GetGateway and a target list cut short: targets=%v detail_incomplete=%v "+
			"targets_incomplete=%v, want the previous full list kept, both flags set", targets, detail, incomplete)
	}

	// ---- scan 3: GetGateway still denied; the target list complete, tgt-b gone
	paged.failAfterFirst = false
	core.targetsByGateway["gw-t"] = core.targetsByGateway["gw-t"][:1]
	s3bScanAndProject(l, a, f)
	targets, detail, incomplete = s3bStoredTargets(t, l)
	if !detail || incomplete || s3bTargetIDs(targets) != "tgt-a" {
		t.Fatalf("after a complete target read (GetGateway still denied): targets=%v detail_incomplete=%v "+
			"targets_incomplete=%v, want [tgt-a] and the stale targets_incomplete cleared", targets, detail, incomplete)
	}

	// ---- scan 4: still denied; the gateway now has no targets at all --------
	core.targetsByGateway["gw-t"] = nil
	s3bScanAndProject(l, a, f)
	if targets, _, incomplete = s3bStoredTargets(t, l); len(targets) != 0 || incomplete {
		t.Fatalf("after a complete read of no targets: targets=%v targets_incomplete=%v, want none", targets, incomplete)
	}
}

/* ------------------------------- bare-id rows ------------------------------- */

// Before T3.6 a Bedrock agent whose GetAgent failed, and every AgentCore
// gateway (GetGateway has never been in the role template), were stored under
// the BARE id. Now keyed by the ARN, the object would get a second
// cloud_workload row beside the old one -- and a gateway's never ages out,
// since its surface stays partial until the stack grants GetGateway. The old
// row is adopted instead: re-keyed in place (same id, so its observations stay
// linked), or, when an ARN row already exists beside it, removed.
//
// Safeguards (mutation-checked): adoptBareIDRow's UPDATE and its DELETE.
func TestP2S3bBareIDRowsAreAdoptedByTheirARN(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-bare-ids", true)
	a := l.account(accountA)
	role := a.role("legacy-role", "AROAS3BLEGACYROLE1")
	agentARN := "arn:aws:bedrock:us-east-1:" + a.id + ":agent/AGENTOLD01"
	gwARN := "arn:aws:bedrock-agentcore:us-east-1:" + a.id + ":gateway/gw-old-1"

	// What the pre-T3.6 collector left: the agent under its bare id alone; the
	// gateway under its bare id AND (from a scan whose GetGateway answered)
	// under its ARN.
	plant := func(kind, native string) {
		if err := l.db.Exec(`INSERT INTO cloud_workload (workspace_id, connector_id, runtime_kind, native_id, name, region, last_seen_generation)
		                     VALUES (?, ?, ?, ?, 'legacy', 'us-east-1', 0)`, l.ws, a.conn, kind, native).Error; err != nil {
			t.Fatalf("plant %s: %v", native, err)
		}
	}
	plant(models.WorkloadBedrockAgent, "AGENTOLD01")
	plant(models.WorkloadBedrockAgentCoreGW, "gw-old-1")
	plant(models.WorkloadBedrockAgentCoreGW, gwARN)
	agentRow := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgent)[0].ID
	var gwARNRow = func() (id string) {
		for _, r := range s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreGW) {
			if r.NativeID == gwARN {
				return r.ID.String()
			}
		}
		return ""
	}()

	f := &s3bFakes{
		bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"AGENTOLD01": {
			AgentId: aws.String("AGENTOLD01"), AgentArn: aws.String(agentARN), AgentName: aws.String("old-bot"),
			AgentResourceRoleArn: aws.String(role), AgentStatus: bedrockagenttypes.AgentStatusPrepared,
		}}},
		agentCore: &fakeAgentCore{
			gateways: []agentcoretypes.GatewaySummary{{GatewayId: aws.String("gw-old-1"),
				Name: aws.String("old-tools"), Status: agentcoretypes.GatewayStatusReady}},
			getGatewayFail: denied("bedrock-agentcore:GetGateway"),
		},
	}
	s3bScanAndProject(l, a, f)

	agents := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgent)
	if len(agents) != 1 || agents[0].NativeID != agentARN || agents[0].ID != agentRow {
		t.Errorf("agent rows = %+v, want the bare-id row re-keyed in place to %s (id %s)", agents, agentARN, agentRow)
	}
	gws := s3bCloudWorkloads(t, l, models.WorkloadBedrockAgentCoreGW)
	if len(gws) != 1 || gws[0].NativeID != gwARN || gws[0].ID.String() != gwARNRow {
		t.Errorf("gateway rows = %+v, want only the ARN row %s (id %s): the bare-id duplicate removed", gws, gwARN, gwARNRow)
	}
}
