package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// T3.17 dedicated-identity isolation (SPEC-iga-phase3-policy.md §11; A33,
// A61): a dedicated_identity version on the source role's policy compiles a
// split and split_revert (no permission removed: the new role gets the
// source's managed policies by ARN), refused with
// migration_evidence_unavailable on the older discovery template; the split
// PR adds the role and moves the subject's binding; per compute type the
// migration row stays moving while anything runs on the source role, an
// unreadable DescribeTasks page makes it incomplete (never moved), and the
// deployment reaches applied_unverified only when the row is moved.

/* ------------------------------ AWS fakes -------------------------------- */

type p3iECS struct {
	service  string
	deps     []ecstypes.Deployment
	desired  int32
	running  int32
	tasks    map[string]string // task ARN -> task definition ARN
	failDesc bool
}

func (f *p3iECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-1:" + accountA + ":cluster/payments"}}, nil
}
func (f *p3iECS) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return &ecs.ListServicesOutput{ServiceArns: []string{f.service}}, nil
}
func (f *p3iECS) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: []ecstypes.Service{{ServiceArn: aws.String(f.service), Deployments: f.deps,
		DesiredCount: f.desired, RunningCount: f.running}}}, nil
}
func (f *p3iECS) ListTasks(_ context.Context, in *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	var out []string
	for t := range f.tasks {
		out = append(out, t)
	}
	return &ecs.ListTasksOutput{TaskArns: out}, nil
}
func (f *p3iECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	if f.failDesc {
		return nil, errors.New("AccessDeniedException: not authorized")
	}
	out := &ecs.DescribeTasksOutput{}
	for _, t := range in.Tasks {
		out.Tasks = append(out.Tasks, ecstypes.Task{TaskArn: aws.String(t), TaskDefinitionArn: aws.String(f.tasks[t]), LastStatus: aws.String("RUNNING")})
	}
	return out, nil
}

type p3iLambda struct {
	latest  string
	roles   map[string]string // version -> role
	alias   string
	weights map[string]float64
}

func (f *p3iLambda) GetFunctionConfiguration(_ context.Context, in *lambda.GetFunctionConfigurationInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error) {
	fn := "arn:aws:lambda:us-east-1:" + accountA + ":function:" + aws.ToString(in.FunctionName)
	if in.Qualifier == nil {
		return &lambda.GetFunctionConfigurationOutput{FunctionArn: aws.String(fn), Role: aws.String(f.latest)}, nil
	}
	q := aws.ToString(in.Qualifier)
	return &lambda.GetFunctionConfigurationOutput{FunctionArn: aws.String(fn + ":" + q), Role: aws.String(f.roles[q])}, nil
}
func (f *p3iLambda) ListAliases(context.Context, *lambda.ListAliasesInput, ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error) {
	a := lambdatypes.AliasConfiguration{Name: aws.String("live"), FunctionVersion: aws.String(f.alias)}
	if len(f.weights) > 0 {
		a.RoutingConfig = &lambdatypes.AliasRoutingConfiguration{AdditionalVersionWeights: f.weights}
	}
	return &lambda.ListAliasesOutput{Aliases: []lambdatypes.AliasConfiguration{a}}, nil
}
func (f *p3iLambda) ListVersionsByFunction(context.Context, *lambda.ListVersionsByFunctionInput, ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error) {
	var vs []lambdatypes.FunctionConfiguration
	for v, r := range f.roles {
		vs = append(vs, lambdatypes.FunctionConfiguration{Version: aws.String(v), Role: aws.String(r)})
	}
	return &lambda.ListVersionsByFunctionOutput{Versions: vs}, nil
}
func (f *p3iLambda) ListEventSourceMappings(context.Context, *lambda.ListEventSourceMappingsInput, ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error) {
	return &lambda.ListEventSourceMappingsOutput{}, nil
}

type p3iASG struct {
	name      string
	instances []string
	ltProfile string
	assoc     map[string]string // instance -> profile ARN
}

func (f *p3iASG) DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	g := astypes.AutoScalingGroup{AutoScalingGroupName: aws.String(f.name), AutoScalingGroupARN: aws.String("arn:asg"),
		LaunchTemplate: &astypes.LaunchTemplateSpecification{LaunchTemplateId: aws.String("lt-1"), Version: aws.String("$Latest")}}
	for _, i := range f.instances {
		g.Instances = append(g.Instances, astypes.Instance{InstanceId: aws.String(i), LifecycleState: astypes.LifecycleStateInService})
	}
	return &autoscaling.DescribeAutoScalingGroupsOutput{AutoScalingGroups: []astypes.AutoScalingGroup{g}}, nil
}
func (f *p3iASG) DescribeLaunchTemplateVersions(context.Context, *ec2.DescribeLaunchTemplateVersionsInput, ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	return &ec2.DescribeLaunchTemplateVersionsOutput{LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{{LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
		IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{Arn: aws.String(f.ltProfile)}}}}}, nil
}
func (f *p3iASG) DescribeIamInstanceProfileAssociations(context.Context, *ec2.DescribeIamInstanceProfileAssociationsInput, ...func(*ec2.Options)) (*ec2.DescribeIamInstanceProfileAssociationsOutput, error) {
	out := &ec2.DescribeIamInstanceProfileAssociationsOutput{}
	for i, p := range f.assoc {
		out.IamInstanceProfileAssociations = append(out.IamInstanceProfileAssociations, ec2types.IamInstanceProfileAssociation{
			InstanceId: aws.String(i), IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String(p)},
			State: ec2types.IamInstanceProfileAssociationStateAssociated})
	}
	return out, nil
}

/* -------------------------------- helpers -------------------------------- */

const p3iTrustHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func p3iRoleARN(name string) string { return "arn:aws:iam::" + accountA + ":role/" + name }

// identityOf is a role identity's id.
func (l *p3iLab) identityOf(roleID string) uuid.UUID {
	return bdbID(l.t, l.p2Lab, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND immutable_key = ?`, l.ws, roleID)
}

// graphWorkload adds a workload keyed by an ARN executing as identity.
func (l *p3iLab) graphWorkload(arn, kind string, identity uuid.UUID) uuid.UUID {
	id := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key) VALUES (?, ?, ?, ?, 'us-east-1', ?)`,
		id, l.ws, kind, arn[strings.LastIndexAny(arn, "/:")+1:], igagraph.Key("aws", arn))
	l.relate(id, identity)
	return id
}

func (l *p3iLab) relate(workload, identity uuid.UUID) {
	p3exec(l.t, l.db, `INSERT INTO iga_relationship (workspace_id, relationship_type, source_workload_id, target_identity_account_id, basis, state, source_key, partition_key)
		VALUES (?, 'executes_as', ?, ?, 'declared', 'current', ?, ?)`, l.ws, workload, identity, "rel:"+uuid.NewString(), "aws:"+accountA)
}

// newRoleIdentity publishes the dedicated role in the graph and the live read.
func (l *p3iLab) newRole(name, roleID, managed string) uuid.UUID {
	id := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, 'role', 'aws', ?, 'immutable', ?, ?, '{"path":"/"}'::jsonb)`, id, l.ws, igagraph.IdentityARNKey(p3iRoleARN(name)), roleID, name)
	l.live.setRole(igagov.LiveRole{RoleID: roleID, ARN: p3iRoleARN(name), Name: name, Path: "/", AccountID: accountA, Partition: "aws",
		Tags: map[string]string{}, TrustPolicyHash: p3iTrustHash, ManagedPolicies: []igagov.PolicyRef{{Ref: managed, DocumentHash: "sha256:" + strings.Repeat("b", 64)}},
		InlinePolicies: []igagov.PolicyRef{}})
	return id
}

// isolate sets up a source role, proposes and approves a dedicated identity
// for the workload, and returns (policy, version 2 plans).
func (l *p3iLab) isolate(name, roleID, newName, workloadID, binding, ref string) (string, map[string]any) {
	l.t.Helper()
	pol, _ := l.proposeTemplateDelivery(roleID)
	managed := l.a.policyARN(name + "Work")
	intent := map[string]any{"kind": "dedicated_identity",
		"source":   map[string]any{"identity_account_id": l.identityOf(roleID).String(), "role_id": roleID, "account_id": accountA},
		"workload": map[string]any{"workload_id": workloadID, "binding_kind": binding, "binding_ref": ref},
		"new_role": map[string]any{"name": newName, "path": "/", "trust_policy_hash": p3iTrustHash, "managed_policy_arns": []string{managed},
			"inline_policies": []any{}},
		"delivery": "iac_pr"}
	code, body := l.call(l.author, http.MethodPost, "/policies/"+pol+"/versions", map[string]any{"intent": intent, "base_version_no": 1})
	l.must(code, body, http.StatusCreated, "dedicated version")
	return pol, nil
}

func (l *p3iLab) proposeTemplateDelivery(roleID string) (string, map[string]any) {
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []any{map[string]any{"provider": "aws", "role_id": roleID}}, "delivery": "iac_pr"})
	d := l.must(code, body, http.StatusCreated, "POST /proposals")
	return d["policy"].(map[string]any)["id"].(string), d
}

// migration is the deployment's migration row.
func (l *p3iLab) migration(dep uuid.UUID) models.IGAGovWorkloadMigration {
	l.t.Helper()
	var m models.IGAGovWorkloadMigration
	if err := l.db.Where("workspace_id = ? AND plan_id = ?", l.ws, l.dep(dep).PlanID).Take(&m).Error; err != nil {
		l.t.Fatal(err)
	}
	return m
}

func (l *p3iLab) setTemplate(v string) {
	p3exec(l.t, l.db, `UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{template_version}', to_jsonb(?::text)) WHERE id = ?`, v, l.a.conn)
}

const p3iIsoTF = `resource "aws_iam_role" "src" {
  name               = "%[1]s"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy_attachment" "src_work" {
  role       = aws_iam_role.src.name
  policy_arn = "%[2]s"
}

resource "aws_ecs_task_definition" "refund" {
  family        = "refund-agent"
  task_role_arn = aws_iam_role.src.arn
}

resource "aws_ecs_service" "refund" {
  name            = "refund-agent"
  task_definition = aws_ecs_task_definition.refund.arn
}

resource "aws_lambda_function" "fn" {
  function_name = "%[3]s"
  role          = aws_iam_role.src.arn
  publish       = true
}

resource "aws_lambda_alias" "live" {
  name             = "live"
  function_name    = aws_lambda_function.fn.function_name
  function_version = aws_lambda_function.fn.version
}

resource "aws_iam_instance_profile" "asg" {
  name = "%[1]s"
  role = aws_iam_role.src.name
}

resource "aws_launch_template" "lt" {
  name = "refund"
  iam_instance_profile {
    name = aws_iam_instance_profile.asg.name
  }
}

resource "aws_autoscaling_group" "asg" {
  name = "refund-asg"
  launch_template {
    id = aws_launch_template.lt.id
  }
}
`

/* -------------------------------- scenarios ------------------------------ */

// runIsolation is one compute type of A33: propose (refused on the older
// template, then compiled), approve, deliver the split PR, merge, and walk
// the migration evidence through `step` until the row is moved.
func p3iRunIsolation(t *testing.T, kind string) {
	l := newP3iLab(t, "p3-t317-a33-"+kind)
	name, roleID := "Shared"+strings.ToUpper(kind[:1])+kind[1:]+"Role", "AROASHAREDISO"+strings.ToUpper(kind[:3])
	src := l.role(name, roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.live.mu.Lock()
	l.live.roles[src].TrustPolicyHash = p3iTrustHash
	l.live.mu.Unlock()
	l.publish()
	identity := l.identityOf(roleID)
	managed := l.a.policyARN(name + "Work")
	fn := strings.ToLower(name) + "-fn"
	fnARN := "arn:aws:lambda:us-east-1:" + accountA + ":function:" + fn
	newName := "refund-" + kind + "-role"
	newARN := p3iRoleARN(newName)
	td := func(rev int) string {
		return fmt.Sprintf("arn:aws:ecs:us-east-1:%s:task-definition/refund-agent:%d", accountA, rev)
	}
	svcARN := "arn:aws:ecs:us-east-1:" + accountA + ":service/payments/refund-agent"
	asgARN := "arn:aws:autoscaling:us-east-1:" + accountA + ":autoScalingGroup:9f3c:autoScalingGroupName/refund-asg"
	inst := func(i string) string { return "arn:aws:ec2:us-east-1:" + accountA + ":instance/" + i }

	var workload uuid.UUID
	var binding, ref string
	switch kind {
	case "ecs":
		workload = l.graphWorkload(td(4), "ecs_task", identity)
		l.graphWorkload(td(3), "ecs_task", identity)
		binding, ref = igagov.BindingECSTaskRole, svcARN
	case "lambda":
		workload = bdbID(t, l.p2Lab, `SELECT id FROM iga_workload WHERE workspace_id = ? AND source_key = ?`, l.ws, igagraph.Key("aws", fnARN))
		binding, ref = igagov.BindingLambdaRole, fnARN
	case "asg":
		workload = l.graphWorkload(inst("i-2"), "ec2_instance", identity)
		l.graphWorkload(inst("i-1"), "ec2_instance", identity)
		binding, ref = igagov.BindingEC2InstanceProfile, asgARN
	}
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": fmt.Sprintf(p3iIsoTF, name, managed, fn)})
	l.grantWrite()
	policy, _ := l.isolate(name, roleID, newName, workload.String(), binding, ref)

	// Older discovery template: no isolation (migration_evidence_unavailable).
	l.setTemplate("2026-09-24")
	code, body := l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions/2/propose", nil)
	if code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(body), igagov.RefuseMigrationEvidence) {
		t.Fatalf("older template: %d %v", code, body)
	}
	l.setTemplate(awsdiscovery.ResourcePolicyTemplateVersion)
	plans := l.compile(policy, 2)
	sp, rv := p3iPlan(t, plans, "split"), p3iPlan(t, plans, "split_revert")
	if sp["delivery"] != "iac_pr" || sp["desired_attachment"] != "unchanged" || rv["delivery"] != "iac_pr" {
		t.Fatalf("split %v / revert %v (notes %s)", sp, rv, p3iNotes(sp))
	}
	// A61: no service is removed; the new role gets the source's policies by ARN.
	ops := fmt.Sprint(sp["operations"])
	if len(dig(sp, "impact", "removed").([]any)) != 0 || !strings.Contains(ops, "AttachRolePolicy") || !strings.Contains(ops, managed) {
		t.Fatalf("split impact %v ops %s", sp["impact"], ops)
	}
	// The impact names KMS grants as not analysed; approval must accept it.
	if keys := p3aItemKeys(plans, services.GovAcceptUnanalysed); !p3iHas(keys, "kms_grants") {
		t.Fatalf("unanalysed items %v", keys)
	}
	l.approveAll(policy, 2)
	dep := l.deploy(policy, 2, "split")
	out := l.deliver(dep)
	if out.State != "awaiting_merge" {
		t.Fatalf("split deliver %+v", out)
	}
	tf, _ := l.gh.PRFile(l.repo, out.PR.Number, "iam/main.tf")
	newTF := strings.ReplaceAll(newName, "-", "_")
	if !strings.Contains(tf, `resource "aws_iam_role" "`+newTF+`"`) || !strings.Contains(tf, `policy_arn = "`+managed+`"`) ||
		!strings.Contains(tf, "assume_role_policy = jsonencode") {
		t.Fatalf("split PR:\n%s", tf)
	}
	switch kind {
	case "ecs":
		if !strings.Contains(p3iBlock(tf, `resource "aws_ecs_task_definition" "refund"`), "task_role_arn = aws_iam_role."+newTF+".arn") {
			t.Fatalf("ECS binding not moved:\n%s", tf)
		}
	case "lambda":
		if !strings.Contains(p3iBlock(tf, `resource "aws_lambda_function" "fn"`), "role          = aws_iam_role."+newTF+".arn") {
			t.Fatalf("Lambda binding not moved:\n%s", tf)
		}
	case "asg":
		if !strings.Contains(tf, `resource "aws_iam_instance_profile" "`+newTF+`"`) ||
			!strings.Contains(p3iBlock(tf, `resource "aws_launch_template" "lt"`), "aws_iam_instance_profile."+newTF+".name") ||
			!strings.Contains(p3iBlock(tf, `resource "aws_autoscaling_group" "asg"`), "instance_refresh") {
			t.Fatalf("ASG binding not moved:\n%s", tf)
		}
	}
	l.gh.Merge(l.repo, out.PR.Number, l.clock)
	l.sync(l.change(dep).ID)
	// Merged; the migration evidence cannot be read yet (no session): the
	// row is incomplete, never moved, and the deployment awaits the apply.
	m := l.migration(dep)
	if m.State != "incomplete" || m.EvidenceComplete || l.dep(dep).State != "awaiting_apply" || m.FromRoleARN != src || m.ToRoleARN != newARN || len(m.FromWorkloadKeys) == 0 {
		t.Fatalf("migration row %+v", m)
	}

	// The pipeline creates the new role (published in the graph).
	newIdentity := l.newRole(newName, "AROANEWISO"+strings.ToUpper(kind[:3])+"00", managed)
	ecsF := &p3iECS{service: svcARN, tasks: map[string]string{}}
	lamF := &p3iLambda{roles: map[string]string{}}
	asgF := &p3iASG{name: "refund-asg"}
	l.delivery.WithMigrationClients(func(context.Context, uuid.UUID, uuid.UUID, string) (awsdiscovery.MigrationClients, error) {
		return awsdiscovery.MigrationClients{ECS: ecsF, Lambda: lamF, AutoScaling: asgF, EC2: asgF}, nil
	})
	newProfile := "arn:aws:iam::" + accountA + ":instance-profile/" + newName
	oldProfile := "arn:aws:iam::" + accountA + ":instance-profile/" + name
	observe := func(wantRow, wantDep string, wantRemaining int) models.IGAGovWorkloadMigration {
		t.Helper()
		o := l.observe(dep)
		m := l.migration(dep)
		if m.State != wantRow || o.State != wantDep || (wantRemaining >= 0 && (m.RemainingOldRefs == nil || *m.RemainingOldRefs != wantRemaining)) ||
			(wantRemaining < 0 && m.RemainingOldRefs != nil) {
			rem := "nil"
			if m.RemainingOldRefs != nil {
				rem = fmt.Sprint(*m.RemainingOldRefs)
			}
			t.Fatalf("want row %s dep %s remaining %d; got row %s (complete %v, remaining %s, evidence %s) dep %s %+v",
				wantRow, wantDep, wantRemaining, m.State, m.EvidenceComplete, rem, m.Evidence, o.State, o.Class)
		}
		return m
	}
	switch kind {
	case "ecs":
		l.graphWorkload(td(5), "ecs_task", newIdentity)
		ecsF.deps = []ecstypes.Deployment{{Status: aws.String("PRIMARY"), TaskDefinition: aws.String(td(5)), RolloutState: ecstypes.DeploymentRolloutStateCompleted}}
		ecsF.desired, ecsF.running = 4, 4
		for i := 1; i <= 4; i++ {
			ecsF.tasks[fmt.Sprintf("arn:aws:ecs:us-east-1:%s:task/payments/t%d", accountA, i)] = td(5)
		}
		ecsF.tasks["arn:aws:ecs:us-east-1:"+accountA+":task/payments/t4"] = td(4)
		observe("moving", "awaiting_apply", 1)
		// Every task on revision 5, but a DescribeTasks page is unreadable.
		ecsF.tasks["arn:aws:ecs:us-east-1:"+accountA+":task/payments/t4"] = td(5)
		ecsF.failDesc = true
		if m := observe("incomplete", "awaiting_apply", -1); m.EvidenceComplete {
			t.Fatal("incomplete evidence recorded complete")
		}
		ecsF.failDesc = false
		m := observe("moved", "applied_unverified", 0)
		if !p3iStrHas(m.ToWorkloadKeys, igagraph.Key("aws", td(5))) || !p3iStrHas(m.FromWorkloadKeys, igagraph.Key("aws", td(4))) {
			t.Fatalf("revision link %v -> %v", m.FromWorkloadKeys, m.ToWorkloadKeys)
		}
		// refund-agent:4 and :5 stay two graph workloads.
		if n := l.count(`SELECT count(*) FROM iga_workload WHERE workspace_id = ? AND source_key IN (?, ?)`, l.ws,
			igagraph.Key("aws", td(4)), igagraph.Key("aws", td(5))); n != 2 {
			t.Fatalf("%d revision workloads", n)
		}
	case "lambda":
		lamF.latest = newARN
		lamF.roles = map[string]string{"1": src, "2": newARN}
		lamF.alias, lamF.weights = "2", map[string]float64{"1": 0.1}
		l.relate(workload, newIdentity) // the publication moved executes_as
		observe("moving", "awaiting_apply", 1)
		lamF.weights = nil
		observe("moved", "applied_unverified", 0)
	case "asg":
		asgF.instances = []string{"i-1", "i-2"}
		asgF.ltProfile = newProfile
		asgF.assoc = map[string]string{"i-1": newProfile, "i-2": oldProfile}
		l.relate(workload, newIdentity)
		observe("moving", "awaiting_apply", 1)
		asgF.assoc["i-2"] = newProfile
		observe("moved", "applied_unverified", 0)
	}
	var ledger []string
	l.db.Raw(`SELECT kind || ' ' || native_arn || ' ' || state FROM iga_gov_artifact WHERE workspace_id = ? ORDER BY kind`, l.ws).Scan(&ledger)
	if strings.Join(ledger, ";") != "dedicated_role "+newARN+" present;workload_binding "+ref+" present" {
		t.Fatalf("ledger %v", ledger)
	}
}

func p3iStrHas(a pq.StringArray, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func TestP3T317IsolationECS(t *testing.T)    { p3iRunIsolation(t, "ecs") }
func TestP3T317IsolationLambda(t *testing.T) { p3iRunIsolation(t, "lambda") }
func TestP3T317IsolationASG(t *testing.T)    { p3iRunIsolation(t, "asg") }

// A61 (pure part): reducing the new role later is an ordinary right-size
// with its own evidence; with fewer than 30 qualified days the removal is
// refused, so the split itself never removes the monthly job's S3.
func TestP3T317IsolationReductionNeedsOwnEvidence(t *testing.T) {
	at := time.Now().UTC().Add(-time.Hour)
	run := uuid.NewString()
	role := igagov.LiveRole{RoleID: "AROANEWROLE00001", ARN: p3iRoleARN("monthly-job-role"), Name: "monthly-job-role", Path: "/", AccountID: accountA,
		Tags: map[string]string{}, ManagedPolicies: []igagov.PolicyRef{}, InlinePolicies: []igagov.PolicyRef{}}
	b, err := igagov.BuildBundle(igagov.BundleInput{BuiltAt: time.Now().UTC(),
		Sources: []igagov.BundleSourceInput{{Kind: igagov.SourceAWSPublication, Rev: 1, PublishedAt: at, ConnectorID: uuid.NewString(),
			ConnectorRun: run, Authenticated: true, Ordered: true, ActivityReportGeneratedAt: &at,
			ResourcePolicyCoverage: igagov.CoverageComplete, ResourcePolicyRun: run}},
		Target: igagov.BundleTarget{AccountID: accountA, RoleID: role.RoleID, RoleARN: role.ARN}, RemovedServices: []string{"s3"},
		Owners: []string{uuid.NewString()}, Activity: []igagov.BundleActivity{{Service: "s3", State: igagov.EvidenceCollected,
			Outcome: igagov.QualNoAttempt, GrantAgeBasis: igagov.GrantAgeObservedSinceChange, QualifiedDays: 9}}}, igagov.DefaultTrustRules())
	if err != nil {
		t.Fatal(err)
	}
	tp, err := igagov.CompileTarget(igagov.TargetInput{
		Control: igagov.ControlRef{ID: uuid.NewString(), PolicyID: uuid.NewString(), AccountID: accountA, RoleID: role.RoleID, WorkspaceRef: "ws"},
		Intent: igagov.RightSizeIntent{Kind: igagov.IntentRightSizeServices, Subjects: []igagov.Subject{{IdentityAccountID: uuid.NewString(),
			RoleID: role.RoleID, AccountID: accountA}}, ObservationDays: 7, Delivery: igagov.DeliveryExport, EvidenceRev: 1,
			Remove: []igagov.RemoveEntry{{Service: "s3", Basis: igagov.RemoveNoAttempt, QualifiedDays: 30, GrantAgeBasis: igagov.GrantAgeObservedSinceChange}}},
		Live:     igagov.LiveRead{ReadAt: time.Now(), Role: &role, Policies: map[string]*igagov.LivePolicy{igagov.AuthSecBoundaryARN("aws", accountA, role.RoleID): nil}},
		Evidence: igagov.EvidenceRef{Bundle: b, EvidenceRev: 1, ScanRunID: run}, AccountServices: []string{"s3"}})
	if err != nil {
		t.Fatal(err)
	}
	if tp.Apply.Eligible() || !strings.Contains(tp.Apply.IneligibleReason, igagov.RefuseRemovalNotJustified) {
		t.Fatalf("reduction with 9 qualified days: %s %s", tp.Apply.Eligibility, tp.Apply.IneligibleReason)
	}
}
