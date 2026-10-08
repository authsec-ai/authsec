package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
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
// A61) with the review fixes of P1-12: a dedicated_identity version on the
// source role's policy compiles a split and split_revert (the new role gets
// the source's identity policies -- managed by ARN, inline copies, trust
// and boundary -- archived by hash), refused with
// migration_evidence_unavailable on the older discovery template; the split
// PR is rendered from the APPROVED documents and says "same identity
// policies" with the effective-access qualification, never "no permission
// is removed"; every ECS service of the family is its own migration subject
// with its own evidence; a Lambda read error is never ignored (propose 503,
// observe incomplete) and versions behind no alias are unanalysed; the
// deployment reaches applied_unverified only when every row is moved.

/* ------------------------------ AWS fakes -------------------------------- */

type p3iSvc struct {
	deps     []ecstypes.Deployment
	desired  int32
	running  int32
	tasks    map[string]string // task ARN -> task definition ARN
	failList bool              // ListTasks for this service fails
}

type p3iECS struct {
	mu       sync.Mutex
	services map[string]*p3iSvc // service ARN ->
	failDesc bool
}

func (f *p3iECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-1:" + accountA + ":cluster/payments"}}, nil
}
func (f *p3iECS) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for a := range f.services {
		out = append(out, a)
	}
	sort.Strings(out)
	return &ecs.ListServicesOutput{ServiceArns: out}, nil
}
func (f *p3iECS) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &ecs.DescribeServicesOutput{}
	for _, a := range in.Services {
		s := f.services[a]
		if s == nil {
			continue
		}
		td := ""
		for _, d := range s.deps {
			if aws.ToString(d.Status) == "PRIMARY" {
				td = aws.ToString(d.TaskDefinition)
			}
		}
		out.Services = append(out.Services, ecstypes.Service{ServiceArn: aws.String(a), Deployments: s.deps, TaskDefinition: aws.String(td),
			DesiredCount: s.desired, RunningCount: s.running})
	}
	return out, nil
}
func (f *p3iECS) ListTasks(_ context.Context, in *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for a, s := range f.services {
		if in.ServiceName != nil {
			if !strings.HasSuffix(a, "/"+aws.ToString(in.ServiceName)) {
				continue
			}
			if s.failList {
				return nil, errors.New("ThrottlingException: rate exceeded")
			}
		}
		for t, td := range s.tasks {
			if in.Family != nil && !strings.Contains(td, ":task-definition/"+aws.ToString(in.Family)+":") {
				continue
			}
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return &ecs.ListTasksOutput{TaskArns: out}, nil
}
func (f *p3iECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDesc {
		return nil, errors.New("AccessDeniedException: not authorized")
	}
	out := &ecs.DescribeTasksOutput{}
	for _, t := range in.Tasks {
		for _, s := range f.services {
			if td, ok := s.tasks[t]; ok {
				out.Tasks = append(out.Tasks, ecstypes.Task{TaskArn: aws.String(t), TaskDefinitionArn: aws.String(td), LastStatus: aws.String("RUNNING")})
			}
		}
	}
	return out, nil
}

type p3iLambda struct {
	latest      string
	roles       map[string]string // version -> role
	alias       string
	weights     map[string]float64
	failAliases bool
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
	if f.failAliases {
		return nil, errors.New("ServiceException: internal error")
	}
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

// p3iTrustDoc is the source role's trust policy as AWS returns it; the TF
// source below declares the same document literally.
const p3iTrustDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

// p3iTrust is the canonical trust document and its hash.
func p3iTrust(t *testing.T) (string, string) {
	t.Helper()
	c, h, err := igagov.CanonicalDocument(p3iTrustDoc)
	if err != nil {
		t.Fatal(err)
	}
	return string(c), h
}

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

// newRole publishes the dedicated role in the graph and the live read.
func (l *p3iLab) newRole(name, roleID, managed string) uuid.UUID {
	id := uuid.New()
	_, th := p3iTrust(l.t)
	p3exec(l.t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, 'role', 'aws', ?, 'immutable', ?, ?, '{"path":"/"}'::jsonb)`, id, l.ws, igagraph.IdentityARNKey(p3iRoleARN(name)), roleID, name)
	l.live.setRole(igagov.LiveRole{RoleID: roleID, ARN: p3iRoleARN(name), Name: name, Path: "/", AccountID: accountA, Partition: "aws",
		Tags: map[string]string{}, TrustPolicyHash: th, ManagedPolicies: []igagov.PolicyRef{{Ref: managed, DocumentHash: "sha256:" + strings.Repeat("b", 64)}},
		InlinePolicies: []igagov.PolicyRef{}})
	return id
}

// isolate creates the dedicated-identity version 2 of the source role's
// policy and returns the policy id.
func (l *p3iLab) isolate(name, roleID, newName, workloadID, binding, ref string) string {
	l.t.Helper()
	pol, _ := l.proposeTemplateDelivery(roleID)
	managed := l.a.policyARN(name + "Work")
	_, th := p3iTrust(l.t)
	intent := map[string]any{"kind": "dedicated_identity",
		"source":   map[string]any{"identity_account_id": l.identityOf(roleID).String(), "role_id": roleID, "account_id": accountA},
		"workload": map[string]any{"workload_id": workloadID, "binding_kind": binding, "binding_ref": ref},
		"new_role": map[string]any{"name": newName, "path": "/", "trust_policy_hash": th, "managed_policy_arns": []string{managed},
			"inline_policies": []any{}},
		"delivery": "iac_pr"}
	code, body := l.call(l.author, http.MethodPost, "/policies/"+pol+"/versions", map[string]any{"intent": intent, "base_version_no": 1})
	l.must(code, body, http.StatusCreated, "dedicated version")
	return pol
}

func (l *p3iLab) proposeTemplateDelivery(roleID string) (string, map[string]any) {
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []any{map[string]any{"provider": "aws", "role_id": roleID}}, "delivery": "iac_pr"})
	d := l.must(code, body, http.StatusCreated, "POST /proposals")
	return d["policy"].(map[string]any)["id"].(string), d
}

// migration is the deployment's single migration row.
func (l *p3iLab) migration(dep uuid.UUID) models.IGAGovWorkloadMigration {
	l.t.Helper()
	ms := l.migrations(dep)
	if len(ms) != 1 {
		l.t.Fatalf("%d migration rows", len(ms))
	}
	return ms[0]
}

// migrations are the deployment's migration rows by subject.
func (l *p3iLab) migrations(dep uuid.UUID) []models.IGAGovWorkloadMigration {
	l.t.Helper()
	var ms []models.IGAGovWorkloadMigration
	if err := l.db.Where("workspace_id = ? AND plan_id = ?", l.ws, l.dep(dep).PlanID).Order("subject_arn").Find(&ms).Error; err != nil {
		l.t.Fatal(err)
	}
	return ms
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

resource "aws_ecs_service" "replay" {
  name            = "refund-replay"
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

// p3iIso is one compute type's isolation set-up: the source role with a
// real trust document, the graph workloads, the mapped source, the AWS
// fakes behind the process-wide migration-evidence clients, and version 2.
type p3iIso struct {
	*p3iLab
	kind, name, roleID, src, managed string
	newName, newARN, ref, svcARN, fn string
	identity                         uuid.UUID
	ecsF                             *p3iECS
	lamF                             *p3iLambda
	asgF                             *p3iASG
	sessionDown                      bool
	policy                           string
	td                               func(int) string
	svc                              func(string) string
	inst                             func(string) string
	workload                         uuid.UUID
}

func p3iIsoSetup(t *testing.T, kind string) *p3iIso {
	x := &p3iIso{p3iLab: newP3iLab(t, "p3-t317-a33-"+kind), kind: kind}
	l := x.p3iLab
	x.name, x.roleID = "Shared"+strings.ToUpper(kind[:1])+kind[1:]+"Role", "AROASHAREDISO"+strings.ToUpper(kind[:3])
	x.src = l.role(x.name, x.roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	tc, th := p3iTrust(t)
	l.live.mu.Lock()
	l.live.roles[x.src].TrustPolicyHash = th
	l.live.roles[x.src].Documents = map[string]string{th: tc}
	l.live.mu.Unlock()
	l.publish()
	x.identity = l.identityOf(x.roleID)
	x.managed = l.a.policyARN(x.name + "Work")
	x.fn = strings.ToLower(x.name) + "-fn"
	fnARN := "arn:aws:lambda:us-east-1:" + accountA + ":function:" + x.fn
	x.newName = "refund-" + kind + "-role"
	x.newARN = p3iRoleARN(x.newName)
	x.td = func(rev int) string {
		return fmt.Sprintf("arn:aws:ecs:us-east-1:%s:task-definition/refund-agent:%d", accountA, rev)
	}
	x.svc = func(n string) string { return "arn:aws:ecs:us-east-1:" + accountA + ":service/payments/" + n }
	x.svcARN = x.svc("refund-agent")
	asgARN := "arn:aws:autoscaling:us-east-1:" + accountA + ":autoScalingGroup:9f3c:autoScalingGroupName/refund-asg"
	x.inst = func(i string) string { return "arn:aws:ec2:us-east-1:" + accountA + ":instance/" + i }
	x.ecsF = &p3iECS{services: map[string]*p3iSvc{}}
	x.lamF = &p3iLambda{roles: map[string]string{}}
	x.asgF = &p3iASG{name: "refund-asg"}
	factory := func(context.Context, uuid.UUID, uuid.UUID, string) (awsdiscovery.MigrationClients, error) {
		if x.sessionDown {
			return awsdiscovery.MigrationClients{}, errors.New("discovery session unavailable")
		}
		return awsdiscovery.MigrationClients{ECS: x.ecsF, Lambda: x.lamF, AutoScaling: x.asgF, EC2: x.asgF}, nil
	}
	services.SetGovMigrationClients(factory)
	t.Cleanup(func() { services.SetGovMigrationClients(nil) })
	var binding string
	switch kind {
	case "ecs":
		x.workload = l.graphWorkload(x.td(4), "ecs_task", x.identity)
		l.graphWorkload(x.td(3), "ecs_task", x.identity)
		binding, x.ref = igagov.BindingECSTaskRole, x.svcARN
		// Two services of the family run the source-role revision 4; a
		// service of another family does not.
		rev4 := []ecstypes.Deployment{{Status: aws.String("PRIMARY"), TaskDefinition: aws.String(x.td(4)), RolloutState: ecstypes.DeploymentRolloutStateCompleted}}
		x.ecsF.services[x.svcARN] = &p3iSvc{deps: rev4, desired: 4, running: 4, tasks: map[string]string{}}
		for i := 1; i <= 4; i++ {
			x.ecsF.services[x.svcARN].tasks[fmt.Sprintf("arn:aws:ecs:us-east-1:%s:task/payments/t%d", accountA, i)] = x.td(4)
		}
		x.ecsF.services[x.svc("refund-replay")] = &p3iSvc{deps: rev4, desired: 1, running: 1,
			tasks: map[string]string{"arn:aws:ecs:us-east-1:" + accountA + ":task/payments/b1": x.td(4)}}
		x.ecsF.services[x.svc("billing")] = &p3iSvc{deps: []ecstypes.Deployment{{Status: aws.String("PRIMARY"),
			TaskDefinition: aws.String("arn:aws:ecs:us-east-1:" + accountA + ":task-definition/billing:7"), RolloutState: ecstypes.DeploymentRolloutStateCompleted}},
			desired: 1, running: 1, tasks: map[string]string{}}
	case "lambda":
		x.workload = bdbID(t, l.p2Lab, `SELECT id FROM iga_workload WHERE workspace_id = ? AND source_key = ?`, l.ws, igagraph.Key("aws", fnARN))
		binding, x.ref = igagov.BindingLambdaRole, fnARN
		// live -> 1; version 3 is behind no alias (unanalysed).
		x.lamF.latest, x.lamF.alias = x.src, "1"
		x.lamF.roles = map[string]string{"1": x.src, "3": x.src}
	case "asg":
		x.workload = l.graphWorkload(x.inst("i-2"), "ec2_instance", x.identity)
		l.graphWorkload(x.inst("i-1"), "ec2_instance", x.identity)
		binding, x.ref = igagov.BindingEC2InstanceProfile, asgARN
	}
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": fmt.Sprintf(p3iIsoTF, x.name, x.managed, x.fn)})
	l.grantWrite()
	x.policy = l.isolate(x.name, x.roleID, x.newName, x.workload.String(), binding, x.ref)
	return x
}

// p3iRunIsolation is one compute type of A33: propose (refused on the older
// template, then compiled), approve, deliver the split PR (rendered from
// the approved documents, qualified wording), merge, and walk the migration
// evidence of every subject until each row is moved.
func p3iRunIsolation(t *testing.T, kind string) {
	x := p3iIsoSetup(t, kind)
	l := x.p3iLab

	// Older discovery template: no isolation (migration_evidence_unavailable).
	l.setTemplate("2026-09-24")
	code, body := l.call(l.author, http.MethodPost, "/policies/"+x.policy+"/versions/2/propose", nil)
	if code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(body), igagov.RefuseMigrationEvidence) {
		t.Fatalf("older template: %d %v", code, body)
	}
	l.setTemplate(awsdiscovery.ResourcePolicyTemplateVersion)
	if kind == "lambda" {
		// P1-12 (c): an unreadable alias listing is never "no aliases".
		x.lamF.failAliases = true
		code, body := l.call(l.author, http.MethodPost, "/policies/"+x.policy+"/versions/2/propose", nil)
		if code != http.StatusServiceUnavailable || dig(body, "error", "code") != services.GovCodeDiscoveryUnavail {
			t.Fatalf("unreadable aliases: %d %v", code, body)
		}
		x.lamF.failAliases = false
	}
	plans := l.compile(x.policy, 2)
	sp, rv := p3iPlan(t, plans, "split"), p3iPlan(t, plans, "split_revert")
	if sp["delivery"] != "iac_pr" || sp["desired_attachment"] != "unchanged" || rv["delivery"] != "iac_pr" {
		t.Fatalf("split %v / revert %v (notes %s)", sp, rv, p3iNotes(sp))
	}
	// A61: no service is removed; the new role gets the source's policies by ARN.
	ops := fmt.Sprint(sp["operations"])
	if len(dig(sp, "impact", "removed").([]any)) != 0 || !strings.Contains(ops, "AttachRolePolicy") || !strings.Contains(ops, x.managed) {
		t.Fatalf("split impact %v ops %s", sp["impact"], ops)
	}
	// The impact names KMS grants as not analysed; approval must accept it.
	keys := p3aItemKeys(plans, services.GovAcceptUnanalysed)
	if !p3iHas(keys, "kms_grants") {
		t.Fatalf("unanalysed items %v", keys)
	}
	var subjects []string
	switch kind {
	case "lambda":
		// P1-12 (c): the version behind no alias is an unanalysed item.
		if !p3iHas(keys, "lambda_version_without_alias:3") || p3iHas(keys, "lambda_version_without_alias:1") {
			t.Fatalf("unaliased versions %v", keys)
		}
		subjects = []string{x.ref}
	case "ecs":
		// P1-12 (d): every service running a source-role revision of the
		// family is a subject; billing (another family) is not.
		subjects = []string{x.svcARN, x.svc("refund-replay")}
		if got := fmt.Sprint(dig(sp, "diff", "split", "subject_arns")); got != fmt.Sprint([]any{x.svcARN, x.svc("refund-replay")}) {
			t.Fatalf("ECS subjects %s", got)
		}
	default:
		subjects = []string{x.ref}
	}
	l.approveAll(x.policy, 2)
	dep := l.deploy(x.policy, 2, "split")
	out := l.deliver(dep)
	if out.State != "awaiting_merge" {
		t.Fatalf("split deliver %+v", out)
	}
	tf, _ := l.gh.PRFile(l.repo, out.PR.Number, "iam/main.tf")
	newTF := strings.ReplaceAll(x.newName, "-", "_")
	nb := p3iBlock(tf, `resource "aws_iam_role" "`+newTF+`"`)
	if nb == "" || !strings.Contains(tf, `policy_arn = "`+x.managed+`"`) || !strings.Contains(nb, "assume_role_policy = jsonencode") ||
		!strings.Contains(nb, `"ecs-tasks.amazonaws.com"`) {
		t.Fatalf("split PR:\n%s", tf)
	}
	// P1-12 (a): the PR text qualifies the claim (§11, §9.7).
	_, prBody := l.gh.PRBody(l.repo, out.PR.Number)
	if strings.Contains(prBody, "No permission is removed") || !strings.Contains(prBody, "same identity policies") ||
		!strings.Contains(prBody, "not evaluated effective access") || !strings.Contains(prBody, "KMS grants") {
		t.Fatalf("PR body:\n%s", prBody)
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
	// Merged; the migration evidence cannot be read (no session): every row
	// is incomplete, never moved, and the deployment awaits the apply.
	x.sessionDown = true
	l.sync(l.change(dep).ID)
	x.sessionDown = false
	ms := l.migrations(dep)
	if len(ms) != len(subjects) {
		t.Fatalf("%d migration rows for subjects %v", len(ms), subjects)
	}
	for i, m := range ms {
		if m.SubjectARN != subjects[i] || m.State != "incomplete" || m.EvidenceComplete || l.dep(dep).State != "awaiting_apply" ||
			m.FromRoleARN != x.src || m.ToRoleARN != x.newARN || len(m.FromWorkloadKeys) == 0 {
			t.Fatalf("migration row %+v", m)
		}
	}

	// The pipeline creates the new role (published in the graph).
	newIdentity := l.newRole(x.newName, "AROANEWISO"+strings.ToUpper(kind[:3])+"00", x.managed)
	newProfile := "arn:aws:iam::" + accountA + ":instance-profile/" + x.newName
	oldProfile := "arn:aws:iam::" + accountA + ":instance-profile/" + x.name
	// observe checks each row (want per subject, in subject order).
	type want struct {
		state     string
		remaining int // -1: nil
	}
	observe := func(wantDep string, wants ...want) []models.IGAGovWorkloadMigration {
		t.Helper()
		o := l.observe(dep)
		ms := l.migrations(dep)
		for i, w := range wants {
			m := ms[i]
			rem := "nil"
			if m.RemainingOldRefs != nil {
				rem = fmt.Sprint(*m.RemainingOldRefs)
			}
			if m.State != w.state || (w.remaining >= 0 && (m.RemainingOldRefs == nil || *m.RemainingOldRefs != w.remaining)) ||
				(w.remaining < 0 && m.RemainingOldRefs != nil) || o.State != wantDep {
				t.Fatalf("row %s: want %s remaining %d dep %s; got %s (complete %v, remaining %s, evidence %s) dep %s %+v",
					m.SubjectARN, w.state, w.remaining, wantDep, m.State, m.EvidenceComplete, rem, m.Evidence, o.State, o.Class)
			}
		}
		return ms
	}
	switch kind {
	case "ecs":
		l.graphWorkload(x.td(5), "ecs_task", newIdentity)
		a, b := x.ecsF.services[x.svcARN], x.ecsF.services[x.svc("refund-replay")]
		rev5 := []ecstypes.Deployment{{Status: aws.String("PRIMARY"), TaskDefinition: aws.String(x.td(5)), RolloutState: ecstypes.DeploymentRolloutStateCompleted}}
		x.ecsF.mu.Lock()
		a.deps = rev5
		for i := 1; i <= 3; i++ {
			a.tasks[fmt.Sprintf("arn:aws:ecs:us-east-1:%s:task/payments/t%d", accountA, i)] = x.td(5)
		}
		x.ecsF.mu.Unlock()
		// refund-agent: t4 and refund-replay's b1 still on revision 4.
		observe("awaiting_apply", want{"moving", 2}, want{"moving", 2})
		// refund-agent fully on 5, refund-replay too, but refund-replay's
		// task listing is unreadable: each row has its own evidence.
		x.ecsF.mu.Lock()
		a.tasks["arn:aws:ecs:us-east-1:"+accountA+":task/payments/t4"] = x.td(5)
		b.deps = rev5
		b.tasks["arn:aws:ecs:us-east-1:"+accountA+":task/payments/b1"] = x.td(5)
		b.failList = true
		x.ecsF.mu.Unlock()
		ms := observe("awaiting_apply", want{"moved", 0}, want{"incomplete", -1})
		if ms[1].EvidenceComplete || !ms[0].EvidenceComplete {
			t.Fatalf("evidence %v / %v", ms[0].EvidenceComplete, ms[1].EvidenceComplete)
		}
		// An unreadable DescribeTasks page makes rows incomplete, not moved.
		x.ecsF.mu.Lock()
		b.failList, x.ecsF.failDesc = false, true
		x.ecsF.mu.Unlock()
		observe("awaiting_apply", want{"incomplete", -1}, want{"incomplete", -1})
		x.ecsF.mu.Lock()
		x.ecsF.failDesc = false
		x.ecsF.mu.Unlock()
		ms = observe("applied_unverified", want{"moved", 0}, want{"moved", 0})
		if !p3iStrHas(ms[0].ToWorkloadKeys, igagraph.Key("aws", x.td(5))) || !p3iStrHas(ms[0].FromWorkloadKeys, igagraph.Key("aws", x.td(4))) {
			t.Fatalf("revision link %v -> %v", ms[0].FromWorkloadKeys, ms[0].ToWorkloadKeys)
		}
		// refund-agent:4 and :5 stay two graph workloads.
		if n := l.count(`SELECT count(*) FROM iga_workload WHERE workspace_id = ? AND source_key IN (?, ?)`, l.ws,
			igagraph.Key("aws", x.td(4)), igagraph.Key("aws", x.td(5))); n != 2 {
			t.Fatalf("%d revision workloads", n)
		}
	case "lambda":
		x.lamF.latest = x.newARN
		x.lamF.roles = map[string]string{"1": x.src, "2": x.newARN, "3": x.src}
		x.lamF.alias, x.lamF.weights = "2", map[string]float64{"1": 0.1}
		l.relate(x.workload, newIdentity) // the publication moved executes_as
		observe("awaiting_apply", want{"moving", 1})
		x.lamF.weights = nil
		// P1-12 (c): an unreadable alias page makes the row incomplete.
		x.lamF.failAliases = true
		observe("awaiting_apply", want{"incomplete", -1})
		x.lamF.failAliases = false
		observe("applied_unverified", want{"moved", 0})
	case "asg":
		x.asgF.instances = []string{"i-1", "i-2"}
		x.asgF.ltProfile = newProfile
		x.asgF.assoc = map[string]string{"i-1": newProfile, "i-2": oldProfile}
		l.relate(x.workload, newIdentity)
		observe("awaiting_apply", want{"moving", 1})
		x.asgF.assoc["i-2"] = newProfile
		observe("applied_unverified", want{"moved", 0})
	}
	var ledger []string
	l.db.Raw(`SELECT kind || ' ' || native_arn || ' ' || state FROM iga_gov_artifact WHERE workspace_id = ? ORDER BY kind, native_arn`, l.ws).Scan(&ledger)
	// One binding row per control (051); the services are migration rows.
	wantLedger := []string{"dedicated_role " + x.newARN + " present", "workload_binding " + x.ref + " present"}
	if strings.Join(ledger, ";") != strings.Join(wantLedger, ";") {
		t.Fatalf("ledger %v, want %v", ledger, wantLedger)
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

// P1-12 (b): the split PR is rendered from the APPROVED documents. When the
// repository's source no longer says what was approved (here the source
// role's trust policy was edited after approval), nothing is rendered: the
// deployment is blocked (iac_form_changed: iac_source_differs), no PR.
func TestP3T317IsolationSourceDiffersBlocks(t *testing.T) {
	x := p3iIsoSetup(t, "asg")
	l := x.p3iLab
	l.compile(x.policy, 2)
	l.approveAll(x.policy, 2)
	dep := l.deploy(x.policy, 2, "split")
	edited := strings.Replace(fmt.Sprintf(p3iIsoTF, x.name, x.managed, x.fn), `Service = "ecs-tasks.amazonaws.com"`, `Service = "ec2.amazonaws.com"`, 1)
	l.gh.Seed(l.repo, "main", map[string]string{"iam/main.tf": edited})
	out := l.deliver(dep)
	if out.State != "blocked" || !strings.Contains(out.Reason, services.IaCReasonFormChanged+": "+iacpr.ReasonSourceDiffers) || l.gh.PRCount(l.repo) != 0 {
		t.Fatalf("source differs: %+v (PRs %d)", out, l.gh.PRCount(l.repo))
	}
}

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
