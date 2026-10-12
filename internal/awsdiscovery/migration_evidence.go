package awsdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

// Migration evidence for dedicated-identity isolation
// (SPEC-iga-phase3-policy.md §11 "Migration evidence, read by the discovery
// role"; T3.03b adds the reads, T3.17 decides `moved`).
//
// Read-only, used only by isolation plans at compile and verification time,
// and never projected into the graph. Each reader returns what it saw plus a
// MigrationEvidence that records, per API, the pages and items read and the
// failures -- the shape 051's iga_gov_workload_migration.evidence stores
// ("per API: pages read, items read, items failed") -- and is complete only
// when every list returned all its pages and every describe succeeded. The
// `moved` / `remaining_old_refs` decision is T3.17's: it needs the plan's
// source and new role, which these readers do not know.

// ECSMigrationAPI is the slice of ECS the migration evidence reads.
type ECSMigrationAPI interface {
	ListClusters(ctx context.Context, in *ecs.ListClustersInput, opts ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListServices(ctx context.Context, in *ecs.ListServicesInput, opts ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(ctx context.Context, in *ecs.DescribeServicesInput, opts ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTasks(ctx context.Context, in *ecs.ListTasksInput, opts ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, opts ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

// LambdaMigrationAPI is the slice of Lambda the migration evidence reads.
type LambdaMigrationAPI interface {
	GetFunctionConfiguration(ctx context.Context, in *lambda.GetFunctionConfigurationInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error)
	ListAliases(ctx context.Context, in *lambda.ListAliasesInput, opts ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error)
	ListVersionsByFunction(ctx context.Context, in *lambda.ListVersionsByFunctionInput, opts ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error)
	ListEventSourceMappings(ctx context.Context, in *lambda.ListEventSourceMappingsInput, opts ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error)
}

// AutoScalingAPI is the slice of EC2 Auto Scaling the migration evidence reads.
type AutoScalingAPI interface {
	DescribeAutoScalingGroups(ctx context.Context, in *autoscaling.DescribeAutoScalingGroupsInput, opts ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
}

// EC2MigrationAPI is the slice of EC2 the migration evidence reads.
type EC2MigrationAPI interface {
	DescribeLaunchTemplateVersions(ctx context.Context, in *ec2.DescribeLaunchTemplateVersionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
	DescribeIamInstanceProfileAssociations(ctx context.Context, in *ec2.DescribeIamInstanceProfileAssociationsInput, opts ...func(*ec2.Options)) (*ec2.DescribeIamInstanceProfileAssociationsOutput, error)
}

// MigrationClients are one region's migration-evidence clients.
type MigrationClients struct {
	ECS         ECSMigrationAPI
	Lambda      LambdaMigrationAPI
	AutoScaling AutoScalingAPI
	EC2         EC2MigrationAPI
}

// NewMigrationClients builds real clients from one region's config.
func NewMigrationClients(cfg aws.Config) MigrationClients {
	return MigrationClients{
		ECS: ecs.NewFromConfig(cfg), Lambda: lambda.NewFromConfig(cfg),
		AutoScaling: autoscaling.NewFromConfig(cfg), EC2: ec2.NewFromConfig(cfg),
	}
}

// APIStats is one API's share of a migration evidence read.
type APIStats struct {
	Pages    int      `json:"pages"`
	Items    int      `json:"items"`
	Failures int      `json:"failures"`
	Errors   []string `json:"errors,omitempty"` // "<code>" per failure, stable (no messages)
}

// MigrationEvidence is what one subject's read saw: per API, pages, items
// and failures, and the regions read.
type MigrationEvidence struct {
	APIs    map[string]*APIStats `json:"apis"`
	Regions []string             `json:"regions"`
}

func newMigrationEvidence(region string) *MigrationEvidence {
	return &MigrationEvidence{APIs: map[string]*APIStats{}, Regions: []string{region}}
}

func (e *MigrationEvidence) stat(api string) *APIStats {
	s := e.APIs[api]
	if s == nil {
		s = &APIStats{}
		e.APIs[api] = s
	}
	return s
}

func (e *MigrationEvidence) page(api string, items int) {
	s := e.stat(api)
	s.Pages++
	s.Items += items
}

func (e *MigrationEvidence) fail(api string, err error) {
	s := e.stat(api)
	s.Failures++
	s.Errors = append(s.Errors, codeOf(err))
}

// Complete is §11's evidence_complete: every list returned all its pages and
// every describe succeeded (and something was read at all).
func (e *MigrationEvidence) Complete() bool {
	if e == nil || len(e.APIs) == 0 {
		return false
	}
	for _, s := range e.APIs {
		if s.Failures > 0 {
			return false
		}
	}
	return true
}

// Merge adds another read's evidence (another region, another subject part).
func (e *MigrationEvidence) Merge(o *MigrationEvidence) {
	if o == nil {
		return
	}
	for api, s := range o.APIs {
		t := e.stat(api)
		t.Pages += s.Pages
		t.Items += s.Items
		t.Failures += s.Failures
		t.Errors = append(t.Errors, s.Errors...)
	}
	e.Regions = sortedUniqueStrings(append(e.Regions, o.Regions...))
}

// JSON is the evidence as iga_gov_workload_migration.evidence stores it.
func (e *MigrationEvidence) JSON() json.RawMessage {
	raw, err := json.Marshal(e)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// MigrationEvidenceReader reads one region's migration evidence.
type MigrationEvidenceReader struct {
	region string
	c      MigrationClients
}

// NewMigrationEvidenceReader builds a reader over one region's clients.
func NewMigrationEvidenceReader(region string, c MigrationClients) *MigrationEvidenceReader {
	return &MigrationEvidenceReader{region: region, c: c}
}

// errNoClient is recorded when a client is missing: evidence is incomplete,
// never silently empty.
var errNoClient = errors.New("no client")

// maxMigrationPages bounds one listing; hitting it is a failure.
const maxMigrationPages = 10000

// listAll pages one listing, counting pages and items; a repeated token or
// the page bound is a failure, never a loop.
func listAll(ev *MigrationEvidence, api string, next func(token *string) (items int, nextToken *string, err error)) bool {
	var token *string
	seen := map[string]bool{}
	for page := 0; page < maxMigrationPages; page++ {
		n, nt, err := next(token)
		if err != nil {
			ev.fail(api, err)
			return false
		}
		ev.page(api, n)
		t := aws.ToString(nt)
		if t == "" {
			return true
		}
		if seen[t] {
			ev.fail(api, errors.New("repeated page token"))
			return false
		}
		seen[t] = true
		token = aws.String(t)
	}
	ev.fail(api, errors.New("page bound reached"))
	return false
}

/* ----------------------------------- ECS ---------------------------------- */

// ECSServiceRef names one ECS service.
type ECSServiceRef struct {
	ClusterARN string `json:"cluster_arn"`
	ServiceARN string `json:"service_arn"`
}

// ECSDeployment is one deployment of a service, as DescribeServices reports it.
type ECSDeployment struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	TaskDefinition string `json:"task_definition"`
	RolloutState   string `json:"rollout_state"`
	DesiredCount   int32  `json:"desired_count"`
	RunningCount   int32  `json:"running_count"`
}

// ECSTask is one task, as DescribeTasks reports it.
type ECSTask struct {
	TaskARN           string `json:"task_arn"`
	TaskDefinitionARN string `json:"task_definition_arn"`
	LastStatus        string `json:"last_status"`
	Group             string `json:"group"`
}

// ECSServiceState is one service's §11 evidence: its deployments and every
// RUNNING task (all pages, every task described).
type ECSServiceState struct {
	ECSServiceRef
	Found          bool            `json:"found"`
	TaskDefinition string          `json:"task_definition"`
	DesiredCount   int32           `json:"desired_count"`
	RunningCount   int32           `json:"running_count"`
	Deployments    []ECSDeployment `json:"deployments"`
	RunningTasks   []ECSTask       `json:"running_tasks"`
}

// ListECSServices lists every service of every cluster in the region.
func (r *MigrationEvidenceReader) ListECSServices(ctx context.Context) ([]ECSServiceRef, *MigrationEvidence) {
	ev := newMigrationEvidence(r.region)
	if r.c.ECS == nil {
		ev.fail("ecs:ListClusters", errNoClient)
		return nil, ev
	}
	clusters := r.clusters(ctx, ev)
	var out []ECSServiceRef
	for _, cl := range clusters {
		listAll(ev, "ecs:ListServices", func(token *string) (int, *string, error) {
			o, err := r.c.ECS.ListServices(ctx, &ecs.ListServicesInput{Cluster: aws.String(cl), NextToken: token, MaxResults: aws.Int32(100)})
			if err != nil {
				return 0, nil, err
			}
			for _, s := range o.ServiceArns {
				out = append(out, ECSServiceRef{ClusterARN: cl, ServiceARN: s})
			}
			return len(o.ServiceArns), o.NextToken, nil
		})
	}
	return out, ev
}

func (r *MigrationEvidenceReader) clusters(ctx context.Context, ev *MigrationEvidence) []string {
	var out []string
	listAll(ev, "ecs:ListClusters", func(token *string) (int, *string, error) {
		o, err := r.c.ECS.ListClusters(ctx, &ecs.ListClustersInput{NextToken: token, MaxResults: aws.Int32(100)})
		if err != nil {
			return 0, nil, err
		}
		out = append(out, o.ClusterArns...)
		return len(o.ClusterArns), o.NextToken, nil
	})
	return out
}

// ECSService reads one service's deployments and every RUNNING task of it.
func (r *MigrationEvidenceReader) ECSService(ctx context.Context, ref ECSServiceRef) (ECSServiceState, *MigrationEvidence) {
	ev := newMigrationEvidence(r.region)
	st := ECSServiceState{ECSServiceRef: ref}
	if r.c.ECS == nil {
		ev.fail("ecs:DescribeServices", errNoClient)
		return st, ev
	}
	o, err := r.c.ECS.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(ref.ClusterARN), Services: []string{ref.ServiceARN}})
	if err != nil {
		ev.fail("ecs:DescribeServices", err)
		return st, ev
	}
	ev.page("ecs:DescribeServices", len(o.Services))
	for _, f := range o.Failures {
		// MISSING is an answer (the service is gone); anything else is not.
		if aws.ToString(f.Reason) != "MISSING" {
			ev.fail("ecs:DescribeServices", errors.New(aws.ToString(f.Reason)))
		}
	}
	for _, s := range o.Services {
		if aws.ToString(s.ServiceArn) != ref.ServiceARN {
			continue
		}
		st.Found = true
		st.TaskDefinition = aws.ToString(s.TaskDefinition)
		st.DesiredCount, st.RunningCount = s.DesiredCount, s.RunningCount
		for _, d := range s.Deployments {
			st.Deployments = append(st.Deployments, ECSDeployment{
				ID: aws.ToString(d.Id), Status: aws.ToString(d.Status), TaskDefinition: aws.ToString(d.TaskDefinition),
				RolloutState: string(d.RolloutState), DesiredCount: d.DesiredCount, RunningCount: d.RunningCount,
			})
		}
	}
	if !st.Found {
		return st, ev
	}
	name := ref.ServiceARN
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	st.RunningTasks = r.runningTasks(ctx, ev, ref.ClusterARN, &ecs.ListTasksInput{ServiceName: aws.String(name)})
	return st, ev
}

// ECSFamilyRunningTasks reads every RUNNING task of a task-definition family
// in every cluster of the region: §11 counts running tasks of the family on a
// source-role revision, and lists standalone or scheduled tasks as unanalysed.
func (r *MigrationEvidenceReader) ECSFamilyRunningTasks(ctx context.Context, family string) ([]ECSTask, *MigrationEvidence) {
	ev := newMigrationEvidence(r.region)
	if r.c.ECS == nil {
		ev.fail("ecs:ListClusters", errNoClient)
		return nil, ev
	}
	var out []ECSTask
	for _, cl := range r.clusters(ctx, ev) {
		out = append(out, r.runningTasks(ctx, ev, cl, &ecs.ListTasksInput{Family: aws.String(family)})...)
	}
	return out, ev
}

func (r *MigrationEvidenceReader) runningTasks(ctx context.Context, ev *MigrationEvidence, cluster string, base *ecs.ListTasksInput) []ECSTask {
	var arns []string
	listAll(ev, "ecs:ListTasks", func(token *string) (int, *string, error) {
		in := *base
		in.Cluster, in.NextToken, in.MaxResults = aws.String(cluster), token, aws.Int32(100)
		in.DesiredStatus = ecstypes.DesiredStatusRunning
		o, err := r.c.ECS.ListTasks(ctx, &in)
		if err != nil {
			return 0, nil, err
		}
		arns = append(arns, o.TaskArns...)
		return len(o.TaskArns), o.NextToken, nil
	})
	var out []ECSTask
	for i := 0; i < len(arns); i += 100 {
		end := i + 100
		if end > len(arns) {
			end = len(arns)
		}
		o, err := r.c.ECS.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: arns[i:end]})
		if err != nil {
			ev.fail("ecs:DescribeTasks", err)
			continue
		}
		ev.page("ecs:DescribeTasks", len(o.Tasks))
		for _, f := range o.Failures {
			if aws.ToString(f.Reason) != "MISSING" { // a task that stopped since the list is an answer
				ev.fail("ecs:DescribeTasks", errors.New(aws.ToString(f.Reason)))
			}
		}
		for _, t := range o.Tasks {
			out = append(out, ECSTask{TaskARN: aws.ToString(t.TaskArn), TaskDefinitionARN: aws.ToString(t.TaskDefinitionArn),
				LastStatus: aws.ToString(t.LastStatus), Group: aws.ToString(t.Group)})
		}
	}
	return out
}

/* ---------------------------------- Lambda -------------------------------- */

// LambdaVersionState is one published version and the role it runs as.
type LambdaVersionState struct {
	Version string `json:"version"`
	ARN     string `json:"arn"`
	Role    string `json:"role"`
}

// LambdaAliasState is one alias: its version and weighted routing.
type LambdaAliasState struct {
	Name             string             `json:"name"`
	ARN              string             `json:"arn"`
	FunctionVersion  string             `json:"function_version"`
	AdditionalWeight map[string]float64 `json:"additional_version_weights,omitempty"`
}

// LambdaEventSourceMapping is one mapping and the (possibly qualified)
// function ARN it targets.
type LambdaEventSourceMapping struct {
	UUID           string `json:"uuid"`
	FunctionARN    string `json:"function_arn"`
	EventSourceARN string `json:"event_source_arn"`
	State          string `json:"state"`
}

// LambdaFunctionState is one function's §11 evidence.
type LambdaFunctionState struct {
	FunctionARN         string                     `json:"function_arn"`
	LatestRole          string                     `json:"latest_role"`
	Versions            []LambdaVersionState       `json:"versions"`
	Aliases             []LambdaAliasState         `json:"aliases"`
	EventSourceMappings []LambdaEventSourceMapping `json:"event_source_mappings"`
}

// LambdaFunction reads $LATEST's role, every published version and its role,
// every alias with its weighted routing, and every event-source mapping. The
// role of each version an alias or a mapping points at is read with
// GetFunctionConfiguration on that version (§11 "per version"); the rest come
// from the version listing.
func (r *MigrationEvidenceReader) LambdaFunction(ctx context.Context, function string) (LambdaFunctionState, *MigrationEvidence) {
	ev := newMigrationEvidence(r.region)
	st := LambdaFunctionState{}
	api := r.c.Lambda
	if api == nil {
		ev.fail("lambda:GetFunctionConfiguration", errNoClient)
		return st, ev
	}
	latest, err := api.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(function)})
	if err != nil {
		ev.fail("lambda:GetFunctionConfiguration", err)
	} else {
		ev.page("lambda:GetFunctionConfiguration", 1)
		st.FunctionARN, st.LatestRole = aws.ToString(latest.FunctionArn), aws.ToString(latest.Role)
	}
	roles := map[string]string{}
	listAll(ev, "lambda:ListVersionsByFunction", func(token *string) (int, *string, error) {
		o, err := api.ListVersionsByFunction(ctx, &lambda.ListVersionsByFunctionInput{FunctionName: aws.String(function), Marker: token, MaxItems: aws.Int32(50)})
		if err != nil {
			return 0, nil, err
		}
		for _, v := range o.Versions {
			ver := aws.ToString(v.Version)
			if ver == "$LATEST" {
				continue
			}
			roles[ver] = aws.ToString(v.Role)
			st.Versions = append(st.Versions, LambdaVersionState{Version: ver, ARN: aws.ToString(v.FunctionArn), Role: aws.ToString(v.Role)})
		}
		return len(o.Versions), o.NextMarker, nil
	})
	listAll(ev, "lambda:ListAliases", func(token *string) (int, *string, error) {
		o, err := api.ListAliases(ctx, &lambda.ListAliasesInput{FunctionName: aws.String(function), Marker: token, MaxItems: aws.Int32(50)})
		if err != nil {
			return 0, nil, err
		}
		for _, a := range o.Aliases {
			as := LambdaAliasState{Name: aws.ToString(a.Name), ARN: aws.ToString(a.AliasArn), FunctionVersion: aws.ToString(a.FunctionVersion)}
			if a.RoutingConfig != nil && len(a.RoutingConfig.AdditionalVersionWeights) > 0 {
				as.AdditionalWeight = a.RoutingConfig.AdditionalVersionWeights
			}
			st.Aliases = append(st.Aliases, as)
		}
		return len(o.Aliases), o.NextMarker, nil
	})
	listAll(ev, "lambda:ListEventSourceMappings", func(token *string) (int, *string, error) {
		o, err := api.ListEventSourceMappings(ctx, &lambda.ListEventSourceMappingsInput{FunctionName: aws.String(function), Marker: token, MaxItems: aws.Int32(100)})
		if err != nil {
			return 0, nil, err
		}
		for _, m := range o.EventSourceMappings {
			st.EventSourceMappings = append(st.EventSourceMappings, LambdaEventSourceMapping{
				UUID: aws.ToString(m.UUID), FunctionARN: aws.ToString(m.FunctionArn),
				EventSourceARN: aws.ToString(m.EventSourceArn), State: aws.ToString(m.State)})
		}
		return len(o.EventSourceMappings), o.NextMarker, nil
	})
	// Every version a live reference points at, read authoritatively.
	referenced := map[string]bool{}
	for _, a := range st.Aliases {
		referenced[a.FunctionVersion] = true
		for v := range a.AdditionalWeight {
			referenced[v] = true
		}
	}
	for _, m := range st.EventSourceMappings {
		if q := qualifierOf(m.FunctionARN); q != "" {
			referenced[q] = true
		}
	}
	vs := make([]string, 0, len(referenced))
	for v := range referenced {
		if v != "" && v != "$LATEST" {
			vs = append(vs, v)
		}
	}
	sort.Strings(vs)
	for _, v := range vs {
		o, err := api.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(function), Qualifier: aws.String(v)})
		if err != nil {
			ev.fail("lambda:GetFunctionConfiguration", err)
			continue
		}
		ev.page("lambda:GetFunctionConfiguration", 1)
		role := aws.ToString(o.Role)
		if _, ok := roles[v]; !ok {
			st.Versions = append(st.Versions, LambdaVersionState{Version: v, ARN: aws.ToString(o.FunctionArn), Role: role})
		}
		for i := range st.Versions {
			if st.Versions[i].Version == v {
				st.Versions[i].Role = role
			}
		}
	}
	sort.Slice(st.Versions, func(i, j int) bool { return st.Versions[i].Version < st.Versions[j].Version })
	return st, ev
}

// qualifierOf returns a qualified function ARN's qualifier
// (arn:aws:lambda:r:acct:function:name:qualifier), "" when unqualified.
func qualifierOf(functionARN string) string {
	parts := strings.Split(functionARN, ":")
	if len(parts) == 8 {
		return parts[7]
	}
	return ""
}

/* ------------------------------- EC2 / ASG -------------------------------- */

// InstanceProfileAssociation is one instance's profile association.
type InstanceProfileAssociation struct {
	InstanceID string `json:"instance_id"`
	ProfileARN string `json:"profile_arn"`
	State      string `json:"state"`
}

// AutoScalingGroupState is one group's §11 evidence.
type AutoScalingGroupState struct {
	Name                     string                       `json:"name"`
	ARN                      string                       `json:"arn"`
	Found                    bool                         `json:"found"`
	LaunchTemplateID         string                       `json:"launch_template_id,omitempty"`
	LaunchTemplateName       string                       `json:"launch_template_name,omitempty"`
	LaunchTemplateVersion    string                       `json:"launch_template_version,omitempty"`
	LaunchConfigurationName  string                       `json:"launch_configuration_name,omitempty"`
	LaunchTemplateProfileARN string                       `json:"launch_template_profile_arn,omitempty"`
	LaunchTemplateProfile    string                       `json:"launch_template_profile_name,omitempty"`
	InServiceInstances       []string                     `json:"in_service_instances"`
	Associations             []InstanceProfileAssociation `json:"associations"`
}

// AutoScalingGroup reads a group, the instance profile its launch template
// version names, and the profile association of every InService instance.
func (r *MigrationEvidenceReader) AutoScalingGroup(ctx context.Context, name string) (AutoScalingGroupState, *MigrationEvidence) {
	ev := newMigrationEvidence(r.region)
	st := AutoScalingGroupState{Name: name}
	if r.c.AutoScaling == nil {
		ev.fail("autoscaling:DescribeAutoScalingGroups", errNoClient)
		return st, ev
	}
	listAll(ev, "autoscaling:DescribeAutoScalingGroups", func(token *string) (int, *string, error) {
		o, err := r.c.AutoScaling.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
			AutoScalingGroupNames: []string{name}, NextToken: token})
		if err != nil {
			return 0, nil, err
		}
		for _, g := range o.AutoScalingGroups {
			if aws.ToString(g.AutoScalingGroupName) != name {
				continue
			}
			st.Found, st.ARN = true, aws.ToString(g.AutoScalingGroupARN)
			st.LaunchConfigurationName = aws.ToString(g.LaunchConfigurationName)
			lt := g.LaunchTemplate
			if lt == nil && g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil {
				lt = g.MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification
			}
			if lt != nil {
				st.LaunchTemplateID, st.LaunchTemplateName = aws.ToString(lt.LaunchTemplateId), aws.ToString(lt.LaunchTemplateName)
				st.LaunchTemplateVersion = aws.ToString(lt.Version)
			}
			for _, inst := range g.Instances {
				if string(inst.LifecycleState) == "InService" {
					st.InServiceInstances = append(st.InServiceInstances, aws.ToString(inst.InstanceId))
				}
			}
		}
		return len(o.AutoScalingGroups), o.NextToken, nil
	})
	sort.Strings(st.InServiceInstances)
	if !st.Found {
		return st, ev
	}
	if st.LaunchTemplateID != "" || st.LaunchTemplateName != "" {
		r.launchTemplateProfile(ctx, ev, &st)
	}
	assocs, aev := r.InstanceAssociations(ctx, st.InServiceInstances)
	st.Associations = assocs
	ev.Merge(aev)
	return st, ev
}

func (r *MigrationEvidenceReader) launchTemplateProfile(ctx context.Context, ev *MigrationEvidence, st *AutoScalingGroupState) {
	if r.c.EC2 == nil {
		ev.fail("ec2:DescribeLaunchTemplateVersions", errNoClient)
		return
	}
	version := st.LaunchTemplateVersion
	if version == "" {
		version = "$Default"
	}
	in := &ec2.DescribeLaunchTemplateVersionsInput{Versions: []string{version}}
	if st.LaunchTemplateID != "" {
		in.LaunchTemplateId = aws.String(st.LaunchTemplateID)
	} else {
		in.LaunchTemplateName = aws.String(st.LaunchTemplateName)
	}
	o, err := r.c.EC2.DescribeLaunchTemplateVersions(ctx, in)
	if err != nil {
		ev.fail("ec2:DescribeLaunchTemplateVersions", err)
		return
	}
	ev.page("ec2:DescribeLaunchTemplateVersions", len(o.LaunchTemplateVersions))
	for _, v := range o.LaunchTemplateVersions {
		if v.LaunchTemplateData != nil && v.LaunchTemplateData.IamInstanceProfile != nil {
			st.LaunchTemplateProfileARN = aws.ToString(v.LaunchTemplateData.IamInstanceProfile.Arn)
			st.LaunchTemplateProfile = aws.ToString(v.LaunchTemplateData.IamInstanceProfile.Name)
		}
	}
}

// InstanceAssociations reads the profile associations of the named
// instances (all pages). An instance with no association is absent.
func (r *MigrationEvidenceReader) InstanceAssociations(ctx context.Context, instanceIDs []string) ([]InstanceProfileAssociation, *MigrationEvidence) {
	ev := newMigrationEvidence(r.region)
	if len(instanceIDs) == 0 {
		ev.page("ec2:DescribeIamInstanceProfileAssociations", 0)
		return nil, ev
	}
	if r.c.EC2 == nil {
		ev.fail("ec2:DescribeIamInstanceProfileAssociations", errNoClient)
		return nil, ev
	}
	var out []InstanceProfileAssociation
	ids := sortedUniqueStrings(instanceIDs)
	for i := 0; i < len(ids); i += 200 {
		end := i + 200
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]
		listAll(ev, "ec2:DescribeIamInstanceProfileAssociations", func(token *string) (int, *string, error) {
			o, err := r.c.EC2.DescribeIamInstanceProfileAssociations(ctx, &ec2.DescribeIamInstanceProfileAssociationsInput{
				Filters:   []ec2types.Filter{{Name: aws.String("instance-id"), Values: chunk}},
				NextToken: token, MaxResults: aws.Int32(1000)})
			if err != nil {
				return 0, nil, err
			}
			for _, a := range o.IamInstanceProfileAssociations {
				p := ""
				if a.IamInstanceProfile != nil {
					p = aws.ToString(a.IamInstanceProfile.Arn)
				}
				out = append(out, InstanceProfileAssociation{InstanceID: aws.ToString(a.InstanceId), ProfileARN: p, State: string(a.State)})
			}
			return len(o.IamInstanceProfileAssociations), o.NextToken, nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out, ev
}
