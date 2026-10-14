package awsdiscovery

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/authsec-ai/authsec/internal/awsdiscovery/rpfake"
)

// T3.03b / §11: the migration-evidence readers over fakes -- every page,
// every describe, and completeness that an unreadable page breaks.

type migFake struct {
	tasks          []string // RUNNING task ARNs of the service
	taskDef        map[string]string
	failDescribeAt int // DescribeTasks call number that fails (1-based), 0 = never
	describeCalls  int
}

func (f *migFake) ListClusters(_ context.Context, in *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:eu-west-1:" + rpAcct + ":cluster/payments"}}, nil
}
func (f *migFake) ListServices(_ context.Context, in *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return &ecs.ListServicesOutput{ServiceArns: []string{"arn:aws:ecs:eu-west-1:" + rpAcct + ":service/payments/refund-agent"}}, nil
}
func (f *migFake) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: []ecstypes.Service{{
		ServiceArn: aws.String(in.Services[0]), TaskDefinition: aws.String("arn:aws:ecs:eu-west-1:" + rpAcct + ":task-definition/refund-agent:5"),
		DesiredCount: 4, RunningCount: 4,
		Deployments: []ecstypes.Deployment{{Id: aws.String("d1"), Status: aws.String("PRIMARY"),
			TaskDefinition: aws.String("arn:aws:ecs:eu-west-1:" + rpAcct + ":task-definition/refund-agent:5"),
			RolloutState:   ecstypes.DeploymentRolloutStateCompleted, DesiredCount: 4, RunningCount: 4}},
	}}}, nil
}
func (f *migFake) ListTasks(_ context.Context, in *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	// Two tasks per page.
	from := 0
	if in.NextToken != nil {
		from, _ = strconv.Atoi(*in.NextToken)
	}
	to := from + 2
	var next *string
	if to < len(f.tasks) {
		next = aws.String(strconv.Itoa(to))
	} else {
		to = len(f.tasks)
	}
	return &ecs.ListTasksOutput{TaskArns: f.tasks[from:to], NextToken: next}, nil
}
func (f *migFake) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	f.describeCalls++
	if f.describeCalls == f.failDescribeAt {
		return nil, rpfake.APIError("AccessDeniedException")
	}
	out := &ecs.DescribeTasksOutput{}
	for _, t := range in.Tasks {
		out.Tasks = append(out.Tasks, ecstypes.Task{TaskArn: aws.String(t), TaskDefinitionArn: aws.String(f.taskDef[t]), LastStatus: aws.String("RUNNING")})
	}
	return out, nil
}

func TestP3RPCMigrationEvidenceECSService(t *testing.T) {
	f := &migFake{taskDef: map[string]string{}}
	for i := 0; i < 5; i++ {
		arn := "arn:aws:ecs:eu-west-1:" + rpAcct + ":task/payments/t" + strconv.Itoa(i)
		f.tasks = append(f.tasks, arn)
		f.taskDef[arn] = "arn:aws:ecs:eu-west-1:" + rpAcct + ":task-definition/refund-agent:5"
	}
	f.taskDef[f.tasks[4]] = "arn:aws:ecs:eu-west-1:" + rpAcct + ":task-definition/refund-agent:4"
	r := NewMigrationEvidenceReader("eu-west-1", MigrationClients{ECS: f})

	refs, ev := r.ListECSServices(context.Background())
	if len(refs) != 1 || !ev.Complete() {
		t.Fatalf("services %v complete=%v", refs, ev.Complete())
	}
	st, ev := r.ECSService(context.Background(), refs[0])
	if !st.Found || len(st.RunningTasks) != 5 || len(st.Deployments) != 1 || st.Deployments[0].RolloutState != "COMPLETED" {
		t.Fatalf("state = %+v", st)
	}
	if !ev.Complete() || ev.APIs["ecs:ListTasks"].Pages != 3 || ev.APIs["ecs:ListTasks"].Items != 5 {
		t.Fatalf("evidence = %s", ev.JSON())
	}
	if st.RunningTasks[4].TaskDefinitionARN == st.TaskDefinition {
		t.Fatal("the old-revision task must be reported as such")
	}

	// A33: an unreadable DescribeTasks page makes the evidence incomplete.
	f.describeCalls, f.failDescribeAt = 0, 1
	_, ev = r.ECSService(context.Background(), refs[0])
	if ev.Complete() || ev.APIs["ecs:DescribeTasks"].Failures != 1 {
		t.Fatalf("evidence after a failed describe = %s", ev.JSON())
	}
	var decoded map[string]any
	if err := json.Unmarshal(ev.JSON(), &decoded); err != nil || decoded["apis"] == nil {
		t.Fatalf("evidence JSON = %s", ev.JSON())
	}
}

type lambdaMigFake struct{}

const fnARN = "arn:aws:lambda:eu-west-1:" + rpAcct + ":function:refund"

func (lambdaMigFake) GetFunctionConfiguration(_ context.Context, in *lambda.GetFunctionConfigurationInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error) {
	role := "arn:aws:iam::" + rpAcct + ":role/new"
	if q := aws.ToString(in.Qualifier); q == "3" {
		role = "arn:aws:iam::" + rpAcct + ":role/shared"
	}
	return &lambda.GetFunctionConfigurationOutput{FunctionArn: aws.String(fnARN), Role: aws.String(role)}, nil
}
func (lambdaMigFake) ListAliases(_ context.Context, in *lambda.ListAliasesInput, _ ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error) {
	return &lambda.ListAliasesOutput{Aliases: []lambdatypes.AliasConfiguration{{Name: aws.String("live"), AliasArn: aws.String(fnARN + ":live"),
		FunctionVersion: aws.String("4"), RoutingConfig: &lambdatypes.AliasRoutingConfiguration{AdditionalVersionWeights: map[string]float64{"3": 0.1}}}}}, nil
}
func (lambdaMigFake) ListVersionsByFunction(_ context.Context, in *lambda.ListVersionsByFunctionInput, _ ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error) {
	return &lambda.ListVersionsByFunctionOutput{Versions: []lambdatypes.FunctionConfiguration{
		{Version: aws.String("$LATEST")}, {Version: aws.String("3"), Role: aws.String("arn:aws:iam::" + rpAcct + ":role/shared")},
		{Version: aws.String("4"), Role: aws.String("arn:aws:iam::" + rpAcct + ":role/new")}}}, nil
}
func (lambdaMigFake) ListEventSourceMappings(_ context.Context, in *lambda.ListEventSourceMappingsInput, _ ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error) {
	return &lambda.ListEventSourceMappingsOutput{EventSourceMappings: []lambdatypes.EventSourceMappingConfiguration{
		{UUID: aws.String("m1"), FunctionArn: aws.String(fnARN + ":3"), EventSourceArn: aws.String("arn:aws:sqs:eu-west-1:" + rpAcct + ":refunds")}}}, nil
}

func TestP3RPCMigrationEvidenceLambda(t *testing.T) {
	st, ev := NewMigrationEvidenceReader("eu-west-1", MigrationClients{Lambda: lambdaMigFake{}}).LambdaFunction(context.Background(), fnARN)
	if !ev.Complete() || st.LatestRole != "arn:aws:iam::"+rpAcct+":role/new" || len(st.Versions) != 2 || len(st.Aliases) != 1 ||
		st.Aliases[0].AdditionalWeight["3"] != 0.1 || len(st.EventSourceMappings) != 1 {
		t.Fatalf("state = %+v, evidence %s", st, ev.JSON())
	}
	// Versions 3 (weighted, mapped) and 4 (alias) are read per version.
	if ev.APIs["lambda:GetFunctionConfiguration"].Pages != 3 {
		t.Fatalf("GetFunctionConfiguration calls = %d, want $LATEST + 2 referenced versions", ev.APIs["lambda:GetFunctionConfiguration"].Pages)
	}
}

type asgFake struct{ failAssoc bool }

func (asgFake) DescribeAutoScalingGroups(_ context.Context, in *autoscaling.DescribeAutoScalingGroupsInput, _ ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	return &autoscaling.DescribeAutoScalingGroupsOutput{AutoScalingGroups: []astypes.AutoScalingGroup{{
		AutoScalingGroupName: aws.String("workers"), AutoScalingGroupARN: aws.String("arn:aws:autoscaling:eu-west-1:" + rpAcct + ":autoScalingGroup:x:autoScalingGroupName/workers"),
		LaunchTemplate: &astypes.LaunchTemplateSpecification{LaunchTemplateId: aws.String("lt-1"), Version: aws.String("7")},
		Instances: []astypes.Instance{{InstanceId: aws.String("i-1"), LifecycleState: astypes.LifecycleStateInService},
			{InstanceId: aws.String("i-2"), LifecycleState: astypes.LifecycleStateTerminating}},
	}}}, nil
}
func (f asgFake) DescribeLaunchTemplateVersions(_ context.Context, in *ec2.DescribeLaunchTemplateVersionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	return &ec2.DescribeLaunchTemplateVersionsOutput{LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{{
		LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{IamInstanceProfile: &ec2types.LaunchTemplateIamInstanceProfileSpecification{
			Arn: aws.String("arn:aws:iam::" + rpAcct + ":instance-profile/new")}}}}}, nil
}
func (f asgFake) DescribeIamInstanceProfileAssociations(_ context.Context, in *ec2.DescribeIamInstanceProfileAssociationsInput, _ ...func(*ec2.Options)) (*ec2.DescribeIamInstanceProfileAssociationsOutput, error) {
	if f.failAssoc {
		return nil, rpfake.APIError("UnauthorizedOperation")
	}
	return &ec2.DescribeIamInstanceProfileAssociationsOutput{IamInstanceProfileAssociations: []ec2types.IamInstanceProfileAssociation{{
		InstanceId: aws.String("i-1"), State: ec2types.IamInstanceProfileAssociationStateAssociated,
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String("arn:aws:iam::" + rpAcct + ":instance-profile/old")}}}}, nil
}

func TestP3RPCMigrationEvidenceAutoScaling(t *testing.T) {
	f := asgFake{}
	st, ev := NewMigrationEvidenceReader("eu-west-1", MigrationClients{AutoScaling: f, EC2: f}).AutoScalingGroup(context.Background(), "workers")
	if !ev.Complete() || !st.Found || st.LaunchTemplateProfileARN != "arn:aws:iam::"+rpAcct+":instance-profile/new" ||
		len(st.InServiceInstances) != 1 || len(st.Associations) != 1 || st.Associations[0].State != "associated" {
		t.Fatalf("state = %+v evidence %s", st, ev.JSON())
	}
	f.failAssoc = true
	_, ev = NewMigrationEvidenceReader("eu-west-1", MigrationClients{AutoScaling: f, EC2: f}).AutoScalingGroup(context.Background(), "workers")
	if ev.Complete() {
		t.Fatal("a refused association read must leave the evidence incomplete")
	}
	// No client is incomplete, never silently empty.
	if _, ev := NewMigrationEvidenceReader("eu-west-1", MigrationClients{}).LambdaFunction(context.Background(), fnARN); ev.Complete() {
		t.Fatal("missing client read as complete")
	}
}
