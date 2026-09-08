package awsdiscovery

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// The workload read surface: the compute that runs AS an IAM role.
//
// Tickets [1] and [2] answer "which identities exist and what may they do".
// This file answers the question that makes those answers actionable for an
// agent-governance product: WHAT actually runs as that role. A role with
// dangerous permissions and no compute attached is a different finding from the
// same role backing a production Lambda.
//
// Every service here is REGIONAL. One reader talks to one region; the caller
// loops over the connector's selected regions.
//
// NO SECRET VALUES. Lambda returns environment variable VALUES with the
// function, and AWS offers no action that returns the names alone. This file
// keeps the NAMES and discards the values at the point of parsing -- see
// lambdaEnvVarNames. That is a code obligation because IAM cannot express it,
// and it is the one guarantee in this package not enforced by the role.

// LambdaAPI is the slice of the Lambda client this package uses.
type LambdaAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, opts ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

// ECSAPI is the slice of the ECS client this package uses.
type ECSAPI interface {
	ListTaskDefinitions(ctx context.Context, in *ecs.ListTaskDefinitionsInput, opts ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(ctx context.Context, in *ecs.DescribeTaskDefinitionInput, opts ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// EC2API is the slice of the EC2 client this package uses.
type EC2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// InstanceProfileAPI resolves an EC2 instance profile to the role inside it.
// Separate from IAMAPI because it is needed only by this file, and adding it to
// that interface would force every IAM fake to grow a method it never uses.
type InstanceProfileAPI interface {
	GetInstanceProfile(ctx context.Context, in *iam.GetInstanceProfileInput, opts ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error)
}

// NewLambdaClient builds a real Lambda client.
func NewLambdaClient(cfg aws.Config) LambdaAPI { return lambda.NewFromConfig(cfg) }

// NewECSClient builds a real ECS client.
func NewECSClient(cfg aws.Config) ECSAPI { return ecs.NewFromConfig(cfg) }

// NewEC2Client builds a real EC2 client.
func NewEC2Client(cfg aws.Config) EC2API { return ec2.NewFromConfig(cfg) }

// NewInstanceProfileClient builds a real IAM client for the instance-profile
// hop. IAM is global, so this one is not region-bound even though its caller is.
func NewInstanceProfileClient(cfg aws.Config) InstanceProfileAPI { return iam.NewFromConfig(cfg) }

// Workload is one piece of compute, normalised across the four services.
type Workload struct {
	// RuntimeKind is one of the models.Workload* values. Declared as a string
	// here because this package must not import models.
	RuntimeKind string
	// NativeID is the provider's identifier: a function ARN, a task definition
	// ARN, an instance id.
	NativeID string
	Name     string
	// RoleARN is the role the compute ACTS AS. For ECS this is deliberately the
	// task role, never the execution role.
	RoleARN string
	// ExecutionRoleARN is ECS's executionRoleArn -- what ECS itself uses to pull
	// images and write logs. Recorded for the reader who needs it, never
	// mistaken for RoleARN.
	ExecutionRoleARN string
	// InstanceProfileARN is EC2 only, the wrapper GetInstanceProfile resolved.
	InstanceProfileARN string
	// EnvVarNames are Lambda environment variable NAMES. Never values.
	EnvVarNames []string
	// FoundationModel is Bedrock only: the model the agent invokes. Part of the
	// workload's identity in a way a Lambda's runtime version is not -- it is
	// what the agent thinks with.
	FoundationModel string
	Status          string
}

// WorkloadReader reads one region's compute.
//
// Each client is optional: a nil client means that surface is skipped rather
// than failing the whole read, so a deployment or a role that covers Lambda but
// not EC2 still returns the Lambda functions.
type WorkloadReader struct {
	lambdaAPI   LambdaAPI
	ecsAPI      ECSAPI
	ec2API      EC2API
	profileAPI  InstanceProfileAPI
	profileSeen map[string]string
}

// NewWorkloadReader constructs a reader over the given clients.
func NewWorkloadReader(l LambdaAPI, e ECSAPI, c EC2API, p InstanceProfileAPI) *WorkloadReader {
	return &WorkloadReader{
		lambdaAPI: l, ecsAPI: e, ec2API: c, profileAPI: p,
		profileSeen: map[string]string{},
	}
}

// LambdaFunctions lists every function in the region.
//
// ListFunctions returns the full configuration per function, including the
// execution role, so there is no per-function detail call -- the one place in
// this package where the list response is enough.
func (r *WorkloadReader) LambdaFunctions(ctx context.Context) ([]Workload, error) {
	if r.lambdaAPI == nil {
		return nil, nil
	}
	var out []Workload
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: lambda functions", errTooManyPages)
		}
		resp, err := r.lambdaAPI.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return out, classify(err)
		}
		for _, fn := range resp.Functions {
			out = append(out, Workload{
				RuntimeKind: "lambda_function",
				NativeID:    aws.ToString(fn.FunctionArn),
				Name:        aws.ToString(fn.FunctionName),
				RoleARN:     aws.ToString(fn.Role),
				EnvVarNames: lambdaEnvVarNames(fn.Environment),
				Status:      string(fn.State),
			})
		}
		if resp.NextMarker == nil || *resp.NextMarker == "" {
			return out, nil
		}
		marker = resp.NextMarker
	}
}

// lambdaEnvVarNames extracts environment variable NAMES and discards every
// value.
//
// This is the "one thing IAM cannot enforce" from the AWS plan: there is no IAM
// action granting the names without the values, so the guarantee has to live
// here. Only map keys are read -- the values are never copied out of the SDK's
// response, and no struct in this package or in the schema has a field one
// could be written to.
//
// Sorted, so a re-scan of an unchanged function produces an identical attrs
// blob instead of a spurious update from Go's randomised map order.
func lambdaEnvVarNames(env *lambdatypes.EnvironmentResponse) []string {
	if env == nil || len(env.Variables) == 0 {
		return nil
	}
	names := make([]string, 0, len(env.Variables))
	for name := range env.Variables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ECSTaskDefinitions lists every ACTIVE task definition in the region and
// resolves each one's roles.
//
// The trap this function exists to avoid: a task definition names TWO roles.
// taskRoleArn is what the application in the container acts as -- the agent.
// executionRoleArn is what ECS itself uses to pull the image and write logs.
// Attributing a container's permissions to the execution role would report
// permissions the application never had, so RoleARN is always the task role.
func (r *WorkloadReader) ECSTaskDefinitions(ctx context.Context) ([]Workload, error) {
	if r.ecsAPI == nil {
		return nil, nil
	}
	var out []Workload
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: ecs task definitions", errTooManyPages)
		}
		resp, err := r.ecsAPI.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
			Status: "ACTIVE", NextToken: next,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, arn := range resp.TaskDefinitionArns {
			w, ok := r.taskDefinitionDetail(ctx, arn)
			if !ok {
				continue
			}
			out = append(out, w)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// taskDefinitionDetail resolves the two roles, which the list response omits.
func (r *WorkloadReader) taskDefinitionDetail(ctx context.Context, arn string) (Workload, bool) {
	detail, err := r.ecsAPI.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(arn),
	})
	if err != nil || detail.TaskDefinition == nil {
		return Workload{}, false
	}
	td := detail.TaskDefinition
	return Workload{
		RuntimeKind: "ecs_task_definition",
		NativeID:    aws.ToString(td.TaskDefinitionArn),
		Name:        aws.ToString(td.Family),
		// The task role, never the execution role. See this function's comment.
		RoleARN:          aws.ToString(td.TaskRoleArn),
		ExecutionRoleARN: aws.ToString(td.ExecutionRoleArn),
		Status:           string(td.Status),
	}, true
}

// EC2Instances lists every instance in the region and resolves the role behind
// each instance profile.
//
// The trap this function exists to avoid: EC2 does not name a role. It names an
// INSTANCE PROFILE -- a thin wrapper holding exactly one role -- so the role
// requires a second call to iam:GetInstanceProfile. EC2 is the only workload
// with this hop, and results are cached because one profile commonly backs an
// entire fleet.
func (r *WorkloadReader) EC2Instances(ctx context.Context) ([]Workload, error) {
	if r.ec2API == nil {
		return nil, nil
	}
	var out []Workload
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: ec2 instances", errTooManyPages)
		}
		resp, err := r.ec2API.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: next})
		if err != nil {
			return out, classify(err)
		}
		for _, reservation := range resp.Reservations {
			for _, inst := range reservation.Instances {
				w := Workload{
					RuntimeKind: "ec2_instance",
					NativeID:    aws.ToString(inst.InstanceId),
					Name:        ec2NameTag(inst.Tags),
					Status:      string(inst.State.Name),
				}
				if inst.IamInstanceProfile != nil {
					w.InstanceProfileARN = aws.ToString(inst.IamInstanceProfile.Arn)
					w.RoleARN = r.roleForInstanceProfile(ctx, w.InstanceProfileARN)
				}
				out = append(out, w)
			}
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// roleForInstanceProfile resolves a profile ARN to the role it holds, caching
// the answer. Returns "" when it cannot be resolved: an instance whose profile
// is unreadable is still a real instance, and recording it unattributed is
// better than dropping it.
func (r *WorkloadReader) roleForInstanceProfile(ctx context.Context, profileARN string) string {
	if profileARN == "" || r.profileAPI == nil {
		return ""
	}
	if role, ok := r.profileSeen[profileARN]; ok {
		return role
	}
	name := afterLastSlash(profileARN)
	if name == "" {
		return ""
	}
	resp, err := r.profileAPI.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(name),
	})
	role := ""
	// An instance profile holds exactly one role in practice; AWS models it as
	// a list and has never allowed a second.
	if err == nil && resp.InstanceProfile != nil && len(resp.InstanceProfile.Roles) > 0 {
		role = aws.ToString(resp.InstanceProfile.Roles[0].Arn)
	}
	r.profileSeen[profileARN] = role
	return role
}

// ec2NameTag returns the instance's Name tag, which is where operators put the
// human label. EC2 has no name field of its own.
func ec2NameTag(tags []ec2types.Tag) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// afterLastSlash returns the trailing segment of an ARN path, which for an
// instance profile ARN is the profile name GetInstanceProfile expects.
func afterLastSlash(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}
