package awsenforce

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Agent containment on the enforcement session (SPEC-agent-runtime-
// visibility.md §5.8, §10 Q4). Identity- and model-level containment are
// template v2 as it is: an AuthSec policy under /authsec/ created
// (ManageAuthSecPolicies) and attached to a role (AttachOnlyAuthSecPolicies).
// Workload-level containment and every IAM-user containment need the
// enforcement stack's opt-in parameter EnableWorkloadContainment (template
// v2, no new template file), which grants:
//
//	lambda:GetFunctionConcurrency, PutFunctionConcurrency, DeleteFunctionConcurrency
//	ecs:DescribeServices, ecs:UpdateService
//	application-autoscaling:DescribeScalableTargets, RegisterScalableTarget
//	iam:ListAccessKeys, iam:UpdateAccessKey
//	iam:AttachUserPolicy, iam:DetachUserPolicy (only an /authsec/ policy ARN)
//
// each denied on resources tagged authsec:protected=true (RegisterScalableTarget
// is limited to ECS desired-count targets in the account). The service
// reference lists aws:ResourceTag on the Lambda function, ECS service,
// scalable target and IAM user resources; that each service enforces it on
// these calls is UNVERIFIED (lab). Application Auto Scaling reads the scalable
// target's own tags, not the ECS service's, so AuthSec also refuses a
// protected service or function itself in the preview (agentcontain.Protected).
//
// The capability workload_containment is proven by the self-test like
// split_role_lifecycle proves EnableLambdaSplit: calls against objects that
// do not exist, so nothing is changed. A permitted call answers "not found";
// a stack without the parameter answers AccessDenied. RegisterScalableTarget
// is not probed (on a missing service its validation may run before
// authorisation, and a first registration needs a service-linked role); the
// first workload containment of an ECS service proves it, as the first
// direct split proves update_function_role.

// CapWorkloadContainment is the template v2 capability of the parameter.
const CapWorkloadContainment = "workload_containment"

// FeatureWorkloadContainment is the feature RequireEnforcementV2 checks for
// workload-level containment and IAM-user containment.
const FeatureWorkloadContainment = "workload_containment"

// ECSServiceInfo is DescribeServices' answer for one service.
type ECSServiceInfo struct {
	ClusterARN     string
	ServiceARN     string
	TaskDefinition string
	DesiredCount   int32
	RunningCount   int32
}

// ScalableTargetInfo is an ECS service's scalable target.
type ScalableTargetInfo struct {
	MinCapacity, MaxCapacity                  int32
	DynamicIn, DynamicOut, ScheduledSuspended bool
}

// AccessKeyInfo is one access key of an IAM user (ListAccessKeys).
type AccessKeyInfo struct {
	ID     string
	Active bool
}

// WorkloadContainer is the enforcement session's containment calls behind
// EnableWorkloadContainment. Whether AWS ALLOWS them is a property of the
// stack, proven by the self-test (CapWorkloadContainment). A missing object
// is an error whose ErrorCode is a not-found code (IsNotFound); a missing
// ECS service or scalable target is (nil, nil) from the Describe calls.
type WorkloadContainer interface {
	GetFunctionConcurrency(ctx context.Context, functionARN string) (*int32, error)
	PutFunctionConcurrency(ctx context.Context, functionARN string, n int32) error
	DeleteFunctionConcurrency(ctx context.Context, functionARN string) error
	DescribeECSService(ctx context.Context, clusterARN, serviceARN string) (*ECSServiceInfo, error)
	UpdateECSServiceDesiredCount(ctx context.Context, clusterARN, serviceARN string, n int32) error
	DescribeECSScalableTarget(ctx context.Context, region, resourceID string) (*ScalableTargetInfo, error)
	SetECSScalingSuspended(ctx context.Context, region, resourceID string, dynamicIn, dynamicOut, scheduled bool) error
	AttachUserPolicy(ctx context.Context, userName, policyARN string) error
	DetachUserPolicy(ctx context.Context, userName, policyARN string) error
	ListAccessKeys(ctx context.Context, userName string) ([]AccessKeyInfo, error)
	UpdateAccessKey(ctx context.Context, userName, keyID string, active bool) error
}

// AsWorkloadContainer returns c as a WorkloadContainer when its
// implementation has the calls (the live enforcement client does).
func AsWorkloadContainer(c IAM) (WorkloadContainer, bool) {
	w, ok := c.(WorkloadContainer)
	return w, ok
}

// notFoundCodes are the answers of a permitted call on an object that does
// not exist.
var notFoundCodes = map[string]bool{
	"NoSuchEntity": true, "ResourceNotFoundException": true, "ClusterNotFoundException": true,
	"ServiceNotFoundException": true, "ObjectNotFoundException": true,
}

// IsNotFound reports a not-found answer of any of the containment services.
func IsNotFound(err error) bool { return notFoundCodes[ErrorCode(err)] }

// SelfTestAbsentName names the objects the workload_containment probe calls
// against: they never exist (AuthSec creates nothing by that name).
func SelfTestAbsentName(runID string) string { return "AuthSecSelfTestAbsent-" + runID }

// workloadContainmentProbe is the CapWorkloadContainment probe (see the file
// comment). The result is the first sub-probe that is not ok.
func workloadContainmentProbe(ctx context.Context, c IAM, in SelfTestInput, runID string, at func() time.Time) CapabilityResult {
	wc, ok := AsWorkloadContainer(c)
	if !ok {
		return untested(at(), "not run: the enforcement client has no workload containment operations")
	}
	partition := in.Partition
	if partition == "" {
		partition = "aws"
	}
	region := in.Region
	if region == "" {
		region = "us-east-1"
	}
	name := SelfTestAbsentName(runID)
	fn := "arn:" + partition + ":lambda:" + region + ":" + in.AccountID + ":function:" + name
	cluster := "arn:" + partition + ":ecs:" + region + ":" + in.AccountID + ":cluster/" + name
	service := "arn:" + partition + ":ecs:" + region + ":" + in.AccountID + ":service/" + name + "/" + name
	policy := "arn:" + partition + ":iam::" + in.AccountID + ":policy" + SelfTestPolicyPath + name
	// Every write containment makes AND every write its release makes is
	// probed: a stack that can contain but not release must not report
	// workload containment available (the contained workload could not be
	// restored).
	probes := []struct {
		op   string
		call func() error
		// ok are error codes that prove the call was authorised (the
		// request was then validated and rejected, nothing changed).
		ok []string
	}{
		{"lambda:GetFunctionConcurrency", func() error { _, err := wc.GetFunctionConcurrency(ctx, fn); return err }, nil},
		{"lambda:PutFunctionConcurrency", func() error { return wc.PutFunctionConcurrency(ctx, fn, 0) }, nil},
		{"lambda:DeleteFunctionConcurrency", func() error { return wc.DeleteFunctionConcurrency(ctx, fn) }, nil},
		{"ecs:DescribeServices", func() error { _, err := wc.DescribeECSService(ctx, cluster, service); return err }, nil},
		{"ecs:UpdateService", func() error { return wc.UpdateECSServiceDesiredCount(ctx, cluster, service, 0) }, nil},
		{"application-autoscaling:DescribeScalableTargets", func() error {
			_, err := wc.DescribeECSScalableTarget(ctx, region, "service/"+name+"/"+name)
			return err
		}, nil},
		// Release re-registers the scalable target with its recorded
		// suspended state. On a target that does not exist the request
		// carries no min/max capacity, so AWS can only validate and refuse
		// it (it never creates one): ValidationException after the
		// authorisation proves the permission.
		{"application-autoscaling:RegisterScalableTarget", func() error {
			return wc.SetECSScalingSuspended(ctx, region, "service/"+name+"/"+name, false, false, false)
		}, []string{"ValidationException"}},
		{"iam:ListAccessKeys", func() error { _, err := wc.ListAccessKeys(ctx, name); return err }, nil},
		{"iam:UpdateAccessKey", func() error { return wc.UpdateAccessKey(ctx, name, "AKIAAUTHSECSELFTEST0", false) }, nil},
		{"iam:AttachUserPolicy", func() error { return wc.AttachUserPolicy(ctx, name, policy) }, nil},
		{"iam:DetachUserPolicy", func() error { return wc.DetachUserPolicy(ctx, name, policy) }, nil},
	}
	for _, p := range probes {
		err := p.call()
		permitted := false
		if err != nil {
			code := ErrorCode(err)
			for _, c := range p.ok {
				permitted = permitted || code == c
			}
		}
		switch {
		case err == nil || IsNotFound(err) || permitted:
			continue
		case IsAccessDenied(err):
			r := classify(err, at())
			r.Message = p.op + " was refused: the stack does not enable workload containment (EnableWorkloadContainment). " + r.Message
			return r
		default:
			r := classify(err, at())
			r.Message = p.op + ": " + r.Message
			return r
		}
	}
	return CapabilityResult{Status: StatusOK, CheckedAt: at()}
}

// ErrNoContainer is returned when the enforcement client cannot contain.
var ErrNoContainer = errors.New("the enforcement client has no workload containment operations")

// ecsServiceRegion is the region of an ECS service or cluster ARN.
func ecsServiceRegion(arn string) string {
	p := strings.SplitN(arn, ":", 6)
	if len(p) == 6 && p[0] == "arn" && p[2] == "ecs" {
		return p[3]
	}
	return ""
}
