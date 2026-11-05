package awsenforce

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	aas "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

// liveIAM implements WorkloadContainer: every call is one request on the
// enforcement session's configuration, in the resource's region, with SDK
// retries off (like the v1 and v2 calls).
var _ WorkloadContainer = liveIAM{}

func (l liveIAM) lambdaIn(functionARN string) (*lambda.Client, error) {
	region, err := lambdaFunctionRegion(functionARN)
	if err != nil {
		return nil, err
	}
	return lambda.NewFromConfig(l.cfg, func(o *lambda.Options) {
		o.Region = region
		o.Retryer = aws.NopRetryer{}
	}), nil
}

func (l liveIAM) ecsIn(arn string) (*ecs.Client, error) {
	region := ecsServiceRegion(arn)
	if region == "" {
		return nil, fmt.Errorf("%q is not an ECS ARN", arn)
	}
	return ecs.NewFromConfig(l.cfg, func(o *ecs.Options) {
		o.Region = region
		o.Retryer = aws.NopRetryer{}
	}), nil
}

func (l liveIAM) aasIn(region string) *aas.Client {
	return aas.NewFromConfig(l.cfg, func(o *aas.Options) {
		o.Region = region
		o.Retryer = aws.NopRetryer{}
	})
}

func (l liveIAM) GetFunctionConcurrency(ctx context.Context, functionARN string) (*int32, error) {
	c, err := l.lambdaIn(functionARN)
	if err != nil {
		return nil, err
	}
	out, err := c.GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{FunctionName: aws.String(functionARN)})
	if err != nil {
		return nil, err
	}
	recordMetadata(ctx, out.ResultMetadata)
	return out.ReservedConcurrentExecutions, nil
}

func (l liveIAM) PutFunctionConcurrency(ctx context.Context, functionARN string, n int32) error {
	c, err := l.lambdaIn(functionARN)
	if err != nil {
		return err
	}
	out, err := c.PutFunctionConcurrency(ctx, &lambda.PutFunctionConcurrencyInput{
		FunctionName: aws.String(functionARN), ReservedConcurrentExecutions: aws.Int32(n)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DeleteFunctionConcurrency(ctx context.Context, functionARN string) error {
	c, err := l.lambdaIn(functionARN)
	if err != nil {
		return err
	}
	out, err := c.DeleteFunctionConcurrency(ctx, &lambda.DeleteFunctionConcurrencyInput{FunctionName: aws.String(functionARN)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DescribeECSService(ctx context.Context, clusterARN, serviceARN string) (*ECSServiceInfo, error) {
	c, err := l.ecsIn(serviceARN)
	if err != nil {
		return nil, err
	}
	out, err := c.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(clusterARN), Services: []string{serviceARN}})
	if err != nil {
		return nil, err
	}
	recordMetadata(ctx, out.ResultMetadata)
	for _, s := range out.Services {
		if aws.ToString(s.ServiceArn) == serviceARN && aws.ToString(s.Status) != "INACTIVE" {
			return &ECSServiceInfo{ClusterARN: aws.ToString(s.ClusterArn), ServiceARN: serviceARN, TaskDefinition: aws.ToString(s.TaskDefinition),
				DesiredCount: s.DesiredCount, RunningCount: s.RunningCount}, nil
		}
	}
	for _, f := range out.Failures {
		if r := aws.ToString(f.Reason); r != "MISSING" {
			return nil, fmt.Errorf("ecs:DescribeServices %s: %s", serviceARN, r)
		}
	}
	return nil, nil
}

func (l liveIAM) UpdateECSServiceDesiredCount(ctx context.Context, clusterARN, serviceARN string, n int32) error {
	c, err := l.ecsIn(serviceARN)
	if err != nil {
		return err
	}
	out, err := c.UpdateService(ctx, &ecs.UpdateServiceInput{Cluster: aws.String(clusterARN), Service: aws.String(serviceARN),
		DesiredCount: aws.Int32(n)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DescribeECSScalableTarget(ctx context.Context, region, resourceID string) (*ScalableTargetInfo, error) {
	out, err := l.aasIn(region).DescribeScalableTargets(ctx, &aas.DescribeScalableTargetsInput{
		ServiceNamespace: aastypes.ServiceNamespaceEcs, ResourceIds: []string{resourceID},
		ScalableDimension: aastypes.ScalableDimensionECSServiceDesiredCount})
	if err != nil {
		return nil, err
	}
	recordMetadata(ctx, out.ResultMetadata)
	for _, t := range out.ScalableTargets {
		if aws.ToString(t.ResourceId) != resourceID {
			continue
		}
		info := &ScalableTargetInfo{MinCapacity: aws.ToInt32(t.MinCapacity), MaxCapacity: aws.ToInt32(t.MaxCapacity)}
		if s := t.SuspendedState; s != nil {
			info.DynamicIn = aws.ToBool(s.DynamicScalingInSuspended)
			info.DynamicOut = aws.ToBool(s.DynamicScalingOutSuspended)
			info.ScheduledSuspended = aws.ToBool(s.ScheduledScalingSuspended)
		}
		return info, nil
	}
	return nil, nil
}

// SetECSScalingSuspended re-registers the EXISTING scalable target with only
// its SuspendedState: min and max capacity are left as they are.
func (l liveIAM) SetECSScalingSuspended(ctx context.Context, region, resourceID string, dynamicIn, dynamicOut, scheduled bool) error {
	out, err := l.aasIn(region).RegisterScalableTarget(ctx, &aas.RegisterScalableTargetInput{
		ServiceNamespace: aastypes.ServiceNamespaceEcs, ResourceId: aws.String(resourceID),
		ScalableDimension: aastypes.ScalableDimensionECSServiceDesiredCount,
		SuspendedState: &aastypes.SuspendedState{DynamicScalingInSuspended: aws.Bool(dynamicIn),
			DynamicScalingOutSuspended: aws.Bool(dynamicOut), ScheduledScalingSuspended: aws.Bool(scheduled)}})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) AttachUserPolicy(ctx context.Context, userName, policyARN string) error {
	out, err := l.c.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{UserName: aws.String(userName), PolicyArn: aws.String(policyARN)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DetachUserPolicy(ctx context.Context, userName, policyARN string) error {
	out, err := l.c.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: aws.String(userName), PolicyArn: aws.String(policyARN)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) ListAccessKeys(ctx context.Context, userName string) ([]AccessKeyInfo, error) {
	var keys []AccessKeyInfo
	pg := iam.NewListAccessKeysPaginator(l.c, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, k := range page.AccessKeyMetadata {
			keys = append(keys, AccessKeyInfo{ID: aws.ToString(k.AccessKeyId), Active: k.Status == iamtypes.StatusTypeActive})
		}
	}
	return keys, nil
}

func (l liveIAM) UpdateAccessKey(ctx context.Context, userName, keyID string, active bool) error {
	st := iamtypes.StatusTypeInactive
	if active {
		st = iamtypes.StatusTypeActive
	}
	out, err := l.c.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{UserName: aws.String(userName), AccessKeyId: aws.String(keyID), Status: st})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}
