// Package rpfake is an in-memory test double of the AWS calls Phase 3
// resource-policy collection makes (awsdiscovery.S3CollectAPI,
// S3ControlPolicyAPI, KMSCollectAPI, SQSPolicyAPI, SNSPolicyAPI,
// LambdaPolicyAPI, SecretsPolicyAPI). It makes no network call.
//
// One Region holds one region's resources. Every listing pages PageSize items
// at a time; every call can be made to fail (Errs, keyed "<Op>" or
// "<Op>:<resource>"), or to be throttled a number of times first (Throttles,
// same keys). An empty policy string means "no policy": the read answers with
// the service's own not-found code, as AWS does.
package rpfake

import (
	"context"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
)

// Named is a resource with a name and a policy ("" = none).
type Named struct{ Name, Policy string }

// Bucket is a general purpose bucket, listed account-wide.
type Bucket struct{ Name, Region, Policy string }

// MRAP is a multi-region access point.
type MRAP struct{ Name, Alias, Policy string }

// ARNPolicy is a resource identified by ARN (key, topic, secret).
type ARNPolicy struct{ ARN, Policy string }

// Queue is a queue by URL.
type Queue struct{ URL, Policy string }

// Version is a published function version.
type Version struct{ Version, Policy string }

// Function is a Lambda function with its versions and aliases.
type Function struct {
	Name, ARN, Policy string
	Versions          []Version
	Aliases           []Named
}

// LayerVersion is one layer version.
type LayerVersion struct {
	Version int64
	Policy  string
}

// Layer is a Lambda layer.
type Layer struct {
	ARN      string
	Versions []LayerVersion
}

// Region is one region's resources and failure plan.
type Region struct {
	Name      string
	AccountID string
	PageSize  int

	Buckets      []Bucket // answered by ListBuckets in any region
	DirBuckets   []Named
	AccessPoints []Named
	MRAPs        []MRAP
	OLAPs        []Named
	Keys         []ARNPolicy
	Queues       []Queue
	Topics       []ARNPolicy
	Functions    []Function
	Layers       []Layer
	Secrets      []ARNPolicy
	// BucketPolicies answers GetBucketPolicy by bucket name (general purpose
	// buckets are read through their own region's client).
	BucketPolicies map[string]string

	Errs      map[string]error
	Throttles map[string]int

	mu    sync.Mutex
	Calls map[string]int
}

// APIError builds an AWS-shaped error with a code.
func APIError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code + " (fake)"}
}

func (r *Region) check(op, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Calls == nil {
		r.Calls = map[string]int{}
	}
	r.Calls[op]++
	for _, k := range []string{op + ":" + key, op} {
		if n := r.Throttles[k]; n > 0 {
			r.Throttles[k] = n - 1
			return APIError("ThrottlingException")
		}
	}
	for _, k := range []string{op + ":" + key, op} {
		if err, ok := r.Errs[k]; ok {
			return err
		}
	}
	return nil
}

// page returns [from, to) and the next token for n items.
func (r *Region) page(token *string, n int) (int, int, *string) {
	size := r.PageSize
	if size <= 0 {
		size = 1000
	}
	from := 0
	if token != nil {
		from, _ = strconv.Atoi(*token)
	}
	to := from + size
	if to >= n {
		return from, n, nil
	}
	return from, to, aws.String(strconv.Itoa(to))
}

func policyOrAbsent(policy, absentCode string) (*string, error) {
	if policy == "" {
		return nil, APIError(absentCode)
	}
	return aws.String(policy), nil
}

/* ---------------------------------- S3 ------------------------------------ */

func (r *Region) ListBuckets(_ context.Context, in *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if err := r.check("ListBuckets", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.ContinuationToken, len(r.Buckets))
	out := &s3.ListBucketsOutput{ContinuationToken: next}
	for _, b := range r.Buckets[from:to] {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(b.Name), BucketRegion: aws.String(b.Region)})
	}
	return out, nil
}

func (r *Region) ListDirectoryBuckets(_ context.Context, in *s3.ListDirectoryBucketsInput, _ ...func(*s3.Options)) (*s3.ListDirectoryBucketsOutput, error) {
	if err := r.check("ListDirectoryBuckets", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.ContinuationToken, len(r.DirBuckets))
	out := &s3.ListDirectoryBucketsOutput{ContinuationToken: next}
	for _, b := range r.DirBuckets[from:to] {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(b.Name)})
	}
	return out, nil
}

func (r *Region) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	name := aws.ToString(in.Bucket)
	if err := r.check("GetBucketPolicy", name); err != nil {
		return nil, err
	}
	policy, found := r.BucketPolicies[name]
	if !found {
		for _, b := range r.DirBuckets {
			if b.Name == name {
				policy = b.Policy
			}
		}
	}
	p, err := policyOrAbsent(policy, "NoSuchBucketPolicy")
	if err != nil {
		return nil, err
	}
	return &s3.GetBucketPolicyOutput{Policy: p}, nil
}

/* ------------------------------- S3 Control ------------------------------- */

func (r *Region) ListAccessPoints(_ context.Context, in *s3control.ListAccessPointsInput, _ ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error) {
	if err := r.check("ListAccessPoints", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.NextToken, len(r.AccessPoints))
	out := &s3control.ListAccessPointsOutput{NextToken: next}
	for _, a := range r.AccessPoints[from:to] {
		out.AccessPointList = append(out.AccessPointList, s3ctypes.AccessPoint{Name: aws.String(a.Name),
			AccessPointArn: aws.String("arn:aws:s3:" + r.Name + ":" + r.AccountID + ":accesspoint/" + a.Name)})
	}
	return out, nil
}

func (r *Region) GetAccessPointPolicy(_ context.Context, in *s3control.GetAccessPointPolicyInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyOutput, error) {
	name := aws.ToString(in.Name)
	if err := r.check("GetAccessPointPolicy", name); err != nil {
		return nil, err
	}
	for _, a := range r.AccessPoints {
		if a.Name == name {
			p, err := policyOrAbsent(a.Policy, "NoSuchAccessPointPolicy")
			if err != nil {
				return nil, err
			}
			return &s3control.GetAccessPointPolicyOutput{Policy: p}, nil
		}
	}
	return nil, APIError("NoSuchAccessPoint")
}

func (r *Region) ListMultiRegionAccessPoints(_ context.Context, in *s3control.ListMultiRegionAccessPointsInput, _ ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error) {
	if err := r.check("ListMultiRegionAccessPoints", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.NextToken, len(r.MRAPs))
	out := &s3control.ListMultiRegionAccessPointsOutput{NextToken: next}
	for _, m := range r.MRAPs[from:to] {
		out.AccessPoints = append(out.AccessPoints, s3ctypes.MultiRegionAccessPointReport{Name: aws.String(m.Name), Alias: aws.String(m.Alias)})
	}
	return out, nil
}

func (r *Region) GetMultiRegionAccessPointPolicy(_ context.Context, in *s3control.GetMultiRegionAccessPointPolicyInput, _ ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointPolicyOutput, error) {
	name := aws.ToString(in.Name)
	if err := r.check("GetMultiRegionAccessPointPolicy", name); err != nil {
		return nil, err
	}
	for _, m := range r.MRAPs {
		if m.Name == name {
			out := &s3control.GetMultiRegionAccessPointPolicyOutput{Policy: &s3ctypes.MultiRegionAccessPointPolicyDocument{}}
			if m.Policy != "" {
				out.Policy.Established = &s3ctypes.EstablishedMultiRegionAccessPointPolicy{Policy: aws.String(m.Policy)}
			}
			return out, nil
		}
	}
	return nil, APIError("NoSuchMultiRegionAccessPoint")
}

func (r *Region) ListAccessPointsForObjectLambda(_ context.Context, in *s3control.ListAccessPointsForObjectLambdaInput, _ ...func(*s3control.Options)) (*s3control.ListAccessPointsForObjectLambdaOutput, error) {
	if err := r.check("ListAccessPointsForObjectLambda", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.NextToken, len(r.OLAPs))
	out := &s3control.ListAccessPointsForObjectLambdaOutput{NextToken: next}
	for _, a := range r.OLAPs[from:to] {
		out.ObjectLambdaAccessPointList = append(out.ObjectLambdaAccessPointList, s3ctypes.ObjectLambdaAccessPoint{Name: aws.String(a.Name)})
	}
	return out, nil
}

func (r *Region) GetAccessPointPolicyForObjectLambda(_ context.Context, in *s3control.GetAccessPointPolicyForObjectLambdaInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyForObjectLambdaOutput, error) {
	name := aws.ToString(in.Name)
	if err := r.check("GetAccessPointPolicyForObjectLambda", name); err != nil {
		return nil, err
	}
	for _, a := range r.OLAPs {
		if a.Name == name {
			p, err := policyOrAbsent(a.Policy, "NoSuchAccessPointPolicy")
			if err != nil {
				return nil, err
			}
			return &s3control.GetAccessPointPolicyForObjectLambdaOutput{Policy: p}, nil
		}
	}
	return nil, APIError("NoSuchAccessPoint")
}

/* ----------------------------------- KMS ---------------------------------- */

func (r *Region) ListKeys(_ context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if err := r.check("ListKeys", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.Marker, len(r.Keys))
	out := &kms.ListKeysOutput{NextMarker: next, Truncated: next != nil}
	for _, k := range r.Keys[from:to] {
		out.Keys = append(out.Keys, kmstypes.KeyListEntry{KeyArn: aws.String(k.ARN)})
	}
	return out, nil
}

func (r *Region) GetKeyPolicy(_ context.Context, in *kms.GetKeyPolicyInput, _ ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	id := aws.ToString(in.KeyId)
	if err := r.check("GetKeyPolicy", id); err != nil {
		return nil, err
	}
	for _, k := range r.Keys {
		if k.ARN == id {
			p, err := policyOrAbsent(k.Policy, "NotFoundException")
			if err != nil {
				return nil, err
			}
			return &kms.GetKeyPolicyOutput{Policy: p}, nil
		}
	}
	return nil, APIError("NotFoundException")
}

/* ----------------------------------- SQS ---------------------------------- */

func (r *Region) ListQueues(_ context.Context, in *sqs.ListQueuesInput, _ ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	if err := r.check("ListQueues", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.NextToken, len(r.Queues))
	out := &sqs.ListQueuesOutput{NextToken: next}
	for _, q := range r.Queues[from:to] {
		out.QueueUrls = append(out.QueueUrls, q.URL)
	}
	return out, nil
}

func (r *Region) GetQueueAttributes(_ context.Context, in *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	u := aws.ToString(in.QueueUrl)
	if err := r.check("GetQueueAttributes", u); err != nil {
		return nil, err
	}
	for _, q := range r.Queues {
		if q.URL == u {
			out := &sqs.GetQueueAttributesOutput{Attributes: map[string]string{}}
			if q.Policy != "" {
				out.Attributes["Policy"] = q.Policy
			}
			return out, nil
		}
	}
	return nil, APIError("AWS.SimpleQueueService.NonExistentQueue")
}

/* ----------------------------------- SNS ---------------------------------- */

func (r *Region) ListTopics(_ context.Context, in *sns.ListTopicsInput, _ ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	if err := r.check("ListTopics", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.NextToken, len(r.Topics))
	out := &sns.ListTopicsOutput{NextToken: next}
	for _, t := range r.Topics[from:to] {
		out.Topics = append(out.Topics, snstypes.Topic{TopicArn: aws.String(t.ARN)})
	}
	return out, nil
}

func (r *Region) GetTopicAttributes(_ context.Context, in *sns.GetTopicAttributesInput, _ ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	arn := aws.ToString(in.TopicArn)
	if err := r.check("GetTopicAttributes", arn); err != nil {
		return nil, err
	}
	for _, t := range r.Topics {
		if t.ARN == arn {
			out := &sns.GetTopicAttributesOutput{Attributes: map[string]string{"TopicArn": arn, "Owner": r.AccountID}}
			if t.Policy != "" {
				out.Attributes["Policy"] = t.Policy
			}
			return out, nil
		}
	}
	return nil, APIError("NotFound")
}

/* --------------------------------- Lambda --------------------------------- */

func (r *Region) fn(nameOrARN string) *Function {
	for i := range r.Functions {
		if r.Functions[i].ARN == nameOrARN || r.Functions[i].Name == nameOrARN {
			return &r.Functions[i]
		}
	}
	return nil
}

func (r *Region) ListFunctions(_ context.Context, in *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if err := r.check("ListFunctions", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.Marker, len(r.Functions))
	out := &lambda.ListFunctionsOutput{NextMarker: next}
	for _, f := range r.Functions[from:to] {
		out.Functions = append(out.Functions, lambdatypes.FunctionConfiguration{FunctionName: aws.String(f.Name), FunctionArn: aws.String(f.ARN)})
	}
	return out, nil
}

func (r *Region) ListVersionsByFunction(_ context.Context, in *lambda.ListVersionsByFunctionInput, _ ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error) {
	f := r.fn(aws.ToString(in.FunctionName))
	if err := r.check("ListVersionsByFunction", aws.ToString(in.FunctionName)); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, APIError("ResourceNotFoundException")
	}
	all := append([]Version{{Version: "$LATEST"}}, f.Versions...)
	from, to, next := r.page(in.Marker, len(all))
	out := &lambda.ListVersionsByFunctionOutput{NextMarker: next}
	for _, v := range all[from:to] {
		out.Versions = append(out.Versions, lambdatypes.FunctionConfiguration{Version: aws.String(v.Version), FunctionArn: aws.String(f.ARN + ":" + v.Version)})
	}
	return out, nil
}

func (r *Region) ListAliases(_ context.Context, in *lambda.ListAliasesInput, _ ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error) {
	f := r.fn(aws.ToString(in.FunctionName))
	if err := r.check("ListAliases", aws.ToString(in.FunctionName)); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, APIError("ResourceNotFoundException")
	}
	from, to, next := r.page(in.Marker, len(f.Aliases))
	out := &lambda.ListAliasesOutput{NextMarker: next}
	for _, a := range f.Aliases[from:to] {
		out.Aliases = append(out.Aliases, lambdatypes.AliasConfiguration{Name: aws.String(a.Name), AliasArn: aws.String(f.ARN + ":" + a.Name)})
	}
	return out, nil
}

func (r *Region) GetPolicy(_ context.Context, in *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	f := r.fn(aws.ToString(in.FunctionName))
	q := aws.ToString(in.Qualifier)
	key := aws.ToString(in.FunctionName)
	if q != "" {
		key += ":" + q
	}
	if err := r.check("GetPolicy", key); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, APIError("ResourceNotFoundException")
	}
	policy := f.Policy
	if q != "" {
		policy = ""
		for _, v := range f.Versions {
			if v.Version == q {
				policy = v.Policy
			}
		}
		for _, a := range f.Aliases {
			if a.Name == q {
				policy = a.Policy
			}
		}
	}
	p, err := policyOrAbsent(policy, "ResourceNotFoundException")
	if err != nil {
		return nil, err
	}
	return &lambda.GetPolicyOutput{Policy: p}, nil
}

func (r *Region) ListLayers(_ context.Context, in *lambda.ListLayersInput, _ ...func(*lambda.Options)) (*lambda.ListLayersOutput, error) {
	if err := r.check("ListLayers", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.Marker, len(r.Layers))
	out := &lambda.ListLayersOutput{NextMarker: next}
	for _, l := range r.Layers[from:to] {
		out.Layers = append(out.Layers, lambdatypes.LayersListItem{LayerArn: aws.String(l.ARN)})
	}
	return out, nil
}

func (r *Region) layer(arn string) *Layer {
	for i := range r.Layers {
		if r.Layers[i].ARN == arn {
			return &r.Layers[i]
		}
	}
	return nil
}

func (r *Region) ListLayerVersions(_ context.Context, in *lambda.ListLayerVersionsInput, _ ...func(*lambda.Options)) (*lambda.ListLayerVersionsOutput, error) {
	if err := r.check("ListLayerVersions", aws.ToString(in.LayerName)); err != nil {
		return nil, err
	}
	l := r.layer(aws.ToString(in.LayerName))
	if l == nil {
		return nil, APIError("ResourceNotFoundException")
	}
	from, to, next := r.page(in.Marker, len(l.Versions))
	out := &lambda.ListLayerVersionsOutput{NextMarker: next}
	for _, v := range l.Versions[from:to] {
		out.LayerVersions = append(out.LayerVersions, lambdatypes.LayerVersionsListItem{
			Version: v.Version, LayerVersionArn: aws.String(l.ARN + ":" + strconv.FormatInt(v.Version, 10))})
	}
	return out, nil
}

func (r *Region) GetLayerVersionPolicy(_ context.Context, in *lambda.GetLayerVersionPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetLayerVersionPolicyOutput, error) {
	key := aws.ToString(in.LayerName) + ":" + strconv.FormatInt(aws.ToInt64(in.VersionNumber), 10)
	if err := r.check("GetLayerVersionPolicy", key); err != nil {
		return nil, err
	}
	l := r.layer(aws.ToString(in.LayerName))
	if l == nil {
		return nil, APIError("ResourceNotFoundException")
	}
	for _, v := range l.Versions {
		if v.Version == aws.ToInt64(in.VersionNumber) {
			p, err := policyOrAbsent(v.Policy, "ResourceNotFoundException")
			if err != nil {
				return nil, err
			}
			return &lambda.GetLayerVersionPolicyOutput{Policy: p}, nil
		}
	}
	return nil, APIError("ResourceNotFoundException")
}

/* ----------------------------- Secrets Manager ---------------------------- */

func (r *Region) ListSecrets(_ context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if err := r.check("ListSecrets", ""); err != nil {
		return nil, err
	}
	from, to, next := r.page(in.NextToken, len(r.Secrets))
	out := &secretsmanager.ListSecretsOutput{NextToken: next}
	for _, s := range r.Secrets[from:to] {
		out.SecretList = append(out.SecretList, smtypes.SecretListEntry{ARN: aws.String(s.ARN)})
	}
	return out, nil
}

func (r *Region) GetResourcePolicy(_ context.Context, in *secretsmanager.GetResourcePolicyInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	id := aws.ToString(in.SecretId)
	if err := r.check("GetResourcePolicy", id); err != nil {
		return nil, err
	}
	for _, s := range r.Secrets {
		if s.ARN == id {
			out := &secretsmanager.GetResourcePolicyOutput{ARN: aws.String(id)}
			if s.Policy != "" {
				out.ResourcePolicy = aws.String(s.Policy)
			}
			return out, nil
		}
	}
	return nil, APIError("ResourceNotFoundException")
}

// GetSecretValue exists only so a test can prove collection never calls it:
// it is not part of SecretsPolicyAPI, and calling it here panics.
func (r *Region) GetSecretValue() { panic("rpfake: GetSecretValue must never be called") }
