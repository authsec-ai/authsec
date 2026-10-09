package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"
)

// Resource-based policies: the half of "can this identity really do this"
// that reading only identity-based policies cannot see at all.
//
// Every permission this package parses elsewhere is IDENTITY-based -- attached
// to a role or a user, saying what IT may do. S3 buckets and KMS keys can also
// carry a RESOURCE-based policy, attached to the bucket or key itself, and an
// explicit Deny there overrides any identity-based Allow (AWS's own evaluation
// order: an explicit deny anywhere wins). Without reading it, a bucket policy
// that blocks an action is invisible, and the identity-based grant it blocks
// still reads as real access -- the false positive this file exists to close.
//
// The reverse -- a resource policy's Allow granting access to a principal that
// has NO identity-based permission at all -- is a real and separate gap this
// file does not close. Discovering it would mean reading every bucket and key
// policy in the account regardless of whether any scanned identity references
// it, which is a different, account-wide surface; what follows here only
// resolves policies for resources a scanned identity's permissions ALREADY
// named.

// S3PolicyAPI is the slice of S3 this package uses.
type S3PolicyAPI interface {
	GetBucketPolicy(ctx context.Context, in *s3.GetBucketPolicyInput, opts ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

// KMSPolicyAPI is the slice of KMS this package uses.
type KMSPolicyAPI interface {
	GetKeyPolicy(ctx context.Context, in *kms.GetKeyPolicyInput, opts ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
}

// NewS3PolicyClient builds a real S3 client for resource-policy reads.
func NewS3PolicyClient(cfg aws.Config) S3PolicyAPI { return s3.NewFromConfig(cfg) }

// NewKMSPolicyClient builds a real KMS client for resource-policy reads.
func NewKMSPolicyClient(cfg aws.Config) KMSPolicyAPI { return kms.NewFromConfig(cfg) }

// ResourcePolicyReader reads S3 bucket and KMS key resource policies.
type ResourcePolicyReader struct {
	s3  S3PolicyAPI
	kms KMSPolicyAPI
}

// NewResourcePolicyReader constructs a reader over the given clients. Either
// may be nil, same as every other reader here -- a customer without KMS in
// scope must not cost the S3 half.
func NewResourcePolicyReader(s3api S3PolicyAPI, kmsapi KMSPolicyAPI) *ResourcePolicyReader {
	return &ResourcePolicyReader{s3: s3api, kms: kmsapi}
}

// ResourcePolicy is one resource's own policy document, parsed the same way
// an identity's policy is -- it is the same JSON statement language -- plus
// whether any statement is an explicit Deny, which is the one fact that can
// invalidate an identity-based Allow this discovery already recorded.
type ResourcePolicy struct {
	Document    string
	Statements  []PolicyStatement
	HasDeny     bool
	ParseFailed bool
}

// resourcePolicyFrom parses a raw policy document (or its absence) into a
// ResourcePolicy. Shared by the S3 and KMS paths, which differ only in which
// AWS call produced the string -- named, so a failed read reports its call and
// its AWS error code, and a caller counting per-resource failures (T3.7) can
// say "s3:GetBucketPolicy AccessDenied" rather than a bare message.
func resourcePolicyFrom(call, doc string, readErr error) (ResourcePolicy, error) {
	if readErr != nil {
		if isNoSuchPolicy(readErr) {
			// No resource policy at all is a real, common, and CLEAN answer --
			// most buckets and keys rely on identity-based policies alone. It
			// is not the same as a denied read, which learns nothing.
			return ResourcePolicy{}, nil
		}
		return ResourcePolicy{}, withCallName(call, readErr)
	}
	stmts, _, err := ParsePolicyDocument(doc)
	if err != nil {
		return ResourcePolicy{Document: doc, ParseFailed: true}, nil
	}
	out := ResourcePolicy{Document: doc, Statements: stmts}
	for _, s := range stmts {
		if s.Effect == "deny" {
			out.HasDeny = true
			break
		}
	}
	return out, nil
}

// isNoSuchPolicy reports whether AWS refused the read because there is no
// policy to return, as opposed to a real denial. Both services use a
// distinct "not found" error for this rather than an empty success.
//
// S3 does not model NoSuchBucketPolicy as a generated exception type the way
// KMS models NotFoundException, so it is matched on error code, same fallback
// isReportInProgress uses for IAM.
func isNoSuchPolicy(err error) bool {
	var kmsNotFound *kmstypes.NotFoundException
	if errors.As(err, &kmsNotFound) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchBucketPolicy"
	}
	return false
}

// BucketPolicy reads one S3 bucket's resource policy.
func (r *ResourcePolicyReader) BucketPolicy(ctx context.Context, bucketName string) (ResourcePolicy, error) {
	if r.s3 == nil || bucketName == "" {
		return ResourcePolicy{}, nil
	}
	out, err := r.s3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucketName)})
	var doc string
	if out != nil {
		doc = aws.ToString(out.Policy)
	}
	return resourcePolicyFrom("s3:GetBucketPolicy", doc, err)
}

// KeyPolicy reads one KMS key's policy. keyID accepts either a bare key id or
// a full key ARN, both of which GetKeyPolicy accepts directly.
func (r *ResourcePolicyReader) KeyPolicy(ctx context.Context, keyID string) (ResourcePolicy, error) {
	if r.kms == nil || keyID == "" {
		return ResourcePolicy{}, nil
	}
	out, err := r.kms.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId: aws.String(keyID), PolicyName: aws.String("default"),
	})
	var doc string
	if out != nil {
		doc = aws.ToString(out.Policy)
	}
	return resourcePolicyFrom("kms:GetKeyPolicy", doc, err)
}

/* ------------------------------------------------------------------------- */
/*        Resource-policy COLLECTION by enumeration (Phase 3, T3.03b)        */
/* ------------------------------------------------------------------------- */

// Everything above reads the policy of a resource an identity's grant already
// named, for the graph's evidence panel. What follows is a different job
// (SPEC-iga-phase3-policy.md §3.9): ENUMERATE every resource of each collected
// policy-bearing form, in every enabled region, read each one's policy (or
// learn that it has none), and say per form and region whether that set is
// complete. The first-attachment proof and the route analysis (§3.4) read
// only this; they never read the summary above.
//
// This file stays an adapter: it returns policy TEXT exactly as AWS sent it,
// with per-(form, region) coverage. Canonicalisation, hashing and storage
// (056) belong to the services layer.

// Collected resource-policy forms (§3.9). Exactly 056's
// cloud_resource_policy_coverage.resource_form CHECK list, which
// igagov.AllForms() also mirrors; TestP3RPCFormsMatch056AndCatalog holds the
// three together.
const (
	FormS3Bucket                  = "s3_bucket"
	FormS3DirectoryBucket         = "s3_directory_bucket"
	FormS3AccessPoint             = "s3_access_point"
	FormS3MultiRegionAccessPoint  = "s3_multi_region_access_point"
	FormS3ObjectLambdaAccessPoint = "s3_object_lambda_access_point"
	FormKMSKey                    = "kms_key"
	FormSQSQueue                  = "sqs_queue"
	FormSNSTopic                  = "sns_topic"
	FormLambdaFunction            = "lambda_function"
	FormLambdaFunctionVersion     = "lambda_function_version"
	FormLambdaAlias               = "lambda_alias"
	FormLambdaLayerVersion        = "lambda_layer_version"
	FormSecretsManagerSecret      = "secretsmanager_secret"
)

// collectedForms is §3.9's table in its own order.
var collectedForms = []string{
	FormS3Bucket, FormS3DirectoryBucket, FormS3AccessPoint, FormS3MultiRegionAccessPoint,
	FormS3ObjectLambdaAccessPoint, FormKMSKey, FormSQSQueue, FormSNSTopic, FormLambdaFunction,
	FormLambdaFunctionVersion, FormLambdaAlias, FormLambdaLayerVersion, FormSecretsManagerSecret,
}

// CollectedForms returns the collected forms, in §3.9's order.
func CollectedForms() []string { return append([]string(nil), collectedForms...) }

// accountScopedForms are read once per account rather than per region
// (§3.9 "Scope": ListBuckets is account-wide; multi-region access points live
// in the S3 control-plane region). Every other collected form is regional.
var accountScopedForms = map[string]bool{FormS3Bucket: true, FormS3MultiRegionAccessPoint: true}

// IsAccountScopedForm reports whether a form is collected once per account.
func IsAccountScopedForm(form string) bool { return accountScopedForms[form] }

// AccountFormRegion is the region label an account-scoped form's coverage
// row and observations carry, and the region its list call is made in.
//
// DECISION (T3.03b-1). 056 keys coverage by (form, region) and an
// observation's region must match its coverage row (FK), so an account-wide
// form needs ONE stable region label. It is the region the list call is
// signed for: S3's home region of the partition for s3_bucket (us-east-1,
// us-gov-west-1, cn-north-1), and the multi-region access point control-plane
// region (us-west-2) for s3_multi_region_access_point in the aws partition.
// Stable across region-selection changes, so two scans of one account always
// produce comparable rows; igagov.AnalyzeRoutes reads account-scoped forms
// as "every row complete and at least one row", which this satisfies. A
// bucket's own region is used only to address its GetBucketPolicy.
func AccountFormRegion(form, partition string) string {
	home := "us-east-1"
	switch partition {
	case "aws-us-gov":
		home = "us-gov-west-1"
	case "aws-cn":
		home = "cn-north-1"
	}
	if form == FormS3MultiRegionAccessPoint && (partition == "" || partition == "aws") {
		return "us-west-2"
	}
	return home
}

// PartitionOf returns an ARN's partition ("aws" when it is not an ARN).
func PartitionOf(arn string) string {
	parts := strings.SplitN(arn, ":", 3)
	if len(parts) >= 2 && parts[0] == "arn" && parts[1] != "" {
		return parts[1]
	}
	return "aws"
}

// Coverage states, exactly 056's cloud_resource_policy_coverage.state CHECK.
const (
	CoverageComplete     = "complete"
	CoveragePartial      = "partial"
	CoverageDenied       = "denied"
	CoverageNotCollected = "not_collected"
)

// --- the AWS slices collection uses, one interface per service ---------------

// S3CollectAPI is the slice of S3 collection uses: both bucket listings and
// the per-bucket policy read (general purpose and directory buckets alike;
// the SDK routes a directory bucket's GetBucketPolicy to the s3express
// control endpoint by its name).
type S3CollectAPI interface {
	S3PolicyAPI
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	ListDirectoryBuckets(ctx context.Context, in *s3.ListDirectoryBucketsInput, opts ...func(*s3.Options)) (*s3.ListDirectoryBucketsOutput, error)
}

// S3ControlPolicyAPI is the slice of S3 Control collection uses: access
// points, multi-region access points and Object Lambda access points.
type S3ControlPolicyAPI interface {
	ListAccessPoints(ctx context.Context, in *s3control.ListAccessPointsInput, opts ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error)
	GetAccessPointPolicy(ctx context.Context, in *s3control.GetAccessPointPolicyInput, opts ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyOutput, error)
	ListMultiRegionAccessPoints(ctx context.Context, in *s3control.ListMultiRegionAccessPointsInput, opts ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error)
	GetMultiRegionAccessPointPolicy(ctx context.Context, in *s3control.GetMultiRegionAccessPointPolicyInput, opts ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointPolicyOutput, error)
	ListAccessPointsForObjectLambda(ctx context.Context, in *s3control.ListAccessPointsForObjectLambdaInput, opts ...func(*s3control.Options)) (*s3control.ListAccessPointsForObjectLambdaOutput, error)
	GetAccessPointPolicyForObjectLambda(ctx context.Context, in *s3control.GetAccessPointPolicyForObjectLambdaInput, opts ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyForObjectLambdaOutput, error)
}

// KMSCollectAPI is the slice of KMS collection uses.
type KMSCollectAPI interface {
	KMSPolicyAPI
	ListKeys(ctx context.Context, in *kms.ListKeysInput, opts ...func(*kms.Options)) (*kms.ListKeysOutput, error)
}

// SQSPolicyAPI is the slice of SQS collection uses.
type SQSPolicyAPI interface {
	ListQueues(ctx context.Context, in *sqs.ListQueuesInput, opts ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, opts ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// SNSPolicyAPI is the slice of SNS collection uses.
type SNSPolicyAPI interface {
	ListTopics(ctx context.Context, in *sns.ListTopicsInput, opts ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(ctx context.Context, in *sns.GetTopicAttributesInput, opts ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

// LambdaPolicyAPI is the slice of Lambda collection uses: functions, their
// published versions and aliases, layers and layer versions, and the policy
// reads of each.
type LambdaPolicyAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, opts ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListVersionsByFunction(ctx context.Context, in *lambda.ListVersionsByFunctionInput, opts ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error)
	ListAliases(ctx context.Context, in *lambda.ListAliasesInput, opts ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error)
	GetPolicy(ctx context.Context, in *lambda.GetPolicyInput, opts ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
	ListLayers(ctx context.Context, in *lambda.ListLayersInput, opts ...func(*lambda.Options)) (*lambda.ListLayersOutput, error)
	ListLayerVersions(ctx context.Context, in *lambda.ListLayerVersionsInput, opts ...func(*lambda.Options)) (*lambda.ListLayerVersionsOutput, error)
	GetLayerVersionPolicy(ctx context.Context, in *lambda.GetLayerVersionPolicyInput, opts ...func(*lambda.Options)) (*lambda.GetLayerVersionPolicyOutput, error)
}

// SecretsPolicyAPI is the slice of Secrets Manager collection uses. It has no
// GetSecretValue on purpose: the template keeps that explicitly denied.
type SecretsPolicyAPI interface {
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetResourcePolicy(ctx context.Context, in *secretsmanager.GetResourcePolicyInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
}

// ResourcePolicyClients are one region's clients. A nil member means the
// service cannot be read there; its forms are recorded not_collected.
type ResourcePolicyClients struct {
	S3        S3CollectAPI
	S3Control S3ControlPolicyAPI
	KMS       KMSCollectAPI
	SQS       SQSPolicyAPI
	SNS       SNSPolicyAPI
	Lambda    LambdaPolicyAPI
	Secrets   SecretsPolicyAPI
}

// NewResourcePolicyClients builds real clients from one region's config.
func NewResourcePolicyClients(cfg aws.Config) ResourcePolicyClients {
	return ResourcePolicyClients{
		S3:        s3.NewFromConfig(cfg),
		S3Control: s3control.NewFromConfig(cfg),
		KMS:       kms.NewFromConfig(cfg),
		SQS:       sqs.NewFromConfig(cfg),
		SNS:       sns.NewFromConfig(cfg),
		Lambda:    lambda.NewFromConfig(cfg),
		Secrets:   secretsmanager.NewFromConfig(cfg),
	}
}

// ResourcePolicyClientsFunc returns the clients for one region.
type ResourcePolicyClientsFunc func(ctx context.Context, region string) (ResourcePolicyClients, error)

// --- what collection returns ------------------------------------------------

// PolicyRead is one resource whose policy was read: present with its text as
// AWS returned it, or absent ("no policy" is a successful read).
type PolicyRead struct {
	ARN     string
	Present bool
	Text    string
	ReadAt  time.Time
}

// ReadFailure is one resource whose policy could not be read, or one parent
// whose children could not be listed (a function's versions or aliases, a
// layer's versions): the call and AWS's error code, never the message (which
// carries request ids).
type ReadFailure struct {
	ARN       string
	Call      string
	Code      string
	Denied    bool
	Throttled bool
	Listing   bool
}

// FormCoverage is one (form, region) of one scan: 056's coverage row plus the
// reads it covers. Enumerated counts the resources listed; ReadOK + ReadFailed
// never exceeds it; State is complete exactly when the listing finished and
// every listed resource was read (056 cloud_rpc_complete_chk).
type FormCoverage struct {
	Form       string
	Region     string
	State      string
	Enumerated int
	ReadOK     int
	ReadFailed int
	Reason     string
	Reads      []PolicyRead
	Failures   []ReadFailure
	// API and ErrorCode name the first call that failed, as the SDK stated it.
	API       string
	ErrorCode string
}

// NotCollected is a not_collected coverage for a form and region.
func NotCollected(form, region, reason string) FormCoverage {
	return FormCoverage{Form: form, Region: region, State: CoverageNotCollected, Reason: reason}
}

// NotCollectedAll is every collected form recorded not_collected: account
// forms under their account region, regional forms in each region. Used for
// a connector whose discovery template predates collection (§3.9: "Connectors
// on the older template record every collected form as not_collected").
func NotCollectedAll(partition string, regions []string, reason string) []FormCoverage {
	var out []FormCoverage
	for _, form := range collectedForms {
		if accountScopedForms[form] {
			out = append(out, NotCollected(form, AccountFormRegion(form, partition), reason))
			continue
		}
		for _, r := range sortedUniqueStrings(regions) {
			out = append(out, NotCollected(form, r, reason))
		}
	}
	sortCoverage(out)
	return out
}

// --- the collector ------------------------------------------------------------

// CollectorOptions bound collection (§3.9 "Budget"): reads are paginated,
// rate-limited per service and region, retried a bounded number of times when
// throttled, and stop at the deadline -- a form that cannot finish is
// partial, never silently complete.
type CollectorOptions struct {
	// MaxThrottleRetries is how many times one throttled call is retried on
	// top of the SDK's own retries. Default 2; negative means none.
	MaxThrottleRetries int
	// Backoff is the first retry's wait, doubled per retry. Default 1s.
	Backoff time.Duration
	// MinCallInterval spaces calls to one service in one region. Default
	// 50ms; negative means none.
	MinCallInterval time.Duration
	// MaxPages bounds one listing; a listing that hits it is partial. Default 10000.
	MaxPages int
	// Deadline, when set, is the scan budget: no call starts after it.
	Deadline time.Time
	// Sleep and Now are seams for tests.
	Sleep func(ctx context.Context, d time.Duration) error
	Now   func() time.Time
}

// ErrCollectionBudget means the scan budget ran out before a form finished.
var ErrCollectionBudget = errors.New("the scan budget ran out before this form finished")

// ResourcePolicyCollector enumerates and reads every collected form. One
// collector serves one scan; it is not safe for concurrent use.
type ResourcePolicyCollector struct {
	opts CollectorOptions
	last map[string]time.Time
}

// NewResourcePolicyCollector builds a collector with defaults filled in.
func NewResourcePolicyCollector(opts CollectorOptions) *ResourcePolicyCollector {
	switch {
	case opts.MaxThrottleRetries == 0:
		opts.MaxThrottleRetries = 2
	case opts.MaxThrottleRetries < 0:
		opts.MaxThrottleRetries = 0
	}
	if opts.Backoff == 0 {
		opts.Backoff = time.Second
	}
	switch {
	case opts.MinCallInterval == 0:
		opts.MinCallInterval = 50 * time.Millisecond
	case opts.MinCallInterval < 0:
		opts.MinCallInterval = 0
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 10000
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return ctx.Err()
			}
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &ResourcePolicyCollector{opts: opts, last: map[string]time.Time{}}
}

// CollectInput is what one connector's collection needs.
type CollectInput struct {
	AccountID string
	Partition string
	// SelectedRegions are the connector's regions: every regional form is
	// read in each.
	SelectedRegions []string
	// EnabledRegions, when known, are the regions enabled in the account;
	// each one not selected is recorded not_collected for every regional form
	// (§3.9 "Regions enabled in the account but not selected on the connector
	// are recorded not_collected").
	EnabledRegions []string
	Clients        ResourcePolicyClientsFunc
}

// ReasonRegionNotSelected is the not_collected reason of an enabled region
// the connector does not scan.
const ReasonRegionNotSelected = "region enabled in the account but not selected on the connector"

// Collect reads every collected form: account forms once, regional forms in
// every selected region, and records each enabled-but-unselected region
// not_collected. It never returns an error: every failure is a coverage fact
// (AccessDenied is denied, a throttle that outlasts the retries or a budget
// overrun is partial). The result is sorted by form and region.
func (c *ResourcePolicyCollector) Collect(ctx context.Context, in CollectInput) []FormCoverage {
	if in.Partition == "" {
		in.Partition = "aws"
	}
	clients := map[string]ResourcePolicyClients{}
	clientErr := map[string]error{}
	clientsFor := func(region string) (ResourcePolicyClients, error) {
		if cl, ok := clients[region]; ok {
			return cl, clientErr[region]
		}
		var cl ResourcePolicyClients
		var err error
		if in.Clients == nil {
			err = errors.New("no resource-policy clients")
		} else {
			cl, err = in.Clients(ctx, region)
		}
		clients[region], clientErr[region] = cl, err
		return cl, err
	}

	out := []FormCoverage{
		c.collectS3Buckets(ctx, in, clientsFor),
		c.collectMRAPs(ctx, in, clientsFor),
	}
	selected := sortedUniqueStrings(in.SelectedRegions)
	isSelected := map[string]bool{}
	for _, region := range selected {
		isSelected[region] = true
		cl, err := clientsFor(region)
		if err != nil {
			for _, form := range collectedForms {
				if !accountScopedForms[form] {
					out = append(out, FormCoverage{Form: form, Region: region, State: CoveragePartial,
						Reason: "no session could be opened in " + region + " (" + codeOf(err) + ")"})
				}
			}
			continue
		}
		out = append(out, c.collectRegion(ctx, in, region, cl)...)
	}
	for _, region := range sortedUniqueStrings(in.EnabledRegions) {
		if isSelected[region] {
			continue
		}
		for _, form := range collectedForms {
			if !accountScopedForms[form] {
				out = append(out, NotCollected(form, region, ReasonRegionNotSelected))
			}
		}
	}
	sortCoverage(out)
	return out
}

func (c *ResourcePolicyCollector) collectRegion(ctx context.Context, in CollectInput, region string, cl ResourcePolicyClients) []FormCoverage {
	var out []FormCoverage
	out = append(out, c.collectDirectoryBuckets(ctx, in, region, cl.S3))
	out = append(out, c.collectAccessPoints(ctx, in, region, cl.S3Control))
	out = append(out, c.collectObjectLambdaAccessPoints(ctx, in, region, cl.S3Control))
	out = append(out, c.collectKMSKeys(ctx, region, cl.KMS))
	out = append(out, c.collectQueues(ctx, in, region, cl.SQS))
	out = append(out, c.collectTopics(ctx, region, cl.SNS))
	out = append(out, c.collectLambda(ctx, region, cl.Lambda)...)
	out = append(out, c.collectLayers(ctx, region, cl.Lambda))
	out = append(out, c.collectSecrets(ctx, region, cl.Secrets))
	return out
}

// --- per-call discipline -----------------------------------------------------

// call runs one AWS call under the budget, the per-service pacing and the
// bounded throttle retry.
func (c *ResourcePolicyCollector) call(ctx context.Context, service, region string, fn func(context.Context) error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrCollectionBudget, err)
		}
		if !c.opts.Deadline.IsZero() && !c.opts.Now().Before(c.opts.Deadline) {
			return ErrCollectionBudget
		}
		key := service + "/" + region
		if c.opts.MinCallInterval > 0 {
			if last, ok := c.last[key]; ok {
				if wait := c.opts.MinCallInterval - c.opts.Now().Sub(last); wait > 0 {
					if err := c.opts.Sleep(ctx, wait); err != nil {
						return fmt.Errorf("%w: %v", ErrCollectionBudget, err)
					}
				}
			}
			c.last[key] = c.opts.Now()
		}
		err := fn(ctx)
		if err == nil || !isThrottleErr(err) || attempt >= c.opts.MaxThrottleRetries {
			return err
		}
		if serr := c.opts.Sleep(ctx, c.opts.Backoff<<attempt); serr != nil {
			return fmt.Errorf("%w: %v", ErrCollectionBudget, serr)
		}
	}
}

// deniedCodes are the codes an authorization refusal carries across the
// services read here (S3 AccessDenied, the JSON services'
// AccessDeniedException, SNS AuthorizationError, EC2 UnauthorizedOperation).
var deniedCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "UnauthorizedOperation": true,
	"AuthorizationError": true, "AuthorizationErrorException": true,
}

// throttleCodes are the codes a throttle carries across those services.
var throttleCodes = map[string]bool{
	"Throttling": true, "ThrottlingException": true, "RequestLimitExceeded": true,
	"TooManyRequestsException": true, "SlowDown": true, "RequestThrottled": true,
	"Throttled": true, "ThrottledException": true, "RequestThrottledException": true,
}

// absentCodes mean "this resource has no policy" (or no longer exists, so has
// none either): a successful read with nothing to record, never a failure.
// NoSuchBucketPolicy (buckets, directory buckets), NoSuchAccessPointPolicy
// (access points, Object Lambda access points), ResourceNotFoundException
// (Lambda GetPolicy / GetLayerVersionPolicy without a policy, §3.9; a secret
// deleted since the list), NotFoundException (KMS, as BucketPolicy/KeyPolicy
// above already read it), and the SQS / SNS codes of a queue or topic deleted
// since the list.
var absentCodes = map[string]bool{
	"NoSuchBucketPolicy": true, "NoSuchAccessPointPolicy": true, "NoSuchAccessPointPolicyForObjectLambda": true,
	"NoSuchMultiRegionAccessPointPolicy": true, "ResourceNotFoundException": true, "NotFoundException": true,
	"NotFound": true, "QueueDoesNotExist": true, "AWS.SimpleQueueService.NonExistentQueue": true,
}

func apiCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

func isDeniedErr(err error) bool { return err != nil && deniedCodes[apiCode(err)] }

func isThrottleErr(err error) bool {
	if err == nil {
		return false
	}
	return throttleCodes[apiCode(err)] || errors.Is(err, ErrThrottled)
}

func isAbsentErr(err error) bool {
	if err == nil {
		return false
	}
	return absentCodes[apiCode(err)] || isNoSuchPolicy(err)
}

// codeOf is the stable code a failure is reported under: AWS's own when it
// sent one, else ErrorCode's fixed label.
func codeOf(err error) string {
	if errors.Is(err, ErrCollectionBudget) {
		return "BudgetExhausted"
	}
	if c := apiCode(err); c != "" {
		return c
	}
	if c := resolverCode(err); c != "" {
		return c
	}
	return ErrorCode(err)
}

// --- the per-form accumulator ----------------------------------------------

type formAcc struct {
	cov        FormCoverage
	listCall   string
	listErr    error // the form's own listing failed (some pages may be in)
	notOffered bool  // the service's regional endpoint does not exist
	noClient   bool
	// per-parent listings (a function's versions/aliases, a layer's versions)
	childListAttempts, childListFailed, childListDenied int
	seen                                                map[string]bool
}

func newAcc(form, region, listCall string) *formAcc {
	return &formAcc{cov: FormCoverage{Form: form, Region: region}, listCall: listCall, seen: map[string]bool{}}
}

func (a *formAcc) noteFirst(call string, err error) {
	if a.cov.API == "" {
		a.cov.API, a.cov.ErrorCode = call, codeOf(err)
	}
}

// listFailed records the form's own listing failure. Only AWS's documented
// "not offered in this region" answer on the FIRST page is not a failure
// (FormNotOfferedIn, review P1-11): any other NXDOMAIN, a DNS timeout or a
// connection failure is a failed listing, so the form is partial.
func (a *formAcc) listFailed(err error) {
	if a.cov.Enumerated == 0 && FormNotOfferedIn(a.cov.Form, a.cov.Region, err) {
		a.notOffered = true
		return
	}
	a.listErr = err
	a.noteFirst(a.listCall, err)
}

// enumerate counts one listed resource, once.
func (a *formAcc) enumerate(arn string) bool {
	if arn == "" || a.seen[arn] {
		return false
	}
	a.seen[arn] = true
	a.cov.Enumerated++
	return true
}

// childListing records one parent's child listing outcome.
func (a *formAcc) childListing(parentARN, call string, err error) {
	a.childListAttempts++
	if err == nil {
		return
	}
	a.childListFailed++
	if isDeniedErr(err) {
		a.childListDenied++
	}
	a.noteFirst(call, err)
	a.cov.Failures = append(a.cov.Failures, ReadFailure{ARN: parentARN, Call: call, Code: codeOf(err),
		Denied: isDeniedErr(err), Throttled: isThrottleErr(err), Listing: true})
}

// read records one resource's policy read. text is the policy (empty with
// present=false for no policy).
func (a *formAcc) read(arn, call string, present bool, text string, err error, at time.Time) {
	switch {
	case err == nil:
		a.cov.ReadOK++
		a.cov.Reads = append(a.cov.Reads, PolicyRead{ARN: arn, Present: present && strings.TrimSpace(text) != "", Text: text, ReadAt: at})
	case isAbsentErr(err):
		a.cov.ReadOK++
		a.cov.Reads = append(a.cov.Reads, PolicyRead{ARN: arn, ReadAt: at})
	default:
		a.cov.ReadFailed++
		a.noteFirst(call, err)
		a.cov.Failures = append(a.cov.Failures, ReadFailure{ARN: arn, Call: call, Code: codeOf(err),
			Denied: isDeniedErr(err), Throttled: isThrottleErr(err)})
	}
}

// failureSummary is "<call> <code> xN, ..." over the failures, sorted: stable
// across scans of an unchanged failure.
func (a *formAcc) failureSummary() string {
	counts := map[string]int{}
	for _, f := range a.cov.Failures {
		counts[f.Call+" "+f.Code]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}

// finish decides the state (056: complete iff read_failed = 0 and
// read_ok = enumerated; every other state names its reason).
func (a *formAcc) finish() FormCoverage {
	cov := a.cov
	switch {
	case a.noClient:
		cov.State, cov.Reason = CoverageNotCollected, "no client for this service in "+cov.Region
	case a.notOffered:
		// AWS does not offer the service there (FormNotOfferedIn: its
		// documented regions exclude this one AND its endpoint there does not
		// exist), so the empty set is the whole set. The reason says why.
		cov.State, cov.Reason = CoverageComplete, "service not offered in "+cov.Region+" (not among the regions AWS documents it in)"
	case a.listErr != nil && errors.Is(a.listErr, ErrCollectionBudget):
		cov.State = CoveragePartial
		cov.Reason = fmt.Sprintf("%s stopped: %v (%d listed, %d read)", a.listCall, ErrCollectionBudget, cov.Enumerated, cov.ReadOK)
	case a.listErr != nil && isDeniedErr(a.listErr) && cov.Enumerated == 0:
		cov.State = CoverageDenied
		cov.Reason = fmt.Sprintf("%s refused (%s)", a.listCall, codeOf(a.listErr))
	case a.listErr != nil:
		cov.State = CoveragePartial
		cov.Reason = fmt.Sprintf("%s failed (%s) after %d listed; the set is not known to be whole",
			a.listCall, codeOf(a.listErr), cov.Enumerated)
	case a.childListFailed > 0 && a.childListDenied == a.childListAttempts && cov.Enumerated == 0:
		cov.State = CoverageDenied
		cov.Reason = "listing refused: " + a.failureSummary()
	case a.childListFailed > 0:
		cov.State = CoveragePartial
		cov.Reason = fmt.Sprintf("%d of %d listings failed (%s); the set is not known to be whole",
			a.childListFailed, a.childListAttempts, a.failureSummary())
	case cov.ReadFailed > 0 && cov.ReadOK == 0 && allDenied(cov.Failures):
		cov.State = CoverageDenied
		cov.Reason = fmt.Sprintf("every policy read refused (%s)", a.failureSummary())
	case cov.ReadFailed > 0:
		cov.State = CoveragePartial
		cov.Reason = fmt.Sprintf("%d of %d policies could not be read (%s)", cov.ReadFailed, cov.Enumerated, a.failureSummary())
	case cov.ReadOK != cov.Enumerated:
		cov.State = CoveragePartial
		cov.Reason = fmt.Sprintf("%d of %d policies read", cov.ReadOK, cov.Enumerated)
		if cov.ErrorCode == "BudgetExhausted" {
			cov.Reason += ": " + ErrCollectionBudget.Error()
		}
	default:
		cov.State = CoverageComplete
	}
	return cov
}

func allDenied(fs []ReadFailure) bool {
	for _, f := range fs {
		if !f.Denied {
			return false
		}
	}
	return len(fs) > 0
}

// pages drives one paginated listing: next is called with the previous
// token until it returns none -- or repeats a token, or the page bound is
// hit, both of which make the listing partial rather than loop.
func (c *ResourcePolicyCollector) pages(ctx context.Context, a *formAcc, service, region string,
	next func(ctx context.Context, token *string) (*string, error)) {
	var token *string
	seenTokens := map[string]bool{}
	for page := 0; ; page++ {
		if page >= c.opts.MaxPages {
			a.listFailed(fmt.Errorf("%w: more than %d pages", ErrCollectionBudget, c.opts.MaxPages))
			return
		}
		var nextToken *string
		err := c.call(ctx, service, region, func(ctx context.Context) error {
			var err error
			nextToken, err = next(ctx, token)
			return err
		})
		if err != nil {
			a.listFailed(err)
			return
		}
		t := aws.ToString(nextToken)
		if t == "" {
			return
		}
		if seenTokens[t] {
			a.listFailed(fmt.Errorf("%w: the listing repeated a page token", ErrCollectionBudget))
			return
		}
		seenTokens[t] = true
		token = aws.String(t)
	}
}

// readOne reads one policy under the call discipline. Once the budget is
// gone, the remaining resources are left unread (the form ends partial)
// rather than each counted as a failed read.
func (c *ResourcePolicyCollector) readOne(ctx context.Context, a *formAcc, service, region, arn, call string,
	fn func(ctx context.Context) (present bool, text string, err error)) {
	var present bool
	var text string
	err := c.call(ctx, service, region, func(ctx context.Context) error {
		var err error
		present, text, err = fn(ctx)
		return err
	})
	if errors.Is(err, ErrCollectionBudget) {
		a.noteFirst(call, err)
		return
	}
	a.read(arn, call, present, text, err, c.opts.Now().UTC())
}

// --- the forms --------------------------------------------------------------

func (c *ResourcePolicyCollector) collectS3Buckets(ctx context.Context, in CollectInput,
	clientsFor func(string) (ResourcePolicyClients, error)) FormCoverage {
	home := AccountFormRegion(FormS3Bucket, in.Partition)
	a := newAcc(FormS3Bucket, home, "s3:ListAllMyBuckets")
	cl, err := clientsFor(home)
	if err != nil {
		a.listFailed(err)
		return a.finish()
	}
	if cl.S3 == nil {
		a.noClient = true
		return a.finish()
	}
	type bucket struct{ name, region string }
	var buckets []bucket
	c.pages(ctx, a, "s3", home, func(ctx context.Context, token *string) (*string, error) {
		out, err := cl.S3.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: token, MaxBuckets: aws.Int32(1000)})
		if err != nil {
			return nil, err
		}
		for _, b := range out.Buckets {
			name := aws.ToString(b.Name)
			if a.enumerate("arn:" + in.Partition + ":s3:::" + name) {
				buckets = append(buckets, bucket{name: name, region: aws.ToString(b.BucketRegion)})
			}
		}
		return out.ContinuationToken, nil
	})
	for _, b := range buckets {
		arn := "arn:" + in.Partition + ":s3:::" + b.name
		region := b.region
		if region == "" {
			region = home
		}
		// GetBucketPolicy is addressed to the bucket's own region.
		rc, err := clientsFor(region)
		if err == nil && rc.S3 == nil {
			err = errors.New("no S3 client in " + region)
		}
		if err != nil {
			a.read(arn, "s3:GetBucketPolicy", false, "", err, c.opts.Now().UTC())
			continue
		}
		c.readOne(ctx, a, "s3", region, arn, "s3:GetBucketPolicy", func(ctx context.Context) (bool, string, error) {
			out, err := rc.S3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(b.name)})
			if err != nil {
				return false, "", err
			}
			return true, aws.ToString(out.Policy), nil
		})
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectMRAPs(ctx context.Context, in CollectInput,
	clientsFor func(string) (ResourcePolicyClients, error)) FormCoverage {
	region := AccountFormRegion(FormS3MultiRegionAccessPoint, in.Partition)
	a := newAcc(FormS3MultiRegionAccessPoint, region, "s3:ListMultiRegionAccessPoints")
	cl, err := clientsFor(region)
	if err != nil {
		a.listFailed(err)
		return a.finish()
	}
	if cl.S3Control == nil {
		a.noClient = true
		return a.finish()
	}
	type mrap struct{ name, arn string }
	var aps []mrap
	c.pages(ctx, a, "s3control", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := cl.S3Control.ListMultiRegionAccessPoints(ctx, &s3control.ListMultiRegionAccessPointsInput{
			AccountId: aws.String(in.AccountID), NextToken: token, MaxResults: 100})
		if err != nil {
			return nil, err
		}
		for _, ap := range out.AccessPoints {
			// A multi-region access point's ARN is built from its ALIAS
			// (arn:aws:s3::<account>:accesspoint/<alias>); the report does not
			// carry the ARN.
			arn := "arn:" + in.Partition + ":s3::" + in.AccountID + ":accesspoint/" + aws.ToString(ap.Alias)
			if aws.ToString(ap.Alias) != "" && a.enumerate(arn) {
				aps = append(aps, mrap{name: aws.ToString(ap.Name), arn: arn})
			}
		}
		return out.NextToken, nil
	})
	for _, ap := range aps {
		c.readOne(ctx, a, "s3control", region, ap.arn, "s3:GetMultiRegionAccessPointPolicy", func(ctx context.Context) (bool, string, error) {
			out, err := cl.S3Control.GetMultiRegionAccessPointPolicy(ctx, &s3control.GetMultiRegionAccessPointPolicyInput{
				AccountId: aws.String(in.AccountID), Name: aws.String(ap.name)})
			if err != nil {
				return false, "", err
			}
			// DECISION (T3.03b-2): the ESTABLISHED policy is the one in
			// effect; a proposed policy that has not propagated grants
			// nothing yet.
			if out.Policy == nil || out.Policy.Established == nil {
				return false, "", nil
			}
			text := aws.ToString(out.Policy.Established.Policy)
			return text != "", text, nil
		})
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectDirectoryBuckets(ctx context.Context, in CollectInput, region string, api S3CollectAPI) FormCoverage {
	a := newAcc(FormS3DirectoryBucket, region, "s3express:ListAllMyDirectoryBuckets")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	type bucket struct{ name, arn string }
	var buckets []bucket
	c.pages(ctx, a, "s3express", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListDirectoryBuckets(ctx, &s3.ListDirectoryBucketsInput{ContinuationToken: token, MaxDirectoryBuckets: aws.Int32(1000)})
		if err != nil {
			return nil, err
		}
		for _, b := range out.Buckets {
			name := aws.ToString(b.Name)
			arn := aws.ToString(b.BucketArn)
			if arn == "" {
				arn = "arn:" + in.Partition + ":s3express:" + region + ":" + in.AccountID + ":bucket/" + name
			}
			if a.enumerate(arn) {
				buckets = append(buckets, bucket{name: name, arn: arn})
			}
		}
		return out.ContinuationToken, nil
	})
	for _, b := range buckets {
		c.readOne(ctx, a, "s3express", region, b.arn, "s3express:GetBucketPolicy", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(b.name)})
			if err != nil {
				return false, "", err
			}
			return true, aws.ToString(out.Policy), nil
		})
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectAccessPoints(ctx context.Context, in CollectInput, region string, api S3ControlPolicyAPI) FormCoverage {
	a := newAcc(FormS3AccessPoint, region, "s3:ListAccessPoints")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	type ap struct{ name, arn string }
	var aps []ap
	c.pages(ctx, a, "s3control", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListAccessPoints(ctx, &s3control.ListAccessPointsInput{
			AccountId: aws.String(in.AccountID), NextToken: token, MaxResults: 1000})
		if err != nil {
			return nil, err
		}
		for _, p := range out.AccessPointList {
			name := aws.ToString(p.Name)
			arn := aws.ToString(p.AccessPointArn)
			if arn == "" {
				arn = "arn:" + in.Partition + ":s3:" + region + ":" + in.AccountID + ":accesspoint/" + name
			}
			if a.enumerate(arn) {
				aps = append(aps, ap{name: name, arn: arn})
			}
		}
		return out.NextToken, nil
	})
	for _, p := range aps {
		c.readOne(ctx, a, "s3control", region, p.arn, "s3:GetAccessPointPolicy", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetAccessPointPolicy(ctx, &s3control.GetAccessPointPolicyInput{
				AccountId: aws.String(in.AccountID), Name: aws.String(p.name)})
			if err != nil {
				return false, "", err
			}
			return true, aws.ToString(out.Policy), nil
		})
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectObjectLambdaAccessPoints(ctx context.Context, in CollectInput, region string, api S3ControlPolicyAPI) FormCoverage {
	a := newAcc(FormS3ObjectLambdaAccessPoint, region, "s3:ListAccessPointsForObjectLambda")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	type ap struct{ name, arn string }
	var aps []ap
	c.pages(ctx, a, "s3control", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListAccessPointsForObjectLambda(ctx, &s3control.ListAccessPointsForObjectLambdaInput{
			AccountId: aws.String(in.AccountID), NextToken: token, MaxResults: 1000})
		if err != nil {
			return nil, err
		}
		for _, p := range out.ObjectLambdaAccessPointList {
			name := aws.ToString(p.Name)
			arn := aws.ToString(p.ObjectLambdaAccessPointArn)
			if arn == "" {
				arn = "arn:" + in.Partition + ":s3-object-lambda:" + region + ":" + in.AccountID + ":accesspoint/" + name
			}
			if a.enumerate(arn) {
				aps = append(aps, ap{name: name, arn: arn})
			}
		}
		return out.NextToken, nil
	})
	for _, p := range aps {
		c.readOne(ctx, a, "s3control", region, p.arn, "s3:GetAccessPointPolicyForObjectLambda", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetAccessPointPolicyForObjectLambda(ctx, &s3control.GetAccessPointPolicyForObjectLambdaInput{
				AccountId: aws.String(in.AccountID), Name: aws.String(p.name)})
			if err != nil {
				return false, "", err
			}
			return true, aws.ToString(out.Policy), nil
		})
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectKMSKeys(ctx context.Context, region string, api KMSCollectAPI) FormCoverage {
	a := newAcc(FormKMSKey, region, "kms:ListKeys")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	var keys []string
	c.pages(ctx, a, "kms", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListKeys(ctx, &kms.ListKeysInput{Marker: token, Limit: aws.Int32(1000)})
		if err != nil {
			return nil, err
		}
		for _, k := range out.Keys {
			if arn := aws.ToString(k.KeyArn); a.enumerate(arn) {
				keys = append(keys, arn)
			}
		}
		if !out.Truncated {
			return nil, nil
		}
		return out.NextMarker, nil
	})
	for _, arn := range keys {
		c.readOne(ctx, a, "kms", region, arn, "kms:GetKeyPolicy", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(arn), PolicyName: aws.String("default")})
			if err != nil {
				return false, "", err
			}
			return true, aws.ToString(out.Policy), nil
		})
	}
	return a.finish()
}

// QueueARNFromURL derives a queue's ARN from its URL
// (https://sqs.<region>.amazonaws.com/<account>/<name>).
//
// DECISION (T3.03b-3): §3.9 reads a queue with AttributeNames=Policy ONLY, so
// the ARN is derived from the URL rather than requested as QueueArn. "" when
// the URL does not have that shape (the queue is then a read failure, never a
// guessed ARN).
func QueueARNFromURL(queueURL, region, partition string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(queueURL, "https://"), "http://")
	parts := strings.Split(u, "/")
	if len(parts) != 3 || len(parts[1]) != 12 || parts[2] == "" {
		return ""
	}
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return "arn:" + partition + ":sqs:" + region + ":" + parts[1] + ":" + parts[2]
}

func (c *ResourcePolicyCollector) collectQueues(ctx context.Context, in CollectInput, region string, api SQSPolicyAPI) FormCoverage {
	a := newAcc(FormSQSQueue, region, "sqs:ListQueues")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	type queue struct{ url, arn string }
	var queues []queue
	c.pages(ctx, a, "sqs", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListQueues(ctx, &sqs.ListQueuesInput{NextToken: token, MaxResults: aws.Int32(1000)})
		if err != nil {
			return nil, err
		}
		for _, u := range out.QueueUrls {
			arn := QueueARNFromURL(u, region, in.Partition)
			if arn == "" {
				// Listed, so counted; it cannot be named, so it is a failed
				// read rather than an invented ARN.
				if a.enumerate("url:" + u) {
					a.read(u, "sqs:ListQueues", false, "", errors.New("unrecognised queue URL"), c.opts.Now().UTC())
				}
				continue
			}
			if a.enumerate(arn) {
				queues = append(queues, queue{url: u, arn: arn})
			}
		}
		return out.NextToken, nil
	})
	for _, q := range queues {
		c.readOne(ctx, a, "sqs", region, q.arn, "sqs:GetQueueAttributes", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: aws.String(q.url), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy}})
			if err != nil {
				return false, "", err
			}
			text, ok := out.Attributes[string(sqstypes.QueueAttributeNamePolicy)]
			return ok && text != "", text, nil
		})
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectTopics(ctx context.Context, region string, api SNSPolicyAPI) FormCoverage {
	a := newAcc(FormSNSTopic, region, "sns:ListTopics")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	var topics []string
	c.pages(ctx, a, "sns", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListTopics(ctx, &sns.ListTopicsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, t := range out.Topics {
			if arn := aws.ToString(t.TopicArn); a.enumerate(arn) {
				topics = append(topics, arn)
			}
		}
		return out.NextToken, nil
	})
	for _, arn := range topics {
		c.readOne(ctx, a, "sns", region, arn, "sns:GetTopicAttributes", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: aws.String(arn)})
			if err != nil {
				return false, "", err
			}
			// Only the Policy attribute is kept; the rest is dropped here.
			text, ok := out.Attributes["Policy"]
			return ok && text != "", text, nil
		})
	}
	return a.finish()
}

// collectLambda reads lambda_function, lambda_function_version and
// lambda_alias from one function listing: the three forms share it, so a
// refused ListFunctions leaves all three unenumerated, each saying so.
func (c *ResourcePolicyCollector) collectLambda(ctx context.Context, region string, api LambdaPolicyAPI) []FormCoverage {
	fa := newAcc(FormLambdaFunction, region, "lambda:ListFunctions")
	va := newAcc(FormLambdaFunctionVersion, region, "lambda:ListFunctions")
	aa := newAcc(FormLambdaAlias, region, "lambda:ListFunctions")
	if api == nil {
		fa.noClient, va.noClient, aa.noClient = true, true, true
		return []FormCoverage{fa.finish(), va.finish(), aa.finish()}
	}
	type fn struct{ arn string }
	var fns []fn
	c.pages(ctx, fa, "lambda", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: token, MaxItems: aws.Int32(50)})
		if err != nil {
			return nil, err
		}
		for _, f := range out.Functions {
			if arn := aws.ToString(f.FunctionArn); fa.enumerate(arn) {
				fns = append(fns, fn{arn: arn})
			}
		}
		return out.NextMarker, nil
	})
	if fa.listErr != nil || fa.notOffered {
		// The children's listing IS the function listing.
		for _, sub := range []*formAcc{va, aa} {
			sub.listErr, sub.notOffered, sub.cov.API, sub.cov.ErrorCode = fa.listErr, fa.notOffered, fa.cov.API, fa.cov.ErrorCode
		}
	}
	for _, f := range fns {
		c.readOne(ctx, fa, "lambda", region, f.arn, "lambda:GetPolicy", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(f.arn)})
			if err != nil {
				return false, "", err
			}
			return true, aws.ToString(out.Policy), nil
		})

		// Published versions. DECISION (T3.03b-4): $LATEST is not a
		// published version and its policy IS the unqualified function's
		// (read above), so it is not listed again as a version.
		type ver struct{ version, arn string }
		var vers []ver
		sub := newAcc(FormLambdaFunctionVersion, region, "lambda:ListVersionsByFunction")
		c.pages(ctx, sub, "lambda", region, func(ctx context.Context, token *string) (*string, error) {
			out, err := api.ListVersionsByFunction(ctx, &lambda.ListVersionsByFunctionInput{
				FunctionName: aws.String(f.arn), Marker: token, MaxItems: aws.Int32(50)})
			if err != nil {
				return nil, err
			}
			for _, v := range out.Versions {
				version := aws.ToString(v.Version)
				if version == "" || version == "$LATEST" {
					continue
				}
				if arn := aws.ToString(v.FunctionArn); va.enumerate(arn) {
					vers = append(vers, ver{version: version, arn: arn})
				}
			}
			return out.NextMarker, nil
		})
		va.childListing(f.arn, "lambda:ListVersionsByFunction", sub.listErr)
		for _, v := range vers {
			c.readOne(ctx, va, "lambda", region, v.arn, "lambda:GetPolicy", func(ctx context.Context) (bool, string, error) {
				out, err := api.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(f.arn), Qualifier: aws.String(v.version)})
				if err != nil {
					return false, "", err
				}
				return true, aws.ToString(out.Policy), nil
			})
		}

		// Aliases: each is its own policy-bearing form (A39).
		type alias struct{ name, arn string }
		var aliases []alias
		sub = newAcc(FormLambdaAlias, region, "lambda:ListAliases")
		c.pages(ctx, sub, "lambda", region, func(ctx context.Context, token *string) (*string, error) {
			out, err := api.ListAliases(ctx, &lambda.ListAliasesInput{FunctionName: aws.String(f.arn), Marker: token, MaxItems: aws.Int32(50)})
			if err != nil {
				return nil, err
			}
			for _, al := range out.Aliases {
				if arn := aws.ToString(al.AliasArn); aa.enumerate(arn) {
					aliases = append(aliases, alias{name: aws.ToString(al.Name), arn: arn})
				}
			}
			return out.NextMarker, nil
		})
		aa.childListing(f.arn, "lambda:ListAliases", sub.listErr)
		for _, al := range aliases {
			c.readOne(ctx, aa, "lambda", region, al.arn, "lambda:GetPolicy", func(ctx context.Context) (bool, string, error) {
				out, err := api.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(f.arn), Qualifier: aws.String(al.name)})
				if err != nil {
					return false, "", err
				}
				return true, aws.ToString(out.Policy), nil
			})
		}
	}
	return []FormCoverage{fa.finish(), va.finish(), aa.finish()}
}

func (c *ResourcePolicyCollector) collectLayers(ctx context.Context, region string, api LambdaPolicyAPI) FormCoverage {
	a := newAcc(FormLambdaLayerVersion, region, "lambda:ListLayers")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	var layers []string
	c.pages(ctx, a, "lambda", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListLayers(ctx, &lambda.ListLayersInput{Marker: token, MaxItems: aws.Int32(50)})
		if err != nil {
			return nil, err
		}
		for _, l := range out.Layers {
			if arn := aws.ToString(l.LayerArn); arn != "" {
				layers = append(layers, arn)
			}
		}
		return out.NextMarker, nil
	})
	for _, layer := range sortedUniqueStrings(layers) {
		type lv struct {
			arn     string
			version int64
		}
		var versions []lv
		sub := newAcc(FormLambdaLayerVersion, region, "lambda:ListLayerVersions")
		c.pages(ctx, sub, "lambda", region, func(ctx context.Context, token *string) (*string, error) {
			out, err := api.ListLayerVersions(ctx, &lambda.ListLayerVersionsInput{LayerName: aws.String(layer), Marker: token, MaxItems: aws.Int32(50)})
			if err != nil {
				return nil, err
			}
			for _, v := range out.LayerVersions {
				if arn := aws.ToString(v.LayerVersionArn); a.enumerate(arn) {
					versions = append(versions, lv{arn: arn, version: v.Version})
				}
			}
			return out.NextMarker, nil
		})
		a.childListing(layer, "lambda:ListLayerVersions", sub.listErr)
		for _, v := range versions {
			c.readOne(ctx, a, "lambda", region, v.arn, "lambda:GetLayerVersionPolicy", func(ctx context.Context) (bool, string, error) {
				out, err := api.GetLayerVersionPolicy(ctx, &lambda.GetLayerVersionPolicyInput{
					LayerName: aws.String(layer), VersionNumber: aws.Int64(v.version)})
				if err != nil {
					return false, "", err
				}
				return true, aws.ToString(out.Policy), nil
			})
		}
	}
	return a.finish()
}

func (c *ResourcePolicyCollector) collectSecrets(ctx context.Context, region string, api SecretsPolicyAPI) FormCoverage {
	a := newAcc(FormSecretsManagerSecret, region, "secretsmanager:ListSecrets")
	if api == nil {
		a.noClient = true
		return a.finish()
	}
	var secrets []string
	c.pages(ctx, a, "secretsmanager", region, func(ctx context.Context, token *string) (*string, error) {
		out, err := api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: token, MaxResults: aws.Int32(100)})
		if err != nil {
			return nil, err
		}
		for _, s := range out.SecretList {
			if arn := aws.ToString(s.ARN); a.enumerate(arn) {
				secrets = append(secrets, arn)
			}
		}
		return out.NextToken, nil
	})
	for _, arn := range secrets {
		c.readOne(ctx, a, "secretsmanager", region, arn, "secretsmanager:GetResourcePolicy", func(ctx context.Context) (bool, string, error) {
			out, err := api.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String(arn)})
			if err != nil {
				return false, "", err
			}
			text := aws.ToString(out.ResourcePolicy)
			return text != "", text, nil
		})
	}
	return a.finish()
}

// --- helpers ------------------------------------------------------------------

func sortedUniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortCoverage(cs []FormCoverage) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Form != cs[j].Form {
			return cs[i].Form < cs[j].Form
		}
		return cs[i].Region < cs[j].Region
	})
}
