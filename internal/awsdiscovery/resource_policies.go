package awsdiscovery

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
		return ResourcePolicy{}, callErr(call, readErr)
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
