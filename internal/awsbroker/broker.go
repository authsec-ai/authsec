// Package awsbroker obtains short-lived AWS credentials for an agent with
// sts:AssumeRole on a customer's opted-in broker role, narrowed by a session
// policy and attributed by session name, session tags and SourceIdentity
// (Phase 3 R3, requirement R-08 moved from R2 by DECISION R2-1; DECISION
// R3-12 in internal/igagov/r3.go).
//
// UNVERIFIED: never run against an AWS account. The calls are the documented
// sts:AssumeRole parameters (aws-sdk-go-v2 sts types); whether a given broker
// role's trust policy admits TagSession and SetSourceIdentity, the packed
// policy size of real session policies, and how the session name and tags
// appear in the customer's CloudTrail are to be proven in the lab.
package awsbroker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// Request is one brokered session.
type Request struct {
	RoleARN         string
	ExternalID      string
	Region          string
	SessionName     string
	SourceIdentity  string
	SessionPolicy   string
	DurationSeconds int32
	Tags            map[string]string
}

// Credentials are returned to the agent once and never stored.
type Credentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
	AssumedRoleARN  string    `json:"assumed_role_arn"`
	AssumedRoleID   string    `json:"assumed_role_id"`
	PackedPolicyPct int32     `json:"packed_policy_size_percent"`
}

// Broker assumes the role.
type Broker interface {
	Assume(ctx context.Context, req Request) (*Credentials, error)
}

// STSAPI is the STS call the live broker makes.
type STSAPI interface {
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

var (
	reSessionName = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	reSourceID    = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	reTag         = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)
)

// Validate checks a request before any network call.
func Validate(req Request) error {
	switch {
	case req.RoleARN == "" || req.ExternalID == "":
		return errors.New("role and external id are required")
	case !reSessionName.MatchString(req.SessionName):
		return fmt.Errorf("session name %q is not valid", req.SessionName)
	case !reSourceID.MatchString(req.SourceIdentity):
		return fmt.Errorf("source identity %q is not valid", req.SourceIdentity)
	case req.DurationSeconds < 900 || req.DurationSeconds > 3600:
		return fmt.Errorf("duration %d is outside 900..3600", req.DurationSeconds)
	case req.SessionPolicy == "":
		return errors.New("a session policy is required")
	case len(req.Tags) > 50:
		return errors.New("at most 50 session tags")
	}
	for k, v := range req.Tags {
		if len(k) == 0 || len(k) > 128 || len(v) > 256 || !reTag.MatchString(k) || !reTag.MatchString(v) {
			return fmt.Errorf("session tag %q is not valid", k)
		}
	}
	return nil
}

// Live calls STS with AuthSec's own (ambient) AWS identity, the principal the
// broker role trusts with the connector's ExternalId.
type Live struct {
	// api, when set, replaces the STS client built from the ambient config.
	api STSAPI
}

// NewLive builds the live broker.
func NewLive() *Live { return &Live{} }

// NewWithAPI builds a broker over a given STS client.
func NewWithAPI(api STSAPI) *Live { return &Live{api: api} }

// Assume implements Broker.
func (l *Live) Assume(ctx context.Context, req Request) (*Credentials, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	api := l.api
	if api == nil {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(req.Region),
			awsconfig.WithRetryMaxAttempts(3), awsconfig.WithRetryMode(aws.RetryModeStandard))
		if err != nil {
			return nil, fmt.Errorf("AuthSec has no AWS identity of its own: %w", err)
		}
		api = sts.NewFromConfig(cfg)
	}
	tags := make([]ststypes.Tag, 0, len(req.Tags))
	for k, v := range req.Tags {
		tags = append(tags, ststypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	out, err := api.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(req.RoleARN),
		RoleSessionName: aws.String(req.SessionName),
		ExternalId:      aws.String(req.ExternalID),
		Policy:          aws.String(req.SessionPolicy),
		DurationSeconds: aws.Int32(req.DurationSeconds),
		SourceIdentity:  aws.String(req.SourceIdentity),
		Tags:            tags,
	})
	if err != nil {
		return nil, fmt.Errorf("sts:AssumeRole: %w", err)
	}
	if out.Credentials == nil {
		return nil, errors.New("sts:AssumeRole returned no credentials")
	}
	c := &Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
		Expiration:      aws.ToTime(out.Credentials.Expiration),
		PackedPolicyPct: aws.ToInt32(out.PackedPolicySize),
	}
	if u := out.AssumedRoleUser; u != nil {
		c.AssumedRoleARN, c.AssumedRoleID = aws.ToString(u.Arn), aws.ToString(u.AssumedRoleId)
	}
	return c, nil
}

// Fake records requests and returns fixed credentials (tests).
type Fake struct {
	Requests []Request
	Fail     error
}

// Assume implements Broker.
func (f *Fake) Assume(_ context.Context, req Request) (*Credentials, error) {
	if err := Validate(req); err != nil {
		return nil, err
	}
	f.Requests = append(f.Requests, req)
	if f.Fail != nil {
		return nil, f.Fail
	}
	return &Credentials{AccessKeyID: "ASIAFAKE", SecretAccessKey: "fake", SessionToken: "fake",
		Expiration:     time.Now().Add(time.Duration(req.DurationSeconds) * time.Second),
		AssumedRoleARN: req.RoleARN + "/" + req.SessionName}, nil
}
