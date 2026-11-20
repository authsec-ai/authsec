package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* agent_review_keys.go issues temporary AWS keys to the agent review service
   (authsec-aws-agent-discovery), so it can read a customer account's
   CloudTrail and network logs for the workloads queued in
   cloud_workload.attrs.agent_review.

   AuthSec assumes the connector's discovery role itself, with the ExternalId
   from the secrets store, exactly as a scan does; the service only ever holds
   the resulting session, never the ExternalId. The session is narrowed by
   agentReviewSessionPolicy (read-only: the calls the service makes) and lasts
   an hour; the service asks again before it expires.

   It is not awsbroker: that broker sets SourceIdentity and session tags,
   which the discovery role's trust policy (sts:AssumeRole with the
   ExternalId condition only) does not allow. */

// Errors the keys route maps to its status codes.
var (
	ErrAgentReviewConnectorNotFound = errors.New("no AWS connector with this id in this workspace")
	ErrAgentReviewConnectorRevoked  = errors.New("the AWS connector is revoked")
	// ErrAgentReviewUnavailable: the connector is in error or its role or
	// ExternalId cannot be read right now; worth retrying later.
	ErrAgentReviewUnavailable = errors.New("AWS keys for this connector are unavailable right now")
	// ErrAgentReviewAssumeFailed: STS refused the role.
	ErrAgentReviewAssumeFailed = errors.New("assuming the connector's role failed")
)

// AgentReviewSessionSeconds is the keys' lifetime (the AWS default maximum
// of a role session).
const AgentReviewSessionSeconds = 3600

// agentReviewSessionPolicy limits the session to the reads the review
// service makes. The effective permissions are this AND the discovery role's.
const agentReviewSessionPolicy = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AgentReviewReadOnly",
    "Effect": "Allow",
    "Action": [
      "cloudtrail:LookupEvents",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "logs:StopQuery",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeFlowLogs",
      "lambda:GetFunctionConfiguration",
      "ecs:ListClusters",
      "ecs:ListTasks",
      "ecs:DescribeTasks",
      "ecs:DescribeTaskDefinition",
      "route53resolver:ListResolverQueryLogConfigAssociations",
      "route53resolver:ListResolverQueryLogConfigs"
    ],
    "Resource": "*"
  }]
}`

// AgentReviewCredentials are returned to the service once and never stored.
type AgentReviewCredentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
	// RoleARN is the connector's role, for the audit record (not a secret).
	RoleARN string `json:"-"`
}

// AgentReviewKeys issues the service's keys for one connector.
type AgentReviewKeys struct {
	onboarding *AWSOnboardingService
	newSTS     func(ctx context.Context, region string) (awsbroker.STSAPI, error)
}

// NewAgentReviewKeys issues keys with AuthSec's ambient AWS identity, the
// principal every discovery role trusts.
func NewAgentReviewKeys(onboarding *AWSOnboardingService) *AgentReviewKeys {
	return &AgentReviewKeys{onboarding: onboarding, newSTS: ambientSTS}
}

// WithSTS replaces the STS client (tests).
func (k *AgentReviewKeys) WithSTS(f func(ctx context.Context, region string) (awsbroker.STSAPI, error)) *AgentReviewKeys {
	k.newSTS = f
	return k
}

func ambientSTS(ctx context.Context, region string) (awsbroker.STSAPI, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region),
		awsconfig.WithRetryMaxAttempts(3), awsconfig.WithRetryMode(aws.RetryModeStandard))
	if err != nil {
		return nil, fmt.Errorf("AuthSec has no AWS identity of its own: %w", err)
	}
	return sts.NewFromConfig(cfg), nil
}

// Issue assumes the connector's discovery role for the review service. The
// connector is read under row-level security for ws, so another workspace's
// connector is ErrAgentReviewConnectorNotFound; the ExternalId is read from
// the secrets store after that transaction.
func (k *AgentReviewKeys) Issue(ctx context.Context, ws, connectorID uuid.UUID) (*AgentReviewCredentials, error) {
	var row *models.CloudConnector
	if err := tenancy.InWorkspaceRead(ctx, k.onboarding.db, ws, func(tx *gorm.DB) error {
		var err error
		row, err = repositories.NewCloudConnectorRepository(tx).Get(ws, connectorID)
		return err
	}); err != nil || row == nil || row.WorkspaceID != ws || row.Provider != models.CloudProviderAWS {
		return nil, ErrAgentReviewConnectorNotFound
	}
	switch row.Status {
	case models.CloudConnectorActive:
	case models.CloudConnectorRevoked:
		return nil, ErrAgentReviewConnectorRevoked
	default: // error: the next good scan clears it
		return nil, ErrAgentReviewUnavailable
	}
	_, req, err := k.onboarding.assumeRequestForConnector(ws, row)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentReviewUnavailable, err)
	}
	return k.assume(ctx, req.RoleARN, req.ExternalID, req.Region, connectorID)
}

func (k *AgentReviewKeys) assume(ctx context.Context, roleARN, externalID, region string, connectorID uuid.UUID) (*AgentReviewCredentials, error) {
	api, err := k.newSTS(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentReviewUnavailable, err)
	}
	out, err := api.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(agentReviewSessionName(connectorID)),
		ExternalId:      aws.String(externalID),
		Policy:          aws.String(agentReviewSessionPolicy),
		DurationSeconds: aws.Int32(AgentReviewSessionSeconds),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentReviewAssumeFailed, err)
	}
	if out.Credentials == nil {
		return nil, fmt.Errorf("%w: sts:AssumeRole returned no credentials", ErrAgentReviewAssumeFailed)
	}
	return &AgentReviewCredentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
		Expiration:      aws.ToTime(out.Credentials.Expiration).UTC(),
		RoleARN:         roleARN,
	}, nil
}

// agentReviewSessionName names the session in the customer's CloudTrail, so
// the service's reads are told apart from a scan's.
func agentReviewSessionName(connectorID uuid.UUID) string {
	return "authsec-agent-review-" + strings.ReplaceAll(connectorID.String(), "-", "")[:16]
}
