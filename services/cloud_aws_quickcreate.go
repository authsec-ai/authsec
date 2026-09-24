package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// AWS Quick Create onboarding: the customer picks AWS Regions, clicks "Launch
// in AWS", ticks the IAM acknowledgement and clicks Create stack. Nothing is
// pasted back.
//
// How the pieces fit:
//
//  1. StartSession mints an ExternalId (the existing MintExternalID), names the
//     stack and role, and stores a short-lived session in Redis. The Quick
//     Create link it returns pre-fills every template parameter.
//  2. The stack's Custom::AuthSecRegistration resource makes CloudFormation
//     publish a Create request to AuthSec's SNS topic in the stack's region,
//     which delivers to one central SQS queue.
//  3. HandleCallbackMessage (driven by the SQS worker) finds the session by the
//     ExternalId, checks the request against it, and connects the account with
//     the EXISTING Onboard() — the same AssumeRole + GetCallerIdentity proof the
//     manual flow uses. Then it answers CloudFormation.
//
// The callback is never proof by itself. The topic accepts publishes from any
// AWS account, so a message proves nothing until the role it names has been
// assumed with the session's ExternalId and the account read back from AWS.
//
// The ExternalId doubles as the correlation value. Quick Create ignores NoEcho
// parameters, so a separate secret token could not be pre-filled either, and a
// non-NoEcho token would sit in the same URL and stack parameters as the
// ExternalId — no more secret than it. The ExternalId is already unique per
// session and HMAC-bound to the workspace.

// Deployment settings. Read once per construction; see LoadAWSCallbackConfig.
const (
	envAWSCallbackTopics    = "AUTHSEC_AWS_CFN_CALLBACK_TOPICS"
	envAWSCallbackQueueURL  = "AUTHSEC_AWS_CFN_CALLBACK_QUEUE_URL"
	envAWSTemplateBaseURL   = "AUTHSEC_AWS_TEMPLATE_BASE_URL"
	envAWSTemplateOverrides = "AUTHSEC_AWS_TEMPLATE_URL_OVERRIDES"
	envAWSOptInScanRegions  = "AUTHSEC_AWS_OPTIN_SCAN_REGIONS"
)

const (
	// awsOnbSessionTTL is how long a launch link stays usable. Short, because
	// whoever holds a live link's ExternalId could connect their own account to
	// this workspace until it is used.
	awsOnbSessionTTL = time.Hour
	// awsOnbTerminalTTL keeps a finished session readable, and its ExternalId
	// index resolvable, so the console can show the result and a late duplicate
	// callback is answered consistently.
	awsOnbTerminalTTL = time.Hour
	// awsOnbLockTTL is short and refreshed every awsOnbLockRefresh while the
	// holder works, so a worker that crashes releases the session within
	// minutes instead of stranding it past the stack's ServiceTimeout.
	awsOnbLockTTL     = 3 * time.Minute
	awsOnbLockRefresh = time.Minute
	// awsOnbActiveTTL is the floor for a session's lifetime while a callback is
	// being handled, so its ExternalId index cannot expire mid-onboarding.
	awsOnbActiveTTL = 15 * time.Minute
	// awsCallbackDeadline is how long after CloudFormation published a request
	// AuthSec keeps retrying before it answers anyway. 60s inside the template's
	// ServiceTimeout of 600s, so the final answer always arrives before
	// CloudFormation gives up on its own.
	awsCallbackDeadline = 540 * time.Second
	// awsAnswerReserve is kept free before the deadline for the answer itself:
	// saving the session and up to three PUTs to CloudFormation. No Onboard
	// attempt may still be running once the reserve starts.
	awsAnswerReserve = 40 * time.Second
	// awsIAMPropagationBudget bounds retrying AccessDenied right after the role
	// was created. A new role's trust policy takes a few seconds to be honoured
	// by STS; a trust policy that is simply wrong never will be.
	awsIAMPropagationBudget = 90 * time.Second
	// awsAuthSecErrorBudget bounds retrying an AuthSec-side failure that does
	// not heal by itself — Vault unreachable or unmounted, the database, AuthSec's
	// own AWS credentials. Retrying those to the deadline only made the customer
	// watch "Verifying…" for nine minutes before the same failure. Throttling
	// and timeouts, which do heal, are still retried to the deadline.
	awsAuthSecErrorBudget = 60 * time.Second
	// awsCallbackMaxAttempts caps callback attempts per session, so a flood of
	// forged messages carrying a leaked ExternalId cannot drive AssumeRole calls.
	awsCallbackMaxAttempts = 5
	// Regional probes: bounded in parallelism and in time, and run AFTER the
	// answer to CloudFormation so the customer's stack is never held for them.
	awsProbeConcurrency = 8
	awsProbeTimeout     = 20 * time.Second
	// awsTemplateCheckTTL caches a successful template HEAD check.
	awsTemplateCheckTTL = 10 * time.Minute
	// awsTemplateCheckFailTTL caches a failed one, briefly, so a broken bucket
	// is not re-probed on every launch.
	awsTemplateCheckFailTTL = time.Minute
)

// Session statuses.
const (
	AWSOnbPending   = "pending"
	AWSOnbVerifying = "verifying"
	AWSOnbConnected = "connected"
	AWSOnbFailed    = "failed"
)

// Stable error codes. The same code appears in the session, the Reason a
// customer reads in their stack events, the logs and the console copy.
const (
	AWSOnbCodeNotConfigured      = "aws_onb_not_configured"
	AWSOnbCodeInvalidRegions     = "aws_onb_invalid_regions"
	AWSOnbCodeStoreUnavailable   = "aws_onb_session_store_unavailable"
	AWSOnbCodeTemplateMissing    = "aws_onb_template_missing"
	AWSOnbCodeUnknownLink        = "aws_onb_unknown_link"
	AWSOnbCodeWrongWorkspace     = "aws_onb_wrong_workspace"
	AWSOnbCodeRegionMismatch     = "aws_onb_region_mismatch"
	AWSOnbCodeAccountMismatch    = "aws_onb_account_mismatch"
	AWSOnbCodeInvalidRequest     = "aws_onb_invalid_request"
	AWSOnbCodeLinkUsed           = "aws_onb_link_used"
	AWSOnbCodeTooManyAttempts    = "aws_onb_too_many_attempts"
	AWSOnbCodeAssumeDenied       = "aws_onb_assume_denied"
	AWSOnbCodeAuthSecUnavailable = "aws_onb_authsec_unavailable"
)

// awsOnbReasons is what a customer reads in their CloudFormation stack events
// when AuthSec answers FAILED. Short, actionable, and free of internals; the
// "AuthSec ref" appended to each lets support find the session.
var awsOnbReasons = map[string]string{
	AWSOnbCodeUnknownLink:        "This AuthSec launch link has expired, or the values AuthSec filled in were changed. Start again in AuthSec.",
	AWSOnbCodeWrongWorkspace:     "This AuthSec launch link is not valid. Start again in AuthSec.",
	AWSOnbCodeRegionMismatch:     "The stack was created in a different AWS Region than AuthSec expected. Do not switch Regions in the console; start again in AuthSec.",
	AWSOnbCodeAccountMismatch:    "The role and the stack are in different AWS accounts.",
	AWSOnbCodeInvalidRequest:     "The stack sent AuthSec an invalid role. Start again in AuthSec.",
	AWSOnbCodeLinkUsed:           "This AuthSec launch link was already used. Start again in AuthSec.",
	AWSOnbCodeTooManyAttempts:    "Too many attempts for this AuthSec launch link. Start again in AuthSec.",
	AWSOnbCodeAssumeDenied:       "AuthSec could not assume the role. Check the trust policy and ExternalId were not changed.",
	AWSOnbCodeAuthSecUnavailable: "AuthSec could not complete setup. Try again later.",
}

// AWSOnbError is a failure with a stable code.
type AWSOnbError struct {
	Code    string
	Message string
}

func (e *AWSOnbError) Error() string { return e.Message }

func onbErr(code, format string, args ...any) *AWSOnbError {
	return &AWSOnbError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ErrAWSOnbSessionNotFound means no session with that id exists in this
// workspace — expired, never created, or another workspace's.
var ErrAWSOnbSessionNotFound = errors.New("onboarding session not found")

// AWSRegionProbe is the result of checking one scan region after connecting.
type AWSRegionProbe struct {
	Status string `json:"status"` // connected | not_reachable
	Reason string `json:"reason,omitempty"`
}

// awsStoredResult is the answer already given to one CloudFormation request,
// replayed verbatim on a duplicate delivery.
type awsStoredResult struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// AWSOnboardingSession is one Quick Create launch.
type AWSOnboardingSession struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	CreatedBy   string    `json:"created_by"`
	// CreatorUserID is the signed-in user who started the launch (CreatedBy
	// may be a workspace-level client id). Empty for sessions started before
	// it was recorded.
	CreatorUserID    string   `json:"creator_user_id,omitempty"`
	ExternalID       string   `json:"external_id"`
	Regions          []string `json:"regions"`
	DeploymentRegion string   `json:"deployment_region"`
	Suffix           string   `json:"suffix"`
	StackName        string   `json:"stack_name"`
	RoleName         string   `json:"role_name"`
	QuickCreateURL   string   `json:"quick_create_url"`

	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`

	AccountID         string                    `json:"account_id,omitempty"`
	RoleARN           string                    `json:"role_arn,omitempty"`
	PreviousRoleARN   string                    `json:"previous_role_arn,omitempty"`
	ConnectorID       *uuid.UUID                `json:"connector_id,omitempty"`
	RegionStatus      map[string]AWSRegionProbe `json:"region_status,omitempty"`
	ResponsePutFailed bool                      `json:"response_put_failed,omitempty"`

	Attempts int                        `json:"attempts"`
	Results  map[string]awsStoredResult `json:"results,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// TerminalAt is when the session first became connected or failed. Its
	// lifetime is fixed from that moment, so later messages (duplicates, or
	// forgeries carrying a leaked ExternalId) can never keep it alive.
	TerminalAt *time.Time `json:"terminal_at,omitempty"`
}

// AWSOnboardingSessionView is what the console is shown: the session without
// its bookkeeping.
type AWSOnboardingSessionView struct {
	ID                uuid.UUID                 `json:"id"`
	Status            string                    `json:"status"`
	Code              string                    `json:"code,omitempty"`
	Message           string                    `json:"message,omitempty"`
	ExternalID        string                    `json:"external_id"`
	Regions           []string                  `json:"regions"`
	DeploymentRegion  string                    `json:"deployment_region"`
	StackName         string                    `json:"stack_name"`
	RoleName          string                    `json:"role_name"`
	QuickCreateURL    string                    `json:"quick_create_url"`
	AccountID         string                    `json:"account_id,omitempty"`
	RoleARN           string                    `json:"role_arn,omitempty"`
	PreviousRoleARN   string                    `json:"previous_role_arn,omitempty"`
	ConnectorID       *uuid.UUID                `json:"connector_id,omitempty"`
	RegionStatus      map[string]AWSRegionProbe `json:"region_status,omitempty"`
	ResponsePutFailed bool                      `json:"response_put_failed,omitempty"`
	CreatedAt         time.Time                 `json:"created_at"`
	ExpiresAt         time.Time                 `json:"expires_at"`
}

// View strips the bookkeeping.
// StartedBy reports whether the caller is the user who started the session.
// The per-user id decides when it was recorded; only an older session without
// one falls back to comparing the actor.
func (s *AWSOnboardingSession) StartedBy(userID, actor string) bool {
	if s.CreatorUserID != "" {
		return userID != "" && userID == s.CreatorUserID
	}
	return actor != "" && actor == s.CreatedBy
}

func (s *AWSOnboardingSession) View() AWSOnboardingSessionView {
	return AWSOnboardingSessionView{
		ID: s.ID, Status: s.Status, Code: s.Code, Message: s.Message,
		ExternalID: s.ExternalID, Regions: s.Regions, DeploymentRegion: s.DeploymentRegion,
		StackName: s.StackName, RoleName: s.RoleName, QuickCreateURL: s.QuickCreateURL,
		AccountID: s.AccountID, RoleARN: s.RoleARN, PreviousRoleARN: s.PreviousRoleARN,
		ConnectorID: s.ConnectorID, RegionStatus: s.RegionStatus,
		ResponsePutFailed: s.ResponsePutFailed, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
	}
}

func (s *AWSOnboardingSession) terminal() bool {
	return s.Status == AWSOnbConnected || s.Status == AWSOnbFailed
}

// ref is the short id a customer can quote to support.
func (s *AWSOnboardingSession) ref() string { return s.Suffix }

// CallbackOutcome tells the SQS worker what to do with a message.
type CallbackOutcome int

const (
	// CallbackDone: handled (answered, or deliberately dropped). Delete it.
	CallbackDone CallbackOutcome = iota
	// CallbackRetry: a transient AuthSec-side failure. Leave it for redelivery.
	CallbackRetry
	// CallbackReject: malformed or not ours. Never answered; it is left to reach
	// the DLQ, where it raises an alarm.
	CallbackReject
)

func (o CallbackOutcome) String() string {
	switch o {
	case CallbackDone:
		return "done"
	case CallbackRetry:
		return "retry"
	default:
		return "reject"
	}
}

// LoadAWSCallbackConfig reads the automatic-onboarding settings from the
// environment. Unset means disabled, which is valid.
func LoadAWSCallbackConfig() (awsdiscovery.CallbackConfig, error) {
	return awsdiscovery.ParseCallbackConfig(
		os.Getenv(envAWSCallbackTopics),
		os.Getenv(envAWSCallbackQueueURL),
		os.Getenv(envAWSTemplateBaseURL),
		os.Getenv(envAWSTemplateOverrides),
		os.Getenv(envAWSOptInScanRegions),
	)
}

// AWSQuickCreateService owns Quick Create sessions and the callback. It wraps
// AWSOnboardingService rather than changing it: every connection it makes goes
// through the existing Onboard().
type AWSQuickCreateService struct {
	onboarding *AWSOnboardingService
	redis      *redis.Client
	cfg        awsdiscovery.CallbackConfig
	principal  string
	http       *http.Client
	now        func() time.Time

	// Seams, defaulting to the real thing.
	onboard       func(ctx context.Context, ws uuid.UUID, in AWSOnboardInput, actor string) (*models.CloudConnector, bool, error)
	existing      func(ws uuid.UUID, accountID string) (*models.CloudConnector, error)
	verifier      awsdiscovery.Verifier
	templateCheck func(ctx context.Context, templateURL string) error
	sleep         func(ctx context.Context, d time.Duration) error
}

// NewAWSQuickCreateService constructs the service. principal is the AuthSec
// AWS principal customers' trust policies name.
func NewAWSQuickCreateService(
	onboarding *AWSOnboardingService, rc *redis.Client, cfg awsdiscovery.CallbackConfig, principal string,
) *AWSQuickCreateService {
	s := &AWSQuickCreateService{
		onboarding: onboarding,
		redis:      rc,
		cfg:        cfg,
		principal:  strings.TrimSpace(principal),
		http:       awsdiscovery.NewCFNResponseClient(),
		now:        time.Now,
		sleep:      sleepCtx,
	}
	if onboarding != nil {
		s.onboard = onboarding.Onboard
		s.verifier = onboarding.verifier
		s.existing = func(ws uuid.UUID, accountID string) (*models.CloudConnector, error) {
			c, err := onboarding.repo.GetByScope(ws, models.CloudProviderAWS, accountID)
			if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
				return nil, nil
			}
			return c, err
		}
	}
	s.templateCheck = newTemplateChecker(s.now)
	return s
}

// Config exposes the settings the console needs.
func (s *AWSQuickCreateService) Config() awsdiscovery.CallbackConfig { return s.cfg }

// Available reports whether automatic onboarding can be offered right now.
func (s *AWSQuickCreateService) Available() bool {
	return s.cfg.Enabled() && s.principal != "" && s.redis != nil
}

/* --------------------------------- sessions -------------------------------- */

func awsOnbSessionKey(id uuid.UUID) string         { return "aws:onb:session:" + id.String() }
func awsOnbExtKey(externalID string) string        { return "aws:onb:ext:" + sha256Hex(externalID) }
func awsOnbLockKey(id uuid.UUID) string            { return "aws:onb:lock:" + id.String() }
func sha256Hex(v string) string                    { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func shortHash(v string) string                    { return sha256Hex(v)[:8] }
func awsOnbStackName(suffix string) string         { return "AuthSec-Discovery-" + suffix }
func awsOnbRoleName(suffix string) string          { return "AuthSecCloudDiscovery-" + suffix }
func awsOnbPhysicalID(id uuid.UUID) string         { return "authsec-" + id.String() }
func awsOnbResultKey(stackID, reqID string) string { return stackID + "|" + reqID }

// newSuffix returns 8 random lowercase base32 characters: valid in both a stack
// name and a role name, and shared by the two so an old stack can be named
// from its role.
func newSuffix() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.EncodeToString(b)), nil
}

// StartSession validates the operator's choice of AWS Regions and returns a
// session carrying the Quick Create link.
//
// regions are the regions to SCAN. deploymentRegion is where the one stack is
// created (the IAM role is global, so one stack covers every scan region);
// empty picks the first selected region that can host the stack.
func (s *AWSQuickCreateService) StartSession(
	ctx context.Context, workspaceID uuid.UUID, actor string, regions []string, deploymentRegion string,
) (*AWSOnboardingSession, error) {
	return s.StartSessionFor(ctx, workspaceID, actor, "", regions, deploymentRegion)
}

// StartSessionFor is StartSession that also records the signed-in user who
// started it. actor can be a workspace-level client id shared by every user,
// so the per-user id is what decides who may see the launch link again.
func (s *AWSQuickCreateService) StartSessionFor(
	ctx context.Context, workspaceID uuid.UUID, actor, creatorUserID string, regions []string, deploymentRegion string,
) (*AWSOnboardingSession, error) {
	if !s.cfg.Enabled() || s.principal == "" {
		return nil, onbErr(AWSOnbCodeNotConfigured, "automatic AWS onboarding is not configured on this deployment")
	}
	if s.redis == nil {
		return nil, onbErr(AWSOnbCodeStoreUnavailable, "automatic setup is temporarily unavailable")
	}

	regs, err := normalizeRegions(regions)
	if err != nil {
		return nil, onbErr(AWSOnbCodeInvalidRegions, "%v", err)
	}
	for _, r := range regs {
		if p := awsdiscovery.PartitionForRegion(r); p != awsdiscovery.PartitionAWS {
			return nil, onbErr(AWSOnbCodeInvalidRegions,
				"%s is a GovCloud or China region, which cannot be onboarded automatically; use manual setup", r)
		}
		if !s.cfg.ScanRegionSupported(r) {
			return nil, onbErr(AWSOnbCodeInvalidRegions,
				"%s is an opt-in region AuthSec cannot scan on this deployment yet", r)
		}
	}

	dr := strings.ToLower(strings.TrimSpace(deploymentRegion))
	if dr != "" {
		if _, ok := s.cfg.TopicFor(dr); !ok {
			return nil, onbErr(AWSOnbCodeInvalidRegions,
				"the stack cannot be created in %s; choose one of %s", dr,
				strings.Join(s.cfg.SupportedDeploymentRegions(), ", "))
		}
	} else {
		for _, r := range regs {
			if _, ok := s.cfg.TopicFor(r); ok {
				dr = r
				break
			}
		}
		if dr == "" {
			dr = s.cfg.SupportedDeploymentRegions()[0]
		}
	}
	// The deployment region goes first when it is also scanned: Onboard probes
	// regions[0], and the stack's own region is the one most certain to answer.
	for i, r := range regs {
		if r == dr && i > 0 {
			regs = append([]string{dr}, append(regs[:i:i], regs[i+1:]...)...)
			break
		}
	}
	// When the stack's region is not scanned, never let an opt-in region be the
	// one Onboard probes: if the customer has not enabled it, the whole
	// connection would fail on a region that is only in scope, not required.
	if awsdiscovery.IsOptInRegion(regs[0]) {
		for i, r := range regs {
			if !awsdiscovery.IsOptInRegion(r) {
				regs = append([]string{r}, append(regs[:i:i], regs[i+1:]...)...)
				break
			}
		}
	}

	templateURL := s.cfg.TemplateURLFor(dr)
	if err := s.templateCheck(ctx, templateURL); err != nil {
		log.Printf("[aws-onb] ALERT stage=start code=%s region=%s template=%s err=%v",
			AWSOnbCodeTemplateMissing, dr, templateURL, err)
		return nil, onbErr(AWSOnbCodeTemplateMissing,
			"the AuthSec template for this release is not available right now; use manual setup")
	}

	externalID, err := MintExternalID(workspaceID)
	if err != nil {
		return nil, err
	}
	suffix, err := newSuffix()
	if err != nil {
		return nil, err
	}
	topic, _ := s.cfg.TopicFor(dr)
	sess := &AWSOnboardingSession{
		ID: uuid.New(), WorkspaceID: workspaceID, CreatedBy: actor, CreatorUserID: creatorUserID, ExternalID: externalID,
		Regions: regs, DeploymentRegion: dr, Suffix: suffix,
		StackName: awsOnbStackName(suffix), RoleName: awsOnbRoleName(suffix),
		Status: AWSOnbPending,
	}
	sess.QuickCreateURL, err = awsdiscovery.QuickCreateURL(dr, templateURL, sess.StackName, map[string]string{
		"AuthSecPrincipalArn": s.principal,
		"ExternalId":          externalID,
		"CallbackTopicArn":    topic,
		"RoleName":            sess.RoleName,
	})
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	sess.CreatedAt, sess.UpdatedAt, sess.ExpiresAt = now, now, now.Add(awsOnbSessionTTL)

	payload, err := json.Marshal(sess)
	if err != nil {
		return nil, err
	}
	if _, err := s.redis.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, awsOnbSessionKey(sess.ID), payload, awsOnbSessionTTL)
		p.Set(ctx, awsOnbExtKey(externalID), sess.ID.String(), awsOnbSessionTTL)
		return nil
	}); err != nil {
		log.Printf("[aws-onb] ALERT stage=start code=%s err=%v", AWSOnbCodeStoreUnavailable, err)
		return nil, onbErr(AWSOnbCodeStoreUnavailable, "automatic setup is temporarily unavailable")
	}
	log.Printf("[aws-onb] stage=start outcome=ok session=%s ref=%s region=%s scan_regions=%s",
		sess.ID, sess.ref(), dr, strings.Join(regs, ","))
	return sess, nil
}

// GetSession returns a session of this workspace.
func (s *AWSQuickCreateService) GetSession(ctx context.Context, workspaceID, id uuid.UUID) (*AWSOnboardingSession, error) {
	if s.redis == nil {
		return nil, onbErr(AWSOnbCodeStoreUnavailable, "automatic setup is temporarily unavailable")
	}
	sess, err := s.loadSession(ctx, id)
	if err != nil {
		return nil, err
	}
	// Another workspace's session reads as absent, not forbidden, so an id
	// cannot be probed for existence.
	if sess == nil || sess.WorkspaceID != workspaceID {
		return nil, ErrAWSOnbSessionNotFound
	}
	return sess, nil
}

func (s *AWSQuickCreateService) loadSession(ctx context.Context, id uuid.UUID) (*AWSOnboardingSession, error) {
	raw, err := s.redis.Get(ctx, awsOnbSessionKey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess AWSOnboardingSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return nil, fmt.Errorf("corrupt onboarding session %s: %w", id, err)
	}
	return &sess, nil
}

// saveSession writes a session back, the ExternalId index with it.
//
// A session that has just become terminal is kept readable for
// awsOnbTerminalTTL from that moment — once. Later saves never extend it. A
// session still being worked on is kept at least awsOnbActiveTTL, so its index
// cannot expire between the lookup and the answer.
func (s *AWSQuickCreateService) saveSession(ctx context.Context, sess *AWSOnboardingSession) error {
	now := s.now().UTC()
	sess.UpdatedAt = now
	if sess.terminal() && sess.TerminalAt == nil {
		sess.TerminalAt = &now
		sess.ExpiresAt = now.Add(awsOnbTerminalTTL)
	}
	ttl := sess.ExpiresAt.Sub(now)
	if !sess.terminal() && ttl < awsOnbActiveTTL {
		ttl = awsOnbActiveTTL
	}
	if ttl <= 0 {
		// A terminal session past its lifetime: keep it only briefly.
		ttl = time.Minute
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	_, err = s.redis.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, awsOnbSessionKey(sess.ID), payload, ttl)
		p.Set(ctx, awsOnbExtKey(sess.ExternalID), sess.ID.String(), ttl)
		return nil
	})
	return err
}

/* --------------------------------- callback -------------------------------- */

// callbackLog is one line per decision, so any onboarding can be rebuilt from
// its AuthSec ref. Never carries a ResponseURL query (a presigned write
// credential), and the ExternalId only as a short hash.
type callbackLog struct {
	stage, session, ref, stack, request, account, region, ext string
	attempt                                                   int
}

func (l callbackLog) emit(outcome, code, msg string) {
	alert := ""
	if outcome == CallbackReject.String() || code == AWSOnbCodeAuthSecUnavailable {
		alert = "ALERT "
	}
	log.Printf("[aws-onb] %sstage=%s outcome=%s code=%s session=%s ref=%s stack=%s request=%s account=%s region=%s ext=%s attempt=%d msg=%q",
		alert, l.stage, outcome, code, l.session, l.ref, l.stack, l.request, l.account, l.region, l.ext, l.attempt, msg)
}

// HandleCallbackMessage processes one SQS message body. See the file comment
// for the trust model; every check runs before any AWS call.
func (s *AWSQuickCreateService) HandleCallbackMessage(ctx context.Context, body string) CallbackOutcome {
	return s.HandleCallbackDelivery(ctx, body, false)
}

// HandleCallbackDelivery is HandleCallbackMessage for a queue consumer that
// knows how often the message has been delivered. lastChance means SQS will
// move it to the DLQ instead of delivering it again: a transient failure is
// then answered FAILED now, because an unanswered stack only fails after its
// full ServiceTimeout, with no reason the customer can read.
func (s *AWSQuickCreateService) HandleCallbackDelivery(ctx context.Context, body string, lastChance bool) CallbackOutcome {
	lg := callbackLog{stage: "envelope"}

	// 1. Envelope: ours, and a well-formed request for our resource.
	env, err := awsdiscovery.ParseSNSEnvelope(body)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}
	if !s.cfg.IsOurTopic(env.TopicArn) {
		lg.emit(CallbackReject.String(), "", "message did not arrive through an AuthSec callback topic")
		return CallbackReject
	}
	req, err := awsdiscovery.ParseCFNRequest(env.Message)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}
	lg.stack, lg.request = req.StackID, req.RequestID
	stack, err := awsdiscovery.ParseStackID(req.StackID)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}
	lg.account, lg.region = stack.AccountID, stack.Region

	// 2. ResponseURL, before anything could make AuthSec contact it.
	lg.stage = "response_url"
	target, err := awsdiscovery.ValidateResponseURL(req.ResponseURL, stack.Region)
	if err != nil {
		lg.emit(CallbackReject.String(), "", err.Error())
		return CallbackReject
	}

	deadline := env.Timestamp.Add(awsCallbackDeadline)
	switch req.RequestType {
	case awsdiscovery.CFNRequestDelete, awsdiscovery.CFNRequestUpdate:
		// Never destructive, never blocking. A Delete must always succeed or the
		// customer's stack cannot be deleted (including the Delete a rollback
		// sends), and a forged Delete must not be able to change anything. An
		// Update (a template upgrade) changes nothing AuthSec holds.
		lg.stage = strings.ToLower(req.RequestType)
		physical := req.PhysicalResourceID
		if physical == "" {
			physical = "authsec-unregistered-" + shortHash(req.StackID)
		}
		out, _ := s.deliver(ctx, target, awsdiscovery.NewCFNResponse(req, awsdiscovery.CFNStatusSuccess, "", physical))
		lg.emit(out.String(), "", "answered SUCCESS without changes")
		return out
	}
	return s.handleCreate(ctx, env, req, stack, target, deadline, lastChance, lg)
}

func (s *AWSQuickCreateService) handleCreate(
	ctx context.Context, env *awsdiscovery.SNSEnvelope, req *awsdiscovery.CFNRequest,
	stack awsdiscovery.StackRef, target *url.URL, deadline time.Time, lastChance bool, lg callbackLog,
) CallbackOutcome {
	props := req.ResourceProperties
	lg.stage = "session"
	lg.ext = shortHash(props.ExternalID)
	unregistered := "authsec-unregistered-" + shortHash(req.StackID)

	// failNoSession answers a request no session can be tied to.
	failNoSession := func(code, msg string) CallbackOutcome {
		resp := awsdiscovery.NewCFNResponse(req, awsdiscovery.CFNStatusFailed, awsOnbReasons[code], unregistered)
		out, _ := s.deliver(ctx, target, resp)
		lg.emit(out.String(), code, msg)
		return out
	}
	// transient hands a recoverable failure back to the queue — unless the
	// deadline has passed or this is the queue's last delivery, when the stack
	// is better served by an honest FAILED now than by a silent timeout later.
	transient := func(msg string) CallbackOutcome {
		if !s.now().Before(deadline) || lastChance {
			return failNoSession(AWSOnbCodeAuthSecUnavailable, "final delivery or past deadline: "+msg)
		}
		lg.emit(CallbackRetry.String(), "", msg)
		return CallbackRetry
	}

	// 3. Session, by the ExternalId.
	if awsdiscovery.ValidateExternalID(props.ExternalID) != nil {
		return failNoSession(AWSOnbCodeUnknownLink, "ExternalId missing or malformed")
	}
	idStr, err := s.redis.Get(ctx, awsOnbExtKey(props.ExternalID)).Result()
	if errors.Is(err, redis.Nil) {
		return failNoSession(AWSOnbCodeUnknownLink, "no session for this ExternalId")
	}
	if err != nil {
		return transient("session store: " + err.Error())
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return failNoSession(AWSOnbCodeUnknownLink, "corrupt session index")
	}
	lg.session = id.String()

	release, locked, err := s.acquireSessionLock(ctx, id)
	if err != nil {
		return transient("session lock: " + err.Error())
	}
	if !locked {
		// Another worker holds this session and will answer this same request
		// itself. Never answer here — not even past the deadline — or a FAILED
		// from this duplicate could overtake the holder's SUCCESS. Come back and
		// replay whatever the holder stored.
		lg.emit(CallbackRetry.String(), "", "session is being processed by another worker")
		return CallbackRetry
	}
	defer release()

	sess, err := s.loadSession(ctx, id)
	if err != nil {
		return transient("load session: " + err.Error())
	}
	if sess == nil {
		return failNoSession(AWSOnbCodeUnknownLink, "session expired")
	}
	lg.ref = sess.ref()
	physical := awsOnbPhysicalID(sess.ID)
	key := awsOnbResultKey(req.StackID, req.RequestID)
	if sess.Results == nil {
		sess.Results = map[string]awsStoredResult{}
	}

	// answer delivers a response for this session, flagging the session when
	// the presigned URL refused the answer so the console can warn that the
	// stack is about to roll back.
	answer := func(status, reason string) CallbackOutcome {
		out, rejected := s.deliver(ctx, target, awsdiscovery.NewCFNResponse(req, status, reason, physical))
		// Past the attempt cap nothing is written, not even this flag: those
		// messages are not the customer's stack.
		if rejected && sess.Attempts <= awsCallbackMaxAttempts {
			sess.ResponsePutFailed = true
			if err := s.saveSession(ctx, sess); err != nil {
				log.Printf("[aws-onb] stage=respond outcome=save_failed session=%s err=%v", sess.ID, err)
			}
		}
		return out
	}

	// Duplicate delivery: replay the answer already given, never re-onboard.
	if prev, ok := sess.Results[key]; ok {
		out := answer(prev.Status, prev.Reason)
		if out != CallbackRetry && sess.Status == AWSOnbConnected && len(sess.RegionStatus) == 0 {
			s.probeAndSave(ctx, sess, lg)
		}
		lg.emit(out.String(), sess.Code, "replayed stored "+prev.Status)
		return out
	}

	// fail answers FAILED and, while the session is still live, records that
	// answer for replay. Past the attempt cap nothing is written at all, and a
	// finished session records only its attempt count: messages carrying a
	// leaked ExternalId can neither grow the session nor keep it alive.
	fail := func(code, msg string, markSession bool) CallbackOutcome {
		reason := awsOnbReasons[code] + " AuthSec ref: " + sess.ref()
		if sess.Attempts <= awsCallbackMaxAttempts {
			if !sess.terminal() {
				sess.Results[key] = awsStoredResult{Status: awsdiscovery.CFNStatusFailed, Reason: reason}
				if markSession {
					sess.Status, sess.Code, sess.Message = AWSOnbFailed, code, awsOnbReasons[code]
				}
			}
			if err := s.saveSession(ctx, sess); err != nil {
				return transient("save session: " + err.Error())
			}
		}
		out := answer(awsdiscovery.CFNStatusFailed, reason)
		lg.emit(out.String(), code, msg)
		return out
	}

	sess.Attempts++
	lg.attempt = sess.Attempts
	if sess.Attempts > awsCallbackMaxAttempts {
		return fail(AWSOnbCodeTooManyAttempts, "attempt cap reached", false)
	}

	// 4. Everything that decides the connection comes from the session. The
	//    message only names the role; its ExternalId must match exactly.
	lg.stage = "validate"
	if props.ExternalID != sess.ExternalID {
		return fail(AWSOnbCodeUnknownLink, "ExternalId does not match the session", false)
	}
	if err := VerifyExternalIDBinding(sess.WorkspaceID, sess.ExternalID); err != nil {
		return fail(AWSOnbCodeWrongWorkspace, "ExternalId not bound to the session's workspace", true)
	}

	// 5. Stack context: one region end to end, one account, commercial.
	_, topicRegion, err := awsdiscovery.ParseTopicARN(env.TopicArn)
	if err != nil || topicRegion != stack.Region || stack.Region != sess.DeploymentRegion {
		return fail(AWSOnbCodeRegionMismatch, fmt.Sprintf("topic=%s stack=%s session=%s",
			topicRegion, stack.Region, sess.DeploymentRegion), false)
	}
	partition, roleAccount, err := awsdiscovery.ParseRoleARN(props.RoleArn)
	if err != nil {
		return fail(AWSOnbCodeInvalidRequest, "RoleArn: "+err.Error(), false)
	}
	if stack.Partition != awsdiscovery.PartitionAWS || partition != awsdiscovery.PartitionAWS ||
		roleAccount != stack.AccountID {
		return fail(AWSOnbCodeAccountMismatch, fmt.Sprintf("stack account %s, role account %s",
			stack.AccountID, roleAccount), false)
	}

	// Single use. A session that already connected answers a repeat of the same
	// connection consistently and refuses anything else.
	if sess.terminal() {
		if sess.Status == AWSOnbConnected && sess.AccountID == stack.AccountID && sess.RoleARN == props.RoleArn {
			// Nothing to record: the session is finished and the answer is
			// derived from it, so a repeat gets the same answer without a write.
			out := answer(awsdiscovery.CFNStatusSuccess, "")
			lg.emit(out.String(), "", "session already connected to this role")
			return out
		}
		return fail(AWSOnbCodeLinkUsed, "session already "+sess.Status, false)
	}

	if s.existing != nil {
		if prev, err := s.existing(sess.WorkspaceID, stack.AccountID); err == nil && prev != nil {
			if old := prev.AWSAttrs().RoleARN; old != "" && old != props.RoleArn {
				sess.PreviousRoleARN = old
			}
		}
	}
	if s.onboard == nil {
		return fail(AWSOnbCodeAuthSecUnavailable, "service built without an onboarding service", false)
	}
	sess.Status = AWSOnbVerifying
	if err := s.saveSession(ctx, sess); err != nil {
		return transient("save session: " + err.Error())
	}

	// 6-9. AssumeRole with the session's ExternalId, GetCallerIdentity, account
	//      check, Vault write and upsert: all the existing Onboard().
	lg.stage = "onboard"
	connector, err := s.onboardWithRetry(ctx, sess, props.RoleArn, deadline)
	if err != nil {
		var oe *AWSOnbError
		if !errors.As(err, &oe) {
			oe = onbErr(AWSOnbCodeAuthSecUnavailable, "%v", err)
		}
		return fail(oe.Code, err.Error(), true)
	}

	sess.Status, sess.Code, sess.Message = AWSOnbConnected, "", ""
	sess.AccountID, sess.RoleARN = connector.ScopeID, props.RoleArn
	cid := connector.ID
	sess.ConnectorID = &cid
	sess.Results[key] = awsStoredResult{Status: awsdiscovery.CFNStatusSuccess}
	s.auditConnected(sess, connector, stack)
	// Stored BEFORE answering, so a redelivery after a lost answer replays
	// SUCCESS instead of connecting a second time.
	//
	// A failed save must NOT turn into a FAILED answer: the connection is
	// already proven and written (Vault + connector row), and FAILED would roll
	// the stack back and delete the very role the connector now points at.
	// Answer SUCCESS regardless. The worst case of a lost save is a redelivery
	// that runs Onboard again, which upserts the same row.
	if err := s.saveSession(ctx, sess); err != nil {
		log.Printf("[aws-onb] ALERT stage=respond outcome=save_failed session=%s ref=%s err=%v (answering SUCCESS anyway)",
			sess.ID, sess.ref(), err)
	}

	lg.stage = "respond"
	out := answer(awsdiscovery.CFNStatusSuccess, "")
	if out == CallbackRetry {
		lg.emit(out.String(), "", "connected; answer to CloudFormation will be retried")
		return out
	}
	lg.emit(out.String(), "", "connected")

	// Regional probes, after the answer: the stack is never held for them.
	s.probeAndSave(ctx, sess, lg)
	return out
}

// onboardWithRetry runs the existing Onboard until it succeeds, a failure is
// final, or the time left runs out.
//
// Three kinds of failure, three budgets:
//   - AccessDenied from the customer's trust policy right after the stack
//     created the role is usually IAM propagation: retried for
//     awsIAMPropagationBudget, then reported as the customer's to fix.
//   - Throttling and probe timeouts heal by themselves: retried until the last
//     moment an attempt can still finish.
//   - Everything else on AuthSec's side — Vault, the database, AuthSec's own
//     AWS credentials — does not heal within one onboarding: retried for
//     awsAuthSecErrorBudget, then answered FAILED instead of making the
//     customer wait out the whole deadline for the same error.
//
// No attempt may still be running once awsAnswerReserve before the deadline
// begins, so the answer to CloudFormation always goes out in time: an attempt
// starts only if a full awsOnboardingTimeout fits before the reserve, and its
// context ends at the reserve regardless.
func (s *AWSQuickCreateService) onboardWithRetry(
	ctx context.Context, sess *AWSOnboardingSession, roleARN string, deadline time.Time,
) (*models.CloudConnector, error) {
	const baseDelay = 3 * time.Second
	answerBy := deadline.Add(-awsAnswerReserve)
	lastStart := answerBy.Add(-awsOnboardingTimeout)
	start := s.now()
	in := AWSOnboardInput{RoleARN: roleARN, ExternalID: sess.ExternalID, Regions: sess.Regions}
	for attempt := 1; ; attempt++ {
		// !Before, not After: the wait below is capped at lastStart, so the loop
		// lands exactly on it, where After is still false and the next wait
		// would be zero — a spin.
		if attempt > 1 && !s.now().Before(lastStart) {
			return nil, onbErr(AWSOnbCodeAuthSecUnavailable, "no time left for another attempt before the deadline")
		}
		actx, cancel := context.WithDeadline(ctx, answerBy)
		connector, _, err := s.onboard(actx, sess.WorkspaceID, in, sess.CreatedBy)
		cancel()
		if err == nil {
			return connector, nil
		}
		now := s.now()
		switch {
		case errors.Is(err, ErrExternalIDNotIssued):
			return nil, onbErr(AWSOnbCodeWrongWorkspace, "%v", err)
		case strings.Contains(err.Error(), "refusing to onboard"):
			// Onboard's own account cross-check (the ARN names one account, the
			// session landed in another). Permanent. Matched on its message
			// because Onboard's body is deliberately left unchanged.
			return nil, onbErr(AWSOnbCodeAccountMismatch, "%v", err)
		case isAuthSecCredentialError(err):
			// classify() files these under ErrNotAssumable, but they mean
			// AuthSec's OWN credentials are bad or expired — nothing the
			// customer's trust policy can fix.
			if now.Sub(start) >= awsAuthSecErrorBudget {
				return nil, onbErr(AWSOnbCodeAuthSecUnavailable, "%v", err)
			}
		case errors.Is(err, awsdiscovery.ErrNotAssumable):
			if now.Sub(start) >= awsIAMPropagationBudget {
				return nil, onbErr(AWSOnbCodeAssumeDenied, "%v", err)
			}
		case errors.Is(err, awsdiscovery.ErrThrottled), errors.Is(err, ErrAWSProbeTimeout),
			errors.Is(err, context.DeadlineExceeded):
			// Heals by itself; the lastStart check above ends it in time.
		default:
			if now.Sub(start) >= awsAuthSecErrorBudget {
				return nil, onbErr(AWSOnbCodeAuthSecUnavailable, "%v", err)
			}
		}
		log.Printf("[aws-onb] stage=onboard outcome=retry session=%s ref=%s attempt=%d err=%v",
			sess.ID, sess.ref(), attempt, err)
		wait := retryBackoff(baseDelay, attempt)
		// Never sleep past the last moment an attempt may start; with nothing
		// left, the check at the top of the loop ends it. A non-positive wait
		// returns at once, and the loop cannot spin: the next iteration either
		// starts a real attempt or returns.
		if left := lastStart.Sub(now); wait > left {
			wait = left
		}
		if err := s.sleep(ctx, wait); err != nil {
			return nil, onbErr(AWSOnbCodeAuthSecUnavailable, "%v", err)
		}
	}
}

// isAuthSecCredentialError reports whether an assume-role failure is about
// AuthSec's own base credentials (invalid, expired, mis-signed) rather than the
// customer's trust policy. classify() keeps the AWS error code in the message
// as "(Code)", which is what this matches on.
func isAuthSecCredentialError(err error) bool {
	if errors.Is(err, awsdiscovery.ErrNoBaseCredentials) {
		return true
	}
	msg := err.Error()
	for _, code := range []string{"(InvalidClientTokenId)", "(ExpiredToken)", "(SignatureDoesNotMatch)"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// deliver answers CloudFormation. A 5xx or transport error is retried a few
// times and then handed back to the queue (the stored result is replayed on
// redelivery). A 4xx means the presigned URL is dead: nothing can deliver the
// answer any more, so the message is done, rejected is true, and the caller
// flags the session so the console can warn that the stack will roll back.
func (s *AWSQuickCreateService) deliver(
	ctx context.Context, target *url.URL, resp awsdiscovery.CFNResponse,
) (out CallbackOutcome, rejected bool) {
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		err = awsdiscovery.SendCFNResponse(ctx, s.http, target, resp)
		if err == nil {
			return CallbackDone, false
		}
		if errors.Is(err, awsdiscovery.ErrResponseRejected) {
			log.Printf("[aws-onb] ALERT stage=respond outcome=done status=%s stack=%s request=%s err=%v",
				resp.Status, resp.StackID, resp.RequestID, err)
			return CallbackDone, true
		}
		if attempt < 3 {
			if serr := s.sleep(ctx, time.Duration(attempt)*time.Second); serr != nil {
				break
			}
		}
	}
	log.Printf("[aws-onb] stage=respond outcome=retry status=%s stack=%s request=%s err=%v",
		resp.Status, resp.StackID, resp.RequestID, err)
	return CallbackRetry, false
}

// probeAndSave checks every scan region through exactly the path a scan takes
// (AssumeRole at that region's STS endpoint with AuthSec's credentials), so
// "connected" means a scan will work there. A failure never fails the session.
func (s *AWSQuickCreateService) probeAndSave(ctx context.Context, sess *AWSOnboardingSession, lg callbackLog) {
	if s.verifier == nil {
		return
	}
	results := make(map[string]AWSRegionProbe, len(sess.Regions))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, awsProbeConcurrency)
	for _, region := range sess.Regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			// A panic in one probe must not take the backend down with it; the
			// region simply reads as not checked.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[aws-onb] ALERT stage=probe outcome=panic region=%s err=%v", region, r)
					mu.Lock()
					results[region] = AWSRegionProbe{Status: "not_reachable", Reason: "error"}
					mu.Unlock()
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, awsProbeTimeout)
			defer cancel()
			name, err := onboardingSessionName()
			var probe AWSRegionProbe
			if err == nil {
				_, err = s.verifier.Verify(pctx, awsdiscovery.AssumeRequest{
					RoleARN: sess.RoleARN, ExternalID: sess.ExternalID, Region: region, SessionName: name,
				})
			}
			probe = classifyRegionProbe(region, err, pctx.Err())
			mu.Lock()
			results[region] = probe
			mu.Unlock()
		}(region)
	}
	wg.Wait()

	sess.RegionStatus = results
	if err := s.saveSession(ctx, sess); err != nil {
		log.Printf("[aws-onb] stage=probe outcome=save_failed session=%s err=%v", sess.ID, err)
		return
	}
	reachable := 0
	for _, p := range results {
		if p.Status == "connected" {
			reachable++
		}
	}
	lg.stage = "probe"
	lg.emit(CallbackDone.String(), "", fmt.Sprintf("%d/%d regions reachable", reachable, len(results)))
}

// classifyRegionProbe names why a region is not reachable, as far as the
// error says. Whether a disabled opt-in region reports InvalidClientTokenId is
// confirmed in the spike (S9); until then that case also reads as "blocked".
func classifyRegionProbe(region string, err, ctxErr error) AWSRegionProbe {
	switch {
	case err == nil:
		return AWSRegionProbe{Status: "connected"}
	case errors.Is(ctxErr, context.DeadlineExceeded):
		return AWSRegionProbe{Status: "not_reachable", Reason: "timeout"}
	case awsdiscovery.IsOptInRegion(region) && strings.Contains(err.Error(), "InvalidClientTokenId"):
		return AWSRegionProbe{Status: "not_reachable", Reason: "region_disabled"}
	case errors.Is(err, awsdiscovery.ErrNotAssumable):
		return AWSRegionProbe{Status: "not_reachable", Reason: "blocked"}
	default:
		return AWSRegionProbe{Status: "not_reachable", Reason: "error"}
	}
}

/* ------------------------------ template check ----------------------------- */

// newTemplateChecker returns a cached HEAD check of the published template.
// A release whose template was never published would otherwise hand customers
// a Launch link that fails inside the AWS console.
func newTemplateChecker(now func() time.Time) func(ctx context.Context, templateURL string) error {
	type entry struct {
		err     error
		expires time.Time
	}
	var mu sync.Mutex
	cache := map[string]entry{}
	client := &http.Client{Timeout: 5 * time.Second}
	return func(ctx context.Context, templateURL string) error {
		mu.Lock()
		if e, ok := cache[templateURL]; ok && now().Before(e.expires) {
			mu.Unlock()
			return e.err
		}
		mu.Unlock()

		err := func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, templateURL, nil)
			if err != nil {
				return err
			}
			res, err := client.Do(req)
			if err != nil {
				return err
			}
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("HTTP %d", res.StatusCode)
			}
			return nil
		}()
		ttl := awsTemplateCheckTTL
		if err != nil {
			ttl = awsTemplateCheckFailTTL
		}
		mu.Lock()
		cache[templateURL] = entry{err: err, expires: now().Add(ttl)}
		mu.Unlock()
		return err
	}
}

/* ---------------------------------- lock ----------------------------------- */

// Compare-and-delete and compare-and-extend: a worker only ever releases or
// extends the lock it holds. A plain DEL would let a worker that overran the
// TTL delete the lock a second worker has since taken.
var (
	awsOnbUnlockScript = redis.NewScript(
		`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) end return 0`)
	awsOnbExtendScript = redis.NewScript(
		`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("PEXPIRE", KEYS[1], ARGV[2]) end return 0`)
)

// acquireSessionLock takes the per-session lock with a random owner token and
// keeps it alive while the caller works. release stops the keep-alive and
// deletes the lock only if it is still ours. A worker that dies simply stops
// extending, so the lock frees itself within awsOnbLockTTL.
func (s *AWSQuickCreateService) acquireSessionLock(ctx context.Context, id uuid.UUID) (release func(), ok bool, err error) {
	token := uuid.NewString()
	key := awsOnbLockKey(id)
	ok, err = s.redis.SetNX(ctx, key, token, awsOnbLockTTL).Result()
	if err != nil || !ok {
		return func() {}, ok, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(awsOnbLockRefresh)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = awsOnbExtendScript.Run(context.WithoutCancel(ctx), s.redis, []string{key},
					token, awsOnbLockTTL.Milliseconds()).Err()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		_ = awsOnbUnlockScript.Run(context.WithoutCancel(ctx), s.redis, []string{key}, token).Err()
	}, true, nil
}

/* ---------------------------------- audit ---------------------------------- */

// auditConnected records a Quick Create connection the way the manual flow's
// POST /aws/connectors records its own: connecting an AWS account is a
// security-relevant mutation, whichever path made it. There is no HTTP request
// behind a callback, so the actor is the session's creator and the path names
// the stack that reported back.
func (s *AWSQuickCreateService) auditConnected(
	sess *AWSOnboardingSession, connector *models.CloudConnector, stack awsdiscovery.StackRef,
) {
	if config.AuditLogger == nil {
		return
	}
	userID := sess.CreatorUserID
	if userID == "" {
		userID = sess.CreatedBy
	}
	config.AuditLogger.LogAdminAction(
		sess.ID.String(),
		sess.WorkspaceID.String(),
		userID,
		"onboard",
		"cloud_connector",
		connector.ID.String(),
		"CALLBACK",
		"aws-quick-create/"+stack.Region+"/"+sess.StackName,
		"",
		"aws-cloudformation",
		200,
		0,
		nil,
		map[string]any{
			"source": "quick_create", "account_id": connector.ScopeID, "role_arn": sess.RoleARN,
			"regions": sess.Regions, "previous_role_arn": sess.PreviousRoleARN,
		},
		"",
	)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
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
