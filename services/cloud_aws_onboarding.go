package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AWS onboarding: connect a customer's AWS account read-only, prove the
// connection works, and record it as the cloud_connector row every later AWS
// scan resolves against.
//
// The shape of the flow, and why it is two steps rather than one:
//
//  1. The console asks for an onboarding package. AuthSec mints an ExternalId
//     and hands back the CloudFormation template.
//  2. The customer deploys the stack in their own account. It creates one
//     read-only IAM role and nothing else.
//  3. The console posts the role ARN back with that ExternalId. AuthSec assumes
//     the role, reads the account id out of the session, and persists it.
//
// Nothing AuthSec stores can be used by anyone else: the ExternalId is useless
// without the role, and the role is useless to anyone who is not AuthSec's own
// AWS principal. No customer access key ever exists.

// externalIDSeparator splits the nonce from its signature. '.' is inside AWS's
// permitted ExternalId charset.
const externalIDSeparator = "."

// awsOnboardingTimeout bounds one assume-role probe. Generous enough for the
// SDK's retries under throttling, short enough that a wedged onboarding request
// does not hold a connection open until a proxy kills it.
const awsOnboardingTimeout = 45 * time.Second

// maxRegionsPerConnector caps the operator's region selection.
//
// Scan cost grows with regions x services, and every regional surface is a
// separate set of paginated calls. The cap is a guard against an accidental
// "select all" turning one scan into hundreds of thousands of API calls, not a
// technical limit; it is well above the number of regions any real estate uses.
const maxRegionsPerConnector = 32

// ErrExternalIDNotIssued means the submitted ExternalId does not carry this
// workspace's signature. See mintExternalID for why that check exists.
var ErrExternalIDNotIssued = errors.New("this external id was not issued to this workspace")

// ErrAWSProbeTimeout means the assume-role probe did not finish inside
// awsOnboardingTimeout. Distinct from the request context dying (the client
// went away — the controller answers that itself) and from AWS refusing the
// assume (ErrNotAssumable): this is "AWS never answered", a 504, not a 400.
var ErrAWSProbeTimeout = errors.New("the AWS connection probe timed out before AWS answered")

// AWSOnboardingService owns the policy around connecting an AWS account:
// validation, proving the connection, where the ExternalId is stored, and the
// connector row. AWS itself is reached only through the Verifier.
type AWSOnboardingService struct {
	db       *gorm.DB
	repo     repositories.CloudConnectorRepository
	vault    vault.VaultClient
	verifier awsdiscovery.Verifier

	// regionsAPI, when set, answers ec2:DescribeRegions without assuming the
	// role. The test seam for EnabledRegions, like the scanners' With*API.
	regionsAPI awsdiscovery.RegionsAPI

	// pinned is the connector row a scan run was claimed with (ForRun). Every
	// scanner of that run reads the connector through Connector, so they all
	// see ONE region list, however the connector changes mid-run.
	pinned *models.CloudConnector
}

// NewAWSOnboardingService constructs the service against real AWS.
//
// A vault client is REQUIRED. The ExternalId is a shared secret between AuthSec
// and the customer's trust policy; a deployment with nowhere safe to put it
// must fail at construction rather than quietly write it into a database column
// where a backup would carry it.
func NewAWSOnboardingService(db *gorm.DB, vc vault.VaultClient) *AWSOnboardingService {
	return &AWSOnboardingService{
		db:       db,
		repo:     repositories.NewCloudConnectorRepository(db),
		vault:    vc,
		verifier: awsdiscovery.NewLiveVerifier(),
	}
}

// WithVerifier swaps the AWS boundary. The seam that lets onboarding be
// exercised without an AWS account.
func (s *AWSOnboardingService) WithVerifier(v awsdiscovery.Verifier) *AWSOnboardingService {
	s.verifier = v
	return s
}

// WithRegionsAPI installs an EC2 client for DescribeRegions, bypassing
// assume-role. Tests use it; production builds one from the connector's role.
func (s *AWSOnboardingService) WithRegionsAPI(api awsdiscovery.RegionsAPI) *AWSOnboardingService {
	s.regionsAPI = api
	return s
}

/* ------------------------------ the ExternalId ---------------------------- */

// cloudDiscoveryHMACKey returns the key used to bind an ExternalId to the
// workspace it was issued to. Resolution mirrors oidcStateHMACKey:
//
//  1. AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY
//  2. config.AppConfig.JWTSecret (so a local deployment works out of the box)
//  3. a development constant
//
// Rotating the key invalidates ExternalIds that have been issued but not yet
// used. It does NOT affect connectors already onboarded — their ExternalId
// lives in the secrets store and is never re-verified against this key.
func cloudDiscoveryHMACKey() []byte {
	if v := os.Getenv("AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY"); v != "" {
		return []byte(v)
	}
	if config.AppConfig != nil && config.AppConfig.JWTSecret != "" {
		return []byte(config.AppConfig.JWTSecret)
	}
	return []byte("authsec-cloud-discovery-dev-key")
}

// MintExternalID issues an ExternalId for a workspace.
//
// The value is `<nonce>.<signature>`, where the signature is an HMAC over the
// workspace id and the nonce. That makes it self-authenticating, and it closes
// a real hole in the plain-random version of this flow:
//
// Without the binding, any workspace that learned another customer's role ARN
// and ExternalId — both of which travel through consoles, tickets and
// screenshots — could submit them and onboard someone else's AWS account into
// their own inventory. With it, an ExternalId issued to workspace A fails
// verification under workspace B, so the pair is worthless outside the tenant
// it was issued to. No server-side state is needed to achieve that.
func MintExternalID(workspaceID uuid.UUID) (string, error) {
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("external id nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	return nonce + externalIDSeparator + signExternalID(workspaceID, nonce), nil
}

// signExternalID computes the workspace-bound half of an ExternalId. Truncated
// to 32 base64url characters — 192 bits, far beyond guessing, and it keeps the
// whole value short enough to read off a screen without wrapping.
func signExternalID(workspaceID uuid.UUID, nonce string) string {
	mac := hmac.New(sha256.New, cloudDiscoveryHMACKey())
	mac.Write([]byte(workspaceID.String()))
	mac.Write([]byte(externalIDSeparator))
	mac.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
}

// VerifyExternalIDBinding checks that an ExternalId was issued to this
// workspace.
func VerifyExternalIDBinding(workspaceID uuid.UUID, externalID string) error {
	nonce, sig, ok := strings.Cut(externalID, externalIDSeparator)
	if !ok || nonce == "" || sig == "" {
		return ErrExternalIDNotIssued
	}
	// Constant time: the comparison is against a secret-derived value, and a
	// length-or-prefix leak here would let a caller grind out a valid signature.
	if !hmac.Equal([]byte(sig), []byte(signExternalID(workspaceID, nonce))) {
		return ErrExternalIDNotIssued
	}
	return nil
}

/* -------------------------------- onboarding ------------------------------ */

// AWSOnboardInput is what the console posts once the customer's stack exists.
type AWSOnboardInput struct {
	RoleARN     string   `json:"role_arn"`
	ExternalID  string   `json:"external_id"`
	Regions     []string `json:"regions"`
	DisplayName string   `json:"display_name"`
}

// Onboard proves the connection and records it. Reports whether the connector
// was newly created, so the caller can answer 201 rather than 200 and an
// operator can tell a new connection from a re-connection.
//
// Order matters here. AWS is called BEFORE anything is written: an account that
// cannot be assumed must leave no row and no stored secret behind, because a
// connector that has never worked is indistinguishable in the console from one
// that has stopped working, and the second is an incident while the first is a
// typo.
func (s *AWSOnboardingService) Onboard(
	ctx context.Context, workspaceID uuid.UUID, in AWSOnboardInput, actor string,
) (*models.CloudConnector, bool, error) {

	if s.vault == nil {
		return nil, false, errors.New("secrets store not configured; the external id cannot be stored")
	}

	roleARN := strings.TrimSpace(in.RoleARN)
	externalID := strings.TrimSpace(in.ExternalID)

	if err := VerifyExternalIDBinding(workspaceID, externalID); err != nil {
		return nil, false, err
	}
	partition, arnAccount, err := awsdiscovery.ParseRoleARN(roleARN)
	if err != nil {
		return nil, false, err
	}
	regions, err := normalizeRegions(in.Regions)
	if err != nil {
		return nil, false, err
	}

	sessionName, err := onboardingSessionName()
	if err != nil {
		return nil, false, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, awsOnboardingTimeout)
	defer cancel()

	identity, err := s.verifier.Verify(probeCtx, awsdiscovery.AssumeRequest{
		RoleARN: roleARN, ExternalID: externalID,
		// STS is reached regionally; the first selected region is as good as any
		// and keeps the probe inside the estate the operator chose.
		Region: regions[0], SessionName: sessionName,
	})
	if err != nil {
		// probeCtx derives from the request context, so its own deadline
		// firing (rather than the client going away) means AWS never
		// answered in time. Name it explicitly: the controller's generic
		// 400 fall-through must never claim a timeout was bad input.
		if probeCtx.Err() == context.DeadlineExceeded {
			return nil, false, fmt.Errorf("%w: %v", ErrAWSProbeTimeout, err)
		}
		return nil, false, err
	}

	// The account the session landed in must be the account the ARN names. These
	// cannot differ in any normal case; if they ever do, something is wrong
	// enough that recording it as a working connection would be the wrong answer.
	if identity.AccountID != arnAccount {
		return nil, false, fmt.Errorf(
			"the role resolved to account %s but its ARN names %s; refusing to onboard",
			identity.AccountID, arnAccount)
	}

	// Whether the connector already exists decides whether a later failure may
	// roll the stored secret back. Read it BEFORE the write, because after the
	// upsert there is no way to tell.
	existing, err := s.repo.GetByScope(workspaceID, models.CloudProviderAWS, identity.AccountID)
	if err != nil && !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		return nil, false, err
	}
	isNewAccount := existing == nil

	// Deterministic path, keyed by account rather than by connector id. Two
	// consequences, both wanted: re-onboarding the same account overwrites its
	// ExternalId instead of leaving an orphaned entry behind, and the path can be
	// derived from the connector row without a second lookup.
	secretPath := awsExternalIDPath(workspaceID, identity.AccountID)
	if err := s.vault.WriteSecret(secretPath, map[string]interface{}{
		"external_id": externalID,
	}); err != nil {
		return nil, false, fmt.Errorf("failed to store the external id: %w", err)
	}

	now := time.Now()
	connector := &models.CloudConnector{
		WorkspaceID: workspaceID,
		Provider:    models.CloudProviderAWS,
		ScopeKind:   models.CloudScopeAccount,
		ScopeID:     identity.AccountID,
		// Organizations support is deferred; when it arrives the org id lands
		// here and nothing else about this row changes.
		ParentScopeID: nil,
		AuthRef:       secretPath,
		Status:        models.CloudConnectorActive,
		VerifiedAt:    &now,
		CreatedBy:     actor,
		// Set explicitly rather than left to the column default. GORM omits a
		// zero-valued field so the default applies, but a NOT NULL jsonb column
		// is the wrong place to rely on that inference — and this is the column
		// that later records what each scan could and could not read.
		Coverage: json.RawMessage("{}"),
	}
	if err := connector.SetAWSAttrs(models.AWSConnectorAttrs{
		DisplayName:     strings.TrimSpace(in.DisplayName),
		RoleARN:         roleARN,
		Partition:       partition,
		Regions:         regions,
		CallerARN:       identity.ARN,
		TemplateVersion: awsdiscovery.TemplateVersion,
	}); err != nil {
		return nil, false, err
	}

	stored, created, err := s.repo.Upsert(connector)
	if err != nil {
		// Roll the secret back only when this account was not already connected.
		// Deleting it on a re-onboard would strand a working connector with a
		// dangling auth_ref — a worse outcome than the leftover entry, and one
		// that only shows up at the next scan.
		if isNewAccount {
			_ = s.vault.DeleteSecret(secretPath)
		}
		return nil, false, fmt.Errorf("failed to record the connector: %w", err)
	}
	return stored, created, nil
}

// VerifyConnector re-proves an existing connection and records the verdict on
// the row.
//
// A failure is recorded, not raised and forgotten: status becomes 'error' with
// the reason, and verified_at is deliberately left alone so the console can
// still show when the connection last genuinely worked. It never deletes
// anything the connector previously discovered — "we cannot look right now" is
// not "it is gone".
func (s *AWSOnboardingService) VerifyConnector(
	ctx context.Context, workspaceID, id uuid.UUID,
) (*models.CloudConnector, error) {

	_, req, err := s.assumeRequestFor(workspaceID, id)
	if err != nil {
		return nil, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, awsOnboardingTimeout)
	defer cancel()

	identity, verr := s.verifier.Verify(probeCtx, req)
	if verr != nil {
		// Same distinction as Onboard: our own probe budget firing is a
		// timeout to report, not caller input. Recorded on the row as-is,
		// so the console shows what actually happened.
		if probeCtx.Err() == context.DeadlineExceeded {
			verr = fmt.Errorf("%w: %v", ErrAWSProbeTimeout, verr)
		}
		updated, uerr := s.repo.MarkError(workspaceID, id, verr.Error())
		if uerr != nil {
			return nil, uerr
		}
		return updated, verr
	}

	// ONE FIELD, WRITTEN IN PLACE. caller_arn is the only attr a verification
	// learns. Writing back the whole attrs blob read before the probe -- which
	// takes seconds, under retries -- silently undid a region change (PATCH
	// .../connectors/:id) that committed while AWS was answering. jsonb_set
	// touches caller_arn alone; MarkVerified with no attrs leaves the rest.
	if err := s.db.Exec(`UPDATE cloud_connector
		   SET attrs = jsonb_set(attrs, '{caller_arn}', to_jsonb(?::text), true)
		 WHERE workspace_id = ? AND id = ? AND provider = ?`,
		identity.ARN, workspaceID, id, models.CloudProviderAWS).Error; err != nil {
		return nil, err
	}
	return s.repo.MarkVerified(workspaceID, id, nil)
}

// ConfigForConnector returns an AWS config authenticated as a connector's
// discovery role. This is the entry point for every later AWS scan surface —
// IAM identities, access keys, policies, Bedrock, CloudTrail — so that the
// assume-role path, its retry policy and its session naming exist once.
//
// The session name carries the connector's short id, which means the customer
// can see in their own CloudTrail exactly which AuthSec connection made each
// call.
func (s *AWSOnboardingService) ConfigForConnector(
	ctx context.Context, workspaceID, id uuid.UUID, region string,
) (aws.Config, *models.CloudConnector, error) {

	c, req, err := s.assumeRequestFor(workspaceID, id)
	if err != nil {
		return aws.Config{}, nil, err
	}
	if region != "" {
		if err := awsdiscovery.ValidateRegion(region); err != nil {
			return aws.Config{}, nil, err
		}
		req.Region = region
	}

	// Asserted to the narrow ConfigProvider interface rather than to
	// *LiveVerifier, so a test double can supply a config too. A Verifier that
	// cannot produce one is a legitimate thing to have — proving a connection and
	// authenticating a scan are different jobs — so this is an assertion, not an
	// extra method on Verifier.
	provider, ok := s.verifier.(awsdiscovery.ConfigProvider)
	if !ok {
		return aws.Config{}, nil, errors.New("this AWS verifier cannot produce a session config")
	}
	cfg, err := provider.Config(ctx, req)
	if err != nil {
		return aws.Config{}, nil, err
	}
	return cfg, c, nil
}

// RevokeConnector revokes a connector and purges its stored ExternalId. The
// connector row and everything it discovered stay in place for audit -- see
// CloudConnectorRepository.Revoke for why this is not a delete.
//
// The row goes first. A purge that fails leaves an unreferenced secret, which
// is untidy; a revoke that fails after the purge would leave a connector that
// looks usable and is not, and every scan against it would fail confusingly.
func (s *AWSOnboardingService) RevokeConnector(workspaceID, id uuid.UUID) error {
	authRef, err := s.repo.Revoke(workspaceID, id)
	if err != nil {
		return err
	}
	if authRef != "" && s.vault != nil {
		_ = s.vault.DeleteSecret(authRef)
	}
	return nil
}

// Connectors lists the workspace's AWS connectors.
func (s *AWSOnboardingService) Connectors(workspaceID uuid.UUID) ([]models.CloudConnector, error) {
	return s.repo.List(workspaceID, models.CloudProviderAWS)
}

// Connector reads one. On a service pinned to a run (ForRun) it answers that
// run's connector from the pinned row, so every scanner of the run sees the
// scope the run was claimed with.
func (s *AWSOnboardingService) Connector(workspaceID, id uuid.UUID) (*models.CloudConnector, error) {
	if p := s.pinned; p != nil && p.WorkspaceID == workspaceID && p.ID == id {
		cp := *p
		return &cp, nil
	}
	return s.repo.Get(workspaceID, id)
}

// ForRun returns a copy of the service pinned to the connector row as it is
// NOW, for one scan run.
//
// A REGION CHANGE APPLIES FROM THE NEXT SCAN (§5.3 PATCH, D-54: a run keeps
// the regions it was claimed with). The permission scanner's EKS pass and the
// workload scanner each read the connector's regions, minutes apart; without
// the pin, a PATCH landing between them changed the run already in flight --
// EKS read the old regions, compute the new ones, and the run's coverage
// described neither selection. The worker pins right after the claim.
func (s *AWSOnboardingService) ForRun(workspaceID, connectorID uuid.UUID) (*AWSOnboardingService, error) {
	c, err := s.repo.Get(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	cp := *s
	cp.pinned = c
	return &cp, nil
}

/* ----------------------------- region selection --------------------------- */

// ErrAWSConnectorRevoked refuses an operation on a revoked connection: its
// ExternalId is purged, so AWS cannot be asked anything through it, and a
// configuration change would apply to scans that can never run.
var ErrAWSConnectorRevoked = errors.New("this connection was revoked; re-onboard the account first")

// InvalidRegionsError names the regions a selection cannot contain (§5.3:
// "422 invalid_region names the offender"): malformed codes, or regions not
// enabled in the account. An EMPTY selection is one too, with no region to
// name (D-90): it is not a region list the account could be scanned under.
type InvalidRegionsError struct {
	Regions []string
	Reason  string
}

func (e *InvalidRegionsError) Error() string {
	if len(e.Regions) == 0 {
		return e.Reason
	}
	return fmt.Sprintf("%s: %s", e.Reason, strings.Join(e.Regions, ", "))
}

// RegionSelectionError is a selection longer than the cap: 400 on the
// parameter, not 422 -- no region in it is at fault.
type RegionSelectionError struct{ Msg string }

func (e *RegionSelectionError) Error() string { return e.Msg }

// RegionsUnavailableError means the account's ENABLED regions could not be
// read from AWS: ec2:DescribeRegions was refused or throttled, the role could
// not be assumed underneath it, or AWS did not answer in time. Err keeps the
// SDK error chain, so awsdiscovery.FailedCall still names the call and the
// code AWS returned.
//
// It is distinct from every AuthSec-side failure (no secrets store, no base
// credentials, a connector with no role recorded), which never reach AWS and
// are 500s: GET .../regions answers THIS one with the selection it holds and
// the failure stated (200), and PATCH refuses with 422 regions_unavailable,
// because a selection is never accepted unvalidated (D-90).
type RegionsUnavailableError struct{ Err error }

func (e *RegionsUnavailableError) Error() string { return e.Err.Error() }
func (e *RegionsUnavailableError) Unwrap() error { return e.Err }

// EnabledRegions lists the regions enabled in the connector's account
// (ec2:DescribeRegions through the discovery role; §5.3 GET .../regions), with
// the connector as it was read.
//
// The client is signed for the connector's first selected region -- the same
// one assumeRequestFor gives STS -- because DescribeRegions is answered from
// any enabled region, and one the operator chose is known to be enabled.
func (s *AWSOnboardingService) EnabledRegions(
	ctx context.Context, workspaceID, id uuid.UUID,
) ([]awsdiscovery.Region, *models.CloudConnector, error) {
	c, err := s.awsConnector(workspaceID, id)
	if err != nil {
		return nil, nil, err
	}
	if c.Status == models.CloudConnectorRevoked {
		return nil, c, ErrAWSConnectorRevoked
	}

	probeCtx, cancel := context.WithTimeout(ctx, awsOnboardingTimeout)
	defer cancel()

	api := s.regionsAPI
	if api == nil {
		cfg, _, cerr := s.ConfigForConnector(probeCtx, workspaceID, id, "")
		if cerr != nil {
			return nil, c, cerr
		}
		api = awsdiscovery.NewRegionsClient(cfg)
	}
	regions, err := awsdiscovery.EnabledRegions(probeCtx, api)
	if err != nil {
		if ctx.Err() != nil {
			// The CLIENT went away: nothing to report to AWS's account of it.
			return nil, c, err
		}
		// Our own probe budget firing is a timeout to report as one, never as
		// a denial or bad input.
		if probeCtx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("%w: %w", ErrAWSProbeTimeout, err)
		}
		return nil, c, &RegionsUnavailableError{Err: err}
	}
	return regions, c, nil
}

// UpdateRegions replaces the connector's region selection (§5.3 PATCH
// .../connectors/:id). Returns the updated connector and the selection it
// replaced.
//
// Validated in two steps, cheapest first: the codes' shape (no AWS call), then
// membership of the account's ENABLED regions, read live. Every offender is
// named. Nothing is written unless the whole selection is valid, and an
// enabled list that cannot be read refuses the change (RegionsUnavailableError)
// -- a selection is never accepted unvalidated (D-90). Stored de-duplicated
// and sorted.
//
// Applies from the NEXT scan: a run in flight reads its pinned row (ForRun).
func (s *AWSOnboardingService) UpdateRegions(
	ctx context.Context, workspaceID, id uuid.UUID, requested []string,
) (*models.CloudConnector, []string, error) {
	c, err := s.awsConnector(workspaceID, id)
	if err != nil {
		return nil, nil, err
	}
	if c.Status == models.CloudConnectorRevoked {
		return nil, nil, ErrAWSConnectorRevoked
	}
	before := c.AWSAttrs().Regions

	selection, err := normalizeRegionSelection(requested)
	if err != nil {
		return nil, before, err
	}

	enabled, _, err := s.EnabledRegions(ctx, workspaceID, id)
	if err != nil {
		return nil, before, err
	}
	on := make(map[string]bool, len(enabled))
	for _, r := range enabled {
		on[r.Name] = true
	}
	var offenders []string
	for _, r := range selection {
		if !on[r] {
			offenders = append(offenders, r)
		}
	}
	if len(offenders) > 0 {
		return nil, before, &InvalidRegionsError{Regions: offenders,
			Reason: "not enabled in this AWS account"}
	}

	updated, err := s.writeRegions(workspaceID, id, selection)
	if err != nil {
		return nil, before, err
	}
	return updated, before, nil
}

// writeRegions sets attrs.regions IN PLACE, atomically, on a live connector.
//
// jsonb_set rather than a read-modify-write of the whole blob: two writers of
// different attrs (a verify recording caller_arn, this) must not undo each
// other. The status predicate refuses a connector revoked since it was read.
func (s *AWSOnboardingService) writeRegions(
	workspaceID, id uuid.UUID, regions []string,
) (*models.CloudConnector, error) {
	raw, err := json.Marshal(regions)
	if err != nil {
		return nil, err
	}
	var rows []models.CloudConnector
	if err := s.db.Raw(`UPDATE cloud_connector
		   SET attrs = jsonb_set(attrs, '{regions}', ?::jsonb, true), updated_at = now()
		 WHERE workspace_id = ? AND id = ? AND provider = ? AND status <> ?
		RETURNING *`,
		string(raw), workspaceID, id, models.CloudProviderAWS, models.CloudConnectorRevoked,
	).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		// Revoked (or removed) between the read and the write.
		if _, gerr := s.awsConnector(workspaceID, id); gerr != nil {
			return nil, gerr
		}
		return nil, ErrAWSConnectorRevoked
	}
	return &rows[0], nil
}

// awsConnector reads a connector of this workspace that is an AWS connector;
// anything else is not found (a GCP connector id on an AWS route is absent,
// not a type error that confirms the id exists).
func (s *AWSOnboardingService) awsConnector(workspaceID, id uuid.UUID) (*models.CloudConnector, error) {
	c, err := s.repo.Get(workspaceID, id)
	if err != nil {
		return nil, err
	}
	if c.Provider != models.CloudProviderAWS {
		return nil, repositories.ErrCloudConnectorNotFound
	}
	return c, nil
}

/* --------------------------------- helpers -------------------------------- */

// assumeRequestFor rebuilds everything needed to become a connector's role:
// the non-secret half from the row, the ExternalId from the secrets store.
func (s *AWSOnboardingService) assumeRequestFor(
	workspaceID, id uuid.UUID,
) (*models.CloudConnector, awsdiscovery.AssumeRequest, error) {

	var empty awsdiscovery.AssumeRequest

	c, err := s.repo.Get(workspaceID, id)
	if err != nil {
		return nil, empty, err
	}
	if c.Provider != models.CloudProviderAWS {
		return nil, empty, fmt.Errorf("connector %s is a %s connector", id, c.Provider)
	}
	if s.vault == nil {
		return nil, empty, errors.New("secrets store not configured; the external id cannot be read")
	}

	attrs := c.AWSAttrs()
	if attrs.RoleARN == "" {
		return nil, empty, errors.New("connector has no role arn recorded; re-run onboarding")
	}
	region := ""
	if len(attrs.Regions) > 0 {
		region = attrs.Regions[0]
	} else {
		return nil, empty, errors.New("connector has no regions in scope; re-run onboarding")
	}

	secret, err := s.vault.ReadSecret(c.AuthRef)
	if err != nil {
		return nil, empty, fmt.Errorf("failed to read the external id: %w", err)
	}
	externalID, _ := secret["external_id"].(string)
	if externalID == "" {
		return nil, empty, errors.New("no external id stored for this connector; re-run onboarding")
	}

	return c, awsdiscovery.AssumeRequest{
		RoleARN:     attrs.RoleARN,
		ExternalID:  externalID,
		Region:      region,
		SessionName: scanSessionName(c.ID),
	}, nil
}

// awsExternalIDPath is where a workspace's ExternalId for one account lives.
func awsExternalIDPath(workspaceID uuid.UUID, accountID string) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/cloud-discovery/aws/%s",
		workspaceID.String(), accountID)
}

// onboardingSessionName names the probe session. Random, because at this point
// there is no connector id to name it after.
func onboardingSessionName() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session name: %w", err)
	}
	return "authsec-onboarding-" + hex.EncodeToString(b), nil
}

// scanSessionName names a working session after its connector, so the calls
// AuthSec makes are attributable in the customer's own CloudTrail.
func scanSessionName(connectorID uuid.UUID) string {
	return "authsec-discovery-" + strings.ReplaceAll(connectorID.String(), "-", "")[:16]
}

// normalizeRegions lowercases, trims, de-duplicates and validates the operator's
// region selection, preserving the order given.
//
// At least one region is required rather than defaulted. IAM is global and
// would scan fine with none, but every regional surface after it — Lambda, ECS,
// EC2, Bedrock, AgentCore, EKS — would silently find nothing, and "we scanned
// and found no agents" is the most damaging wrong answer this connector can
// give. Making the operator choose keeps the cost decision visible.
func normalizeRegions(in []string) ([]string, error) {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" {
			continue
		}
		if err := awsdiscovery.ValidateRegion(r); err != nil {
			return nil, err
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("select at least one AWS region to scan")
	}
	if len(out) > maxRegionsPerConnector {
		return nil, fmt.Errorf("at most %d regions may be selected", maxRegionsPerConnector)
	}
	return out, nil
}

// normalizeRegionSelection is normalizeRegions for a region CHANGE (PATCH
// .../connectors/:id, D-90), where the caller must be told every malformed
// code at once (422 invalid_region names the offenders), not just the first.
// Duplicates are removed and the result is SORTED: a selection is a set, and
// storing it in one canonical order keeps the audit's before/after comparable.
// An empty selection is 422 invalid_region too -- no scan scope at all -- and
// only a selection over the cap is a 400.
func normalizeRegionSelection(in []string) ([]string, error) {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	var malformed []string
	for _, r := range in {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		if err := awsdiscovery.ValidateRegion(r); err != nil {
			malformed = append(malformed, r)
			continue
		}
		out = append(out, r)
	}
	if len(malformed) > 0 {
		sort.Strings(malformed)
		return nil, &InvalidRegionsError{Regions: malformed, Reason: "not AWS region codes"}
	}
	if len(out) == 0 {
		return nil, &InvalidRegionsError{Regions: []string{}, Reason: "select at least one AWS region to scan"}
	}
	if len(out) > maxRegionsPerConnector {
		return nil, &RegionSelectionError{Msg: fmt.Sprintf("at most %d regions may be selected", maxRegionsPerConnector)}
	}
	sort.Strings(out)
	return out, nil
}
