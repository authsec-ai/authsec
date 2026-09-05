package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IAM identity discovery: the foundation every later AWS surface resolves
// against.
//
// What this writes: cloud_identity (IAM roles and users) and cloud_secret
// (access keys). Nothing else. Trust-policy parsing, permission and resource
// extraction, Bedrock, Lambda, ECS, EC2, EKS, CloudTrail and classification are
// later tickets, and the scope line in ticket [1] is explicit that no other
// write path belongs here.
//
// What it RETRIEVES but does not persist: the policy documents attached to
// every identity. Ticket [1] is responsible for fetching them; ticket [2] parses
// them into cloud_permission and cloud_resource. They are handed over in the
// IAMSnapshot rather than staged in a table, because a full policy document is
// not something the plan wants stored — a summary plus the policy identifier is
// enough, and the document can always be re-fetched.

// iamScanTimeout bounds one whole scan.
//
// A large account is thousands of GetRole and GetPolicyVersion calls under a
// retrying client. Twenty minutes is generous for that and still short enough
// that a wedged scan releases its connector rather than blocking every later
// one forever.
const iamScanTimeout = 20 * time.Minute

// ErrScanNotPermitted is returned when the connector cannot currently be used.
var ErrScanNotPermitted = errors.New("connector is not in a usable state")

// AWSIAMScanner reads the IAM identity foundation of one connector.
type AWSIAMScanner struct {
	db         *gorm.DB
	connectors repositories.CloudConnectorRepository
	identities repositories.CloudIdentityRepository
	onboarding *AWSOnboardingService

	// api, when set, replaces the real IAM client. The seam that lets the whole
	// scan be exercised without an AWS account.
	api awsdiscovery.IAMAPI
}

// NewAWSIAMScanner constructs the scanner.
func NewAWSIAMScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSIAMScanner {
	return &AWSIAMScanner{
		db:         db,
		connectors: repositories.NewCloudConnectorRepository(db),
		identities: repositories.NewCloudIdentityRepository(db),
		onboarding: onboarding,
	}
}

// WithIAMAPI installs a specific IAM client, bypassing assume-role.
func (s *AWSIAMScanner) WithIAMAPI(api awsdiscovery.IAMAPI) *AWSIAMScanner {
	s.api = api
	return s
}

// IAMSnapshot is what one scan read. The persisted half is already in the
// database by the time this is returned; the policy documents are the handover
// to ticket [2].
type IAMSnapshot struct {
	ConnectorID uuid.UUID
	AccountID   string
	Generation  int
	Coverage    models.ScanCoverage

	// Policies is one entry per identity that had any policy attached, keyed by
	// identity ARN. Empty for an identity with no policies, absent for one whose
	// policies could not be read — a distinction ticket [2] must preserve.
	Policies map[string]awsdiscovery.IdentityPolicies

	// TrustPolicies is the decoded AssumeRolePolicyDocument per role ARN, the
	// input for cloud_assume_edge in ticket [2].
	TrustPolicies map[string]string
}

// Scan reads roles, users, access keys and policy documents for one connector.
//
// The order is deliberate. Roles and users first, because access keys and
// policies both resolve against an identity that must already exist. Policies
// last, because they are the most expensive surface and the least damaging to
// lose: an identity recorded without its policies is still a governed identity,
// while a policy with no identity is nothing at all.
//
// No surface failure aborts the scan. Each one is recorded in coverage and the
// next is attempted, because "IAM was denied but access keys were readable" is
// a more useful report than a single error, and because a partial inventory is
// worth having as long as it is labelled partial.
func (s *AWSIAMScanner) Scan(ctx context.Context, workspaceID, connectorID uuid.UUID) (*IAMSnapshot, error) {
	connector, err := s.connectors.Get(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	if connector.Provider != models.CloudProviderAWS {
		return nil, fmt.Errorf("connector %s is a %s connector", connectorID, connector.Provider)
	}
	if connector.Status == models.CloudConnectorRevoked {
		return nil, fmt.Errorf("%w: the connection was revoked", ErrScanNotPermitted)
	}

	reader, err := s.readerFor(ctx, workspaceID, connector)
	if err != nil {
		// Could not even authenticate. Record it as a failed scan rather than
		// silently leaving the last report in place, which would let a broken
		// connection keep displaying a stale all-clear.
		s.persistCoverage(workspaceID, connectorID, models.ScanCoverage{
			Generation: connector.ScanGeneration,
			Status:     models.ScanStatusFailed,
			Error:      err.Error(),
			FinishedAt: ptrTime(time.Now()),
		})
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, iamScanTimeout)
	defer cancel()

	generation := connector.ScanGeneration + 1
	started := time.Now()
	coverage := models.ScanCoverage{
		Generation: generation,
		Status:     models.ScanStatusRunning,
		StartedAt:  &started,
		Surfaces:   map[string]models.SurfaceCoverage{},
		Counters:   map[string]int{},
	}
	s.persistCoverage(workspaceID, connectorID, coverage)

	snapshot := &IAMSnapshot{
		ConnectorID:   connectorID,
		AccountID:     connector.ScopeID,
		Generation:    generation,
		Policies:      map[string]awsdiscovery.IdentityPolicies{},
		TrustPolicies: map[string]string{},
	}

	// ---- roles -------------------------------------------------------------
	roles, rolesErr := reader.ListRoles(ctx)
	for _, role := range roles {
		if err := s.upsertRole(workspaceID, connectorID, generation, role, coverage.Counters); err != nil {
			return nil, err
		}
		if role.TrustPolicy != "" {
			snapshot.TrustPolicies[role.ARN] = role.TrustPolicy
		}
	}
	coverage.Surfaces[models.SurfaceIAMRoles] = surfaceResult(len(roles), rolesErr)

	// ---- users and their access keys ---------------------------------------
	users, usersErr := reader.ListUsers(ctx)
	keyCount := 0
	var keysErr error
	for _, user := range users {
		identity, err := s.upsertUser(workspaceID, connectorID, generation, user, coverage.Counters)
		if err != nil {
			return nil, err
		}
		keys, err := reader.ListAccessKeys(ctx, user.Name)
		if err != nil {
			// One user's keys being unreadable does not mean every user's are.
			// Remember the first failure for the coverage report and carry on,
			// so the scan still records the keys it CAN see.
			if keysErr == nil {
				keysErr = err
			}
			continue
		}
		for _, key := range keys {
			if err := s.upsertAccessKey(workspaceID, connectorID, identity.ID, generation, key, coverage.Counters); err != nil {
				return nil, err
			}
			keyCount++
		}
	}
	coverage.Surfaces[models.SurfaceIAMUsers] = surfaceResult(len(users), usersErr)
	coverage.Surfaces[models.SurfaceIAMAccessKeys] = surfaceResult(keyCount, keysErr)

	// ---- policy documents, for ticket [2] ----------------------------------
	policyCount, policiesErr := s.readPolicies(ctx, reader, roles, users, snapshot)
	coverage.Surfaces[models.SurfaceIAMPolicies] = surfaceResult(policyCount, policiesErr)
	coverage.Counters["policies_fetched"] = policyCount

	// ---- reconcile, but only if we were allowed to look everywhere ----------
	if coverage.Complete() {
		removedIdentities, removedSecrets, err := s.identities.ReconcileGeneration(
			workspaceID, connectorID, generation)
		if err != nil {
			return nil, err
		}
		coverage.Counters["identities_removed"] = int(removedIdentities)
		coverage.Counters["secrets_removed"] = int(removedSecrets)
		coverage.Status = models.ScanStatusComplete
	} else {
		// The rule the whole schema is built around: unreached is not missing.
		// A denied ListRoles and an account with no roles look identical from
		// the database, so a scan that could not look must never conclude that
		// anything is gone.
		coverage.Counters["identities_removed"] = 0
		coverage.Counters["secrets_removed"] = 0
		coverage.Status = models.ScanStatusPartial
	}

	finished := time.Now()
	coverage.FinishedAt = &finished
	if ids, secrets, err := s.identities.CountsForConnector(workspaceID, connectorID); err == nil {
		coverage.Counters["identities_total"] = int(ids)
		coverage.Counters["secrets_total"] = int(secrets)
	}

	if err := s.commitScan(workspaceID, connectorID, generation, coverage); err != nil {
		return nil, err
	}
	snapshot.Coverage = coverage
	return snapshot, nil
}

// readPolicies fetches the managed and inline policy documents for every
// discovered identity.
//
// A failure on one identity is remembered and the rest are still read. The
// alternative — abandoning the surface on the first denied GetRolePolicy —
// would throw away every document already fetched because of one role the
// audit role happens not to cover.
func (s *AWSIAMScanner) readPolicies(
	ctx context.Context, reader *awsdiscovery.IAMReader,
	roles []awsdiscovery.IAMRole, users []awsdiscovery.IAMUser, snapshot *IAMSnapshot,
) (int, error) {

	count := 0
	var firstErr error

	for _, role := range roles {
		policies, err := reader.RolePolicies(ctx, role.ARN, role.Name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(policies.Attached) > 0 || len(policies.Inline) > 0 {
			snapshot.Policies[role.ARN] = policies
			count += len(policies.Attached) + len(policies.Inline)
		}
	}
	for _, user := range users {
		policies, err := reader.UserPolicies(ctx, user.ARN, user.Name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(policies.Attached) > 0 || len(policies.Inline) > 0 {
			snapshot.Policies[user.ARN] = policies
			count += len(policies.Attached) + len(policies.Inline)
		}
	}
	return count, firstErr
}

/* -------------------------------- upserts --------------------------------- */

func (s *AWSIAMScanner) upsertRole(
	workspaceID, connectorID uuid.UUID, generation int,
	role awsdiscovery.IAMRole, counters map[string]int,
) error {
	identity := &models.CloudIdentity{
		WorkspaceID:        workspaceID,
		ConnectorID:        connectorID,
		Kind:               models.CloudIdentityIAMRole,
		NativeID:           role.ARN,
		Name:               role.Name,
		ProviderCreatedAt:  role.CreatedAt,
		LastUsedAt:         role.LastUsedAt,
		Enabled:            true, // IAM has no disable switch for a role.
		LastSeenGeneration: generation,
	}
	if err := identity.SetAWSAttrs(models.AWSIdentityAttrs{
		UniqueID:           role.UniqueID,
		Path:               role.Path,
		Description:        role.Description,
		MaxSessionDuration: role.MaxSessionDuration,
		Tags:               role.Tags,
		HasTrustPolicy:     role.TrustPolicy != "",
	}); err != nil {
		return err
	}
	return s.recordIdentity(identity, counters)
}

func (s *AWSIAMScanner) upsertUser(
	workspaceID, connectorID uuid.UUID, generation int,
	user awsdiscovery.IAMUser, counters map[string]int,
) (*models.CloudIdentity, error) {
	identity := &models.CloudIdentity{
		WorkspaceID: workspaceID,
		ConnectorID: connectorID,
		Kind:        models.CloudIdentityIAMUser,
		NativeID:    user.ARN,
		Name:        user.Name,
		// PasswordLastUsed is CONSOLE sign-in, deliberately not written to
		// last_used_at. That column means "this identity did something", and a
		// human logging in says nothing about whether the credential a workload
		// uses is live. Conflating them would make a dormant access key look
		// active because someone opened the console.
		ProviderCreatedAt:  user.CreatedAt,
		Enabled:            true,
		LastSeenGeneration: generation,
	}
	if err := identity.SetAWSAttrs(models.AWSIdentityAttrs{
		UniqueID: user.UniqueID,
		Path:     user.Path,
	}); err != nil {
		return nil, err
	}
	if err := s.recordIdentity(identity, counters); err != nil {
		return nil, err
	}
	return identity, nil
}

func (s *AWSIAMScanner) recordIdentity(identity *models.CloudIdentity, counters map[string]int) error {
	_, created, err := s.identities.UpsertIdentity(identity)
	if err != nil {
		return fmt.Errorf("record identity %s: %w", identity.NativeID, err)
	}
	if created {
		counters["identities_new"]++
	} else {
		counters["identities_updated"]++
	}
	return nil
}

func (s *AWSIAMScanner) upsertAccessKey(
	workspaceID, connectorID, identityID uuid.UUID, generation int,
	key awsdiscovery.IAMAccessKey, counters map[string]int,
) error {
	status := models.CloudSecretInactive
	if key.Status == "Active" {
		status = models.CloudSecretActive
	}
	secret := &models.CloudSecret{
		WorkspaceID:       workspaceID,
		ConnectorID:       connectorID,
		IdentityID:        identityID,
		Kind:              models.CloudSecretAccessKey,
		NativeID:          key.KeyID,
		ProviderCreatedAt: key.CreatedAt,
		// AWS access keys do not expire. Nil here is the fact, not a gap — and
		// it is exactly why created_at matters.
		ExpiresAt:          nil,
		LastUsedAt:         key.LastUsedAt,
		Status:             status,
		LastSeenGeneration: generation,
	}
	_, created, err := s.identities.UpsertSecret(secret)
	if err != nil {
		return fmt.Errorf("record access key %s: %w", key.KeyID, err)
	}
	if created {
		counters["secrets_new"]++
	} else {
		counters["secrets_updated"]++
	}
	return nil
}

/* -------------------------------- plumbing -------------------------------- */

// readerFor builds an IAM reader for a connector, assuming its role unless a
// client was injected.
func (s *AWSIAMScanner) readerFor(
	ctx context.Context, workspaceID uuid.UUID, connector *models.CloudConnector,
) (*awsdiscovery.IAMReader, error) {

	if s.api != nil {
		return awsdiscovery.NewIAMReader(s.api), nil
	}
	if s.onboarding == nil {
		return nil, errors.New("no IAM client and no onboarding service to assume a role with")
	}
	// IAM is global; the region only decides which endpoint the SDK signs for.
	cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, connector.ID, "")
	if err != nil {
		return nil, err
	}
	return awsdiscovery.NewIAMReader(awsdiscovery.NewIAMClient(cfg)), nil
}

// commitScan advances the connector's generation and stores the final coverage
// in one statement, so a reader can never see a bumped generation with the
// previous scan's report beside it.
func (s *AWSIAMScanner) commitScan(
	workspaceID, connectorID uuid.UUID, generation int, coverage models.ScanCoverage,
) error {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return err
	}
	return s.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, connectorID).
		Updates(map[string]interface{}{
			"scan_generation": generation,
			"coverage":        json.RawMessage(raw),
			"updated_at":      time.Now(),
		}).Error
}

// persistCoverage writes a coverage report without touching the generation.
// Used for the running and failed states, where the generation must not move.
func (s *AWSIAMScanner) persistCoverage(workspaceID, connectorID uuid.UUID, coverage models.ScanCoverage) {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return
	}
	// Best effort: losing a progress update must not fail the scan that was
	// reporting it.
	_ = s.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, connectorID).
		Updates(map[string]interface{}{
			"coverage":   json.RawMessage(raw),
			"updated_at": time.Now(),
		}).Error
}

// surfaceResult turns a read's outcome into a coverage entry.
//
// The count is reported even on failure, where it is a FLOOR rather than a
// total — we read this many before we were stopped. The state is what tells a
// reader which of the two it is.
func surfaceResult(count int, err error) models.SurfaceCoverage {
	switch {
	case err == nil:
		return models.SurfaceCoverage{State: models.CloudCoverageReached, Count: count}
	case errors.Is(err, awsdiscovery.ErrThrottled):
		return models.SurfaceCoverage{State: models.CloudCoverageThrottled, Count: count, Error: err.Error()}
	default:
		return models.SurfaceCoverage{State: models.CloudCoverageDenied, Count: count, Error: err.Error()}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
