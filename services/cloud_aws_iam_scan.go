package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
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
	db          *gorm.DB
	connectors  repositories.CloudConnectorRepository
	identities  repositories.CloudIdentityRepository
	checkpoints repositories.CloudScanCheckpointRepository
	onboarding  *AWSOnboardingService

	// api, when set, replaces the real IAM client. The seam that lets the whole
	// scan be exercised without an AWS account.
	api awsdiscovery.IAMAPI

	// credentialAPI, when set, replaces the real credential-report client.
	credentialAPI awsdiscovery.CredentialReportAPI
	// credentialSleep replaces the report's poll delay, so a test does not wait.
	credentialSleep func(context.Context, time.Duration) error

	// lastCoverage is the coverage report as far as this scan has built it.
	//
	// A surface's state is only known once its loop finishes, so evidence
	// written DURING that loop -- every identity row, for instance -- records an
	// empty state. Empty means "not yet established", which the observation's
	// own comment says, and is better than stamping "reached" on a read that
	// had not finished.
	lastCoverage models.ScanCoverage

	// evidence records why each row exists. Nil is valid and writes nothing --
	// a caller with no durable run to anchor evidence to (a test, a legacy
	// path) degrades to no evidence rather than failing.
	evidence *ObservationWriter
}

// WithEvidence attaches an observation writer for this run.
func (s *AWSIAMScanner) WithEvidence(w *ObservationWriter) *AWSIAMScanner {
	s.evidence = w
	return s
}

// NewAWSIAMScanner constructs the scanner.
func NewAWSIAMScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSIAMScanner {
	return &AWSIAMScanner{
		db:          db,
		connectors:  repositories.NewCloudConnectorRepository(db),
		identities:  repositories.NewCloudIdentityRepository(db),
		checkpoints: repositories.NewCloudScanCheckpointRepository(db),
		onboarding:  onboarding,
	}
}

// WithIAMAPI installs a specific IAM client, bypassing assume-role.
func (s *AWSIAMScanner) WithIAMAPI(api awsdiscovery.IAMAPI) *AWSIAMScanner {
	s.api = api
	return s
}

// WithCredentialReportAPI installs a credential-report client, bypassing
// assume-role, and optionally a sleep function so a test does not wait on the
// report's poll loop.
func (s *AWSIAMScanner) WithCredentialReportAPI(
	api awsdiscovery.CredentialReportAPI, sleep func(context.Context, time.Duration) error,
) *AWSIAMScanner {
	s.credentialAPI = api
	s.credentialSleep = sleep
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

	// CredentialReportSurface is bonus evidence about users this scan already
	// wrote, kept OUT of Coverage on purpose -- see the comment where this is
	// set, in Scan.
	CredentialReportSurface models.SurfaceCoverage
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

	// The generation an interrupted attempt was using is the same number this
	// one computes: commitScan only advances scan_generation on success, so a
	// scan that died left it untouched. Checkpoints at this generation
	// therefore mean "the previous attempt was interrupted part-way", and this
	// run continues it rather than repeating its work.
	generation := connector.ScanGeneration + 1
	resuming, err := s.checkpoints.HasAny(workspaceID, connectorID, generation)
	if err != nil {
		return nil, err
	}

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
	// A role whose GetRole failed is listed but not understood: its tags,
	// last-used date and permissions boundary are unknown. Reporting the
	// surface as reached would let reconciliation delete on the strength of an
	// inventory we only half-read, and would present an unknown boundary as no
	// boundary.
	if incomplete := coverage.Counters["roles_detail_incomplete"]; incomplete > 0 && rolesErr == nil {
		coverage.Surfaces[models.SurfaceIAMRoles] = surfacePartial(
			len(roles), incomplete, "roles could not be read in detail")
	} else {
		coverage.Surfaces[models.SurfaceIAMRoles] = surfaceResult(len(roles), rolesErr)
	}

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
	//
	// The expensive phase: roughly seven calls per identity, so this is what
	// dominates a scan of a large account and what resume exists for. On a
	// resumed attempt the identities whose permissions were already written are
	// skipped entirely -- no AWS call at all for them.
	policyCursor := ""
	if resuming {
		cursor, _, err := s.checkpoints.Cursor(
			workspaceID, connectorID, generation, models.ScanPhaseIdentityPolicies)
		if err != nil {
			return nil, err
		}
		policyCursor = cursor
	}

	policyCount, skippedIdentities, policiesErr := s.readPolicies(
		ctx, reader, roles, users, snapshot, policyCursor)
	coverage.Surfaces[models.SurfaceIAMPolicies] = surfaceResult(policyCount, policiesErr)
	coverage.Counters["policies_fetched"] = policyCount
	if skippedIdentities > 0 {
		coverage.Counters["identities_resumed_past"] = skippedIdentities
		log.Printf("aws iam scan: connector=%s resuming generation %d, skipped %d identities already done",
			connectorID, generation, skippedIdentities)
	}

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

		// The attempt finished, so its checkpoints have served their purpose.
		// Clearing them is what makes the NEXT scan a fresh attempt rather than
		// a resume that skips everything -- and commitScan is about to advance
		// the generation past them anyway, so this is hygiene rather than
		// correctness.
		if err := s.checkpoints.Clear(workspaceID, connectorID, generation); err != nil {
			log.Printf("aws iam scan: clearing checkpoints for generation %d: %v", generation, err)
		}
	} else {
		// The rule the whole schema is built around: unreached is not missing.
		// A denied ListRoles and an account with no roles look identical from
		// the database, so a scan that could not look must never conclude that
		// anything is gone.
		coverage.Counters["identities_removed"] = 0
		coverage.Counters["secrets_removed"] = 0
		coverage.Status = models.ScanStatusPartial
	}

	// ---- credential report --------------------------------------------------
	//
	// Deliberately kept OUT of coverage.Surfaces, which is what the reconcile
	// gate above just consulted -- and, downstream, what the permission and
	// workload scanners' OWN gates consult too, since both check
	// snapshot.Coverage.Complete() as their "did ticket [1] succeed" baseline.
	// Adding a new denial-prone surface there would make every scanner's
	// reconciliation depend on a permission bonus evidence has nothing to do
	// with -- exactly the coupling FinalizeCoverage (see cloud_aws_iam_scan.go)
	// already exists to avoid for the permission and workload scans' own
	// surfaces. snapshot.CredentialReportSurface carries this one the same
	// way, merged only at FinalizeCoverage, after every scanner's local gate
	// has already fired against the unpolluted coverage.
	reportCount, reportErr := s.scanCredentialReport(ctx, workspaceID, connectorID, users)
	snapshot.CredentialReportSurface = surfaceResult(reportCount, reportErr)

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
// resumeCursor is exceeded when an identity sorts after the last one a previous
// attempt finished. Everything at or before the cursor already has its
// permissions written and stamped with this generation.
//
// Identities are walked in sorted ARN order rather than the order AWS returned
// them, because a cursor over an unstable order would silently skip work AWS
// happened to list earlier the second time.
func (s *AWSIAMScanner) readPolicies(
	ctx context.Context, reader *awsdiscovery.IAMReader,
	roles []awsdiscovery.IAMRole, users []awsdiscovery.IAMUser, snapshot *IAMSnapshot,
	resumeCursor string,
) (fetched int, skipped int, err error) {

	// One list of (arn, name, isRole) so the sort order spans roles and users
	// together -- the cursor is a single position through every identity, not
	// one per kind.
	type target struct {
		arn    string
		name   string
		isRole bool
		// boundaryARN is set for roles that carry a permissions boundary, so
		// the policy pass can read the capping document alongside the grants.
		boundaryARN string
	}
	targets := make([]target, 0, len(roles)+len(users))
	for _, role := range roles {
		targets = append(targets, target{
			arn: role.ARN, name: role.Name, isRole: true,
			boundaryARN: role.PermissionsBoundaryARN,
		})
	}
	for _, user := range users {
		targets = append(targets, target{arn: user.ARN, name: user.Name})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].arn < targets[j].arn })

	count := 0
	skippedCount := 0
	var firstErr error

	for _, t := range targets {
		// The saving resume exists for: no AWS call at all for an identity a
		// previous attempt already finished.
		if resumeCursor != "" && t.arn <= resumeCursor {
			skippedCount++
			continue
		}

		var policies awsdiscovery.IdentityPolicies
		var perr error
		if t.isRole {
			policies, perr = reader.RolePolicies(ctx, t.arn, t.name)
		} else {
			policies, perr = reader.UserPolicies(ctx, t.arn, t.name)
		}
		if perr != nil {
			if firstErr == nil {
				firstErr = perr
			}
			continue
		}

		// The boundary caps everything the policies above allow, so it is read
		// in the same pass. A failure to read it degrades this identity rather
		// than the scan: the grants are still worth recording, and the identity
		// keeps constraint_state 'bounded' from the ARN alone, so a missing
		// boundary document never renders as unconstrained access.
		if t.isRole && t.boundaryARN != "" {
			boundary, berr := reader.BoundaryPolicy(ctx, t.boundaryARN)
			if berr != nil {
				if firstErr == nil {
					firstErr = berr
				}
			} else {
				policies.Boundary = &boundary
			}
		}

		if len(policies.Attached) > 0 || len(policies.Inline) > 0 || policies.Boundary != nil {
			snapshot.Policies[t.arn] = policies
			count += len(policies.Attached) + len(policies.Inline)
		}
	}
	return count, skippedCount, firstErr
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
		UniqueID:               role.UniqueID,
		Path:                   role.Path,
		Description:            role.Description,
		MaxSessionDuration:     role.MaxSessionDuration,
		Tags:                   role.Tags,
		HasTrustPolicy:         role.TrustPolicy != "",
		PermissionsBoundaryARN: role.PermissionsBoundaryARN,
		DetailIncomplete:       !role.DetailComplete,
	}); err != nil {
		return err
	}
	if !role.DetailComplete {
		// GetRole failed. The role exists -- ListRoles named it -- but its
		// tags, last-used date and permissions boundary are unknown. Count it
		// so the surface reports partial rather than complete: a role whose
		// boundary we could not read must not be presented as a role with no
		// boundary.
		counters["roles_detail_incomplete"]++
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
	stored, created, err := s.identities.UpsertIdentity(identity)
	if err != nil {
		return fmt.Errorf("record identity %s: %w", identity.NativeID, err)
	}
	if created {
		counters["identities_new"]++
	} else {
		counters["identities_updated"]++
	}

	// The evidence for this row. Recorded from the identity we just wrote
	// rather than from the raw SDK struct: what is stored is what a reviewer
	// will be shown, and evidence for a different shape than the one on screen
	// explains nothing.
	//
	// A failure here does NOT fail the scan. Losing the explanation for a row
	// is bad; losing the row is worse, and an inventory that refuses to record
	// an identity because its evidence write failed is the wrong trade.
	if err := s.recordIdentityEvidence(stored, identity); err != nil {
		log.Printf("aws iam scan: evidence for %s: %v", identity.NativeID, err)
	}
	return nil
}

func (s *AWSIAMScanner) recordIdentityEvidence(
	stored *models.CloudIdentity, identity *models.CloudIdentity,
) error {
	if s.evidence == nil || stored == nil {
		return nil
	}
	attrs := identity.AWSAttrs()
	api := "iam:GetRole"
	surface := models.SurfaceIAMRoles
	if identity.Kind == models.CloudIdentityIAMUser {
		api, surface = "iam:ListUsers", models.SurfaceIAMUsers
	}
	// observed_at is the provider's own creation time where AWS gave one. It is
	// not "now": conflating them makes a delayed scan look like a change.
	observed := time.Now()
	if identity.ProviderCreatedAt != nil {
		observed = *identity.ProviderCreatedAt
	}
	return s.evidence.Record(
		IdentitySubject(stored.ID), api, surface, s.evidenceSurfaceState(surface),
		observed, stored.NativeID,
		map[string]any{
			"kind":                     identity.Kind,
			"native_id":                identity.NativeID,
			"name":                     identity.Name,
			"unique_id":                attrs.UniqueID,
			"path":                     attrs.Path,
			"max_session_duration":     attrs.MaxSessionDuration,
			"tags":                     attrs.Tags,
			"has_trust_policy":         attrs.HasTrustPolicy,
			"permissions_boundary_arn": attrs.PermissionsBoundaryARN,
			"detail_incomplete":        attrs.DetailIncomplete,
		},
	)
}

// evidenceSurfaceState reports what coverage said about a surface at the moment
// evidence under it was written, so a fact collected during a degraded read
// stays readable as such.
func (s *AWSIAMScanner) evidenceSurfaceState(surface string) string {
	if s.lastCoverage.Surfaces == nil {
		return ""
	}
	return SurfaceStateOf(s.lastCoverage, surface)
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

// scanCredentialReport reads the account credential report and records one
// observation per user this same scan already wrote, matched by ARN. A user
// the report mentions but this scan's ListUsers did not (a timing gap between
// two calls that are not transactional with each other) is skipped rather
// than guessed at.
func (s *AWSIAMScanner) scanCredentialReport(
	ctx context.Context, workspaceID, connectorID uuid.UUID, users []awsdiscovery.IAMUser,
) (int, error) {
	reader, err := s.credentialReportReaderFor(ctx, workspaceID, connectorID)
	if err != nil {
		return 0, err
	}
	rows, err := reader.Report(ctx)
	if err != nil {
		return 0, err
	}
	if s.evidence == nil {
		return len(rows), nil
	}
	byARN := make(map[string]awsdiscovery.IAMUser, len(users))
	for _, u := range users {
		byARN[u.ARN] = u
	}
	for _, row := range rows {
		if _, known := byARN[row.UserARN]; !known {
			continue
		}
		identity, ierr := s.identities.GetIdentityByNativeID(workspaceID, row.UserARN)
		if ierr != nil {
			continue
		}
		if rerr := s.evidence.Record(
			IdentitySubject(identity.ID), "iam:GetCredentialReport",
			"iam_credential_report", "", time.Now(), row.UserARN,
			map[string]any{
				"password_enabled":        row.PasswordEnabled,
				"password_last_used":      row.PasswordLastUsed,
				"mfa_active":              row.MFAActive,
				"access_key_1_active":     row.AccessKey1Active,
				"access_key_1_rotated_at": row.AccessKey1LastRotated,
				"access_key_1_last_used":  row.AccessKey1LastUsedAt,
				"access_key_2_active":     row.AccessKey2Active,
				"access_key_2_rotated_at": row.AccessKey2LastRotated,
				"access_key_2_last_used":  row.AccessKey2LastUsedAt,
			},
		); rerr != nil {
			log.Printf("aws iam scan: credential report evidence for %s: %v", row.UserARN, rerr)
		}
	}
	return len(rows), nil
}

// credentialReportReaderFor mirrors readerFor: an injected client wins, for
// tests; otherwise a real one is built from the same assumed-role config the
// IAM reader itself would use.
func (s *AWSIAMScanner) credentialReportReaderFor(
	ctx context.Context, workspaceID, connectorID uuid.UUID,
) (*awsdiscovery.CredentialReportReader, error) {
	if s.credentialAPI != nil {
		r := awsdiscovery.NewCredentialReportReader(s.credentialAPI)
		if s.credentialSleep != nil {
			r = r.WithSleep(s.credentialSleep)
		}
		return r, nil
	}
	if s.onboarding == nil {
		return nil, errors.New("no credential report client and no onboarding service to assume a role with")
	}
	cfg, _, err := s.onboarding.ConfigForConnector(ctx, workspaceID, connectorID, "")
	if err != nil {
		return nil, err
	}
	return awsdiscovery.NewCredentialReportReader(awsdiscovery.NewCredentialReportClient(cfg)), nil
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

// FinalizeCoverage folds the permission- and workload-scan results into the
// connector's coverage report and recomputes the overall status.
//
// WHY THIS EXISTS
// Scan() commits a coverage report based on its own four surfaces the moment
// it returns -- necessarily, since it has no way to know whether the
// permission and workload scans that come after it will succeed. Without this
// call, that premature report is the one that stays: a customer whose Bedrock
// or EKS read was denied would see coverage.status = "complete" simply
// because IAM itself was fully readable, with the actual gap visible only in
// a server log. This call replaces that report with the true, cumulative one
// once every surface this scan touches has actually been attempted.
//
// It never moves the generation. Scan() already advanced it; this only
// corrects what is filed under that same generation.
//
// Returns the merged report so the caller can also stamp it onto the specific
// cloud_scan_run that produced it (CloudScanRunRepository.SetCoverage). That
// per-run copy, not this method's write to the connector, is what a reader
// must consult to ask "was THIS run complete" -- the connector's copy is
// overwritten by whatever scan runs next and answers only for the newest one.
func (s *AWSIAMScanner) FinalizeCoverage(
	workspaceID, connectorID uuid.UUID, iamCoverage models.ScanCoverage,
	credentialReportSurface models.SurfaceCoverage,
	permErr error, permSurfaces map[string]models.SurfaceCoverage,
	workloadErr error, workloadSurfaces map[string]models.SurfaceCoverage,
) models.ScanCoverage {
	merged := models.ScanCoverage{
		Generation: iamCoverage.Generation,
		StartedAt:  iamCoverage.StartedAt,
		FinishedAt: iamCoverage.FinishedAt,
		Counters:   iamCoverage.Counters,
		Surfaces:   map[string]models.SurfaceCoverage{},
	}
	for k, v := range iamCoverage.Surfaces {
		merged.Surfaces[k] = v
	}
	// Merged here, for connector-level display only -- never part of
	// iamCoverage itself, so it never reached the reconcile gate inside Scan,
	// nor the permission/workload scanners' own snapshot.Coverage.Complete()
	// checks. A denied credential report is honest to show as "partial"
	// overall; it must never be a reason to refuse deleting a stale identity.
	if credentialReportSurface.State != "" {
		merged.Surfaces["iam_credential_report"] = credentialReportSurface
	}

	// A scanner that returned an error before producing a snapshot at all
	// (could not assume the role, connector vanished mid-scan, …) gets one
	// surface entry standing in for the surfaces it never got to attempt --
	// the same reasoning as workload_scan.go's own "compute:region" entry.
	if permErr != nil && permSurfaces == nil {
		merged.Surfaces["permission_scan"] = models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Error: permErr.Error(),
		}
	}
	for k, v := range permSurfaces {
		merged.Surfaces[k] = v
	}
	if workloadErr != nil && workloadSurfaces == nil {
		merged.Surfaces["workload_scan"] = models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Error: workloadErr.Error(),
		}
	}
	for k, v := range workloadSurfaces {
		merged.Surfaces[k] = v
	}

	if merged.Complete() {
		merged.Status = models.ScanStatusComplete
	} else {
		merged.Status = models.ScanStatusPartial
	}
	// iamCoverage.Status is already "failed" or "running" only in paths that
	// never reach this call (Scan returns an error and the controller never
	// calls FinalizeCoverage); every path that does call this has a
	// commitScan-produced complete/partial status to refine, never failed.
	s.persistCoverage(workspaceID, connectorID, merged)
	return merged
}

// surfaceResult turns a read's outcome into a coverage entry.
//
// The count is reported even on failure, where it is a FLOOR rather than a
// total — we read this many before we were stopped. The state is what tells a
// reader which of the two it is.
// surfacePartial reports a surface that was listed successfully but whose
// contents are not fully known -- for example roles listed by ListRoles whose
// GetRole detail failed.
//
// Kept distinct from an error: the list call worked, so the rows are real and
// worth keeping. What must not happen is reconciliation treating this run as an
// authoritative inventory and deleting what it could not read.
func surfacePartial(count int, incomplete int, reason string) models.SurfaceCoverage {
	return models.SurfaceCoverage{
		State: models.CloudCoveragePartial,
		Count: count,
		Error: fmt.Sprintf("%d of %d %s", incomplete, count, reason),
	}
}

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
