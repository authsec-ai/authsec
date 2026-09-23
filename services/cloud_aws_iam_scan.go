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
// What this writes: cloud_identity (IAM roles, users and groups, with each
// role's trust document), cloud_secret (access keys) and cloud_group_membership.
//
// What it READS: the whole IAM configuration, through
// iam:GetAccountAuthorizationDetails, one paginated call per filter (SPEC
// T3.1, P2-DECISIONS D-48), plus GetPolicy/GetPolicyVersion for the AWS-managed
// policies a principal attaches or is bounded by. The policy documents are
// handed to the permission scanner in the IAMSnapshot, which writes them as
// cloud_policy rows (035) and, for Cloud Inventory, cloud_permission.

// iamScanTimeout bounds one whole scan.
//
// A large account is hundreds of authorization-details pages, one
// GetPolicyVersion per attached AWS-managed policy and two calls per access
// key, under a retrying client. Twenty minutes is generous for that and still
// short enough that a wedged scan releases its connector rather than blocking
// every later one forever.
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

	// generation, when set, is the scan run's own generation (T1.5). Zero only
	// for a caller with no run -- a test, a legacy path -- which falls back to
	// scan_generation + 1.
	generation int

	// policies writes group memberships (035), fenced like identities.
	policies repositories.CloudPolicyRepository
}

// WithGeneration stamps every row with the RUN's generation instead of
// recomputing connector.scan_generation + 1 (§1.3). A reclaimed run keeps the
// generation assigned at its first claim; recomputing it here named a
// different number from the one the run's evidence and projection job carry.
func (s *AWSIAMScanner) WithGeneration(g int) *AWSIAMScanner {
	s.generation = g
	return s
}

// WithEvidence attaches an observation writer for this run.
func (s *AWSIAMScanner) WithEvidence(w *ObservationWriter) *AWSIAMScanner {
	s.evidence = w
	return s
}

// WithFence makes every inventory write refuse to commit once this worker
// has lost the run (§2.10A, part 3). Applied to the identity repo, which
// carries this scanner's UpsertIdentity and UpsertSecret writes.
func (s *AWSIAMScanner) WithFence(f repositories.ScanFence) *AWSIAMScanner {
	s.identities = s.identities.Fenced(f)
	s.policies = s.policies.Fenced(f)
	return s
}

// NewAWSIAMScanner constructs the scanner.
func NewAWSIAMScanner(db *gorm.DB, onboarding *AWSOnboardingService) *AWSIAMScanner {
	return &AWSIAMScanner{
		db:          db,
		connectors:  repositories.NewCloudConnectorRepository(db),
		identities:  repositories.NewCloudIdentityRepository(db),
		checkpoints: repositories.NewCloudScanCheckpointRepository(db),
		policies:    repositories.NewCloudPolicyRepository(db),
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
	// identity ARN: its attachments, inline documents and boundary, exactly as
	// its authorization-details entry listed them. Absent for an identity with
	// none, and for one its listing never reached.
	Policies map[string]awsdiscovery.IdentityPolicies

	// ManagedPolicies is every managed policy the read resolved, by ARN (T3.1):
	// every customer-managed policy in the account -- ATTACHED OR NOT -- and
	// every AWS-managed policy a principal attaches or is bounded by. The
	// permission scanner writes ONE cloud_policy row per entry, so a policy
	// detached from its last holder keeps its row (§2.15) and an AWS-managed
	// policy is one row per connector however many principals attach it.
	ManagedPolicies map[string]awsdiscovery.AttachedPolicy

	// TrustPolicies is the decoded AssumeRolePolicyDocument per role ARN, the
	// input for cloud_assume_edge in ticket [2].
	TrustPolicies map[string]string

	// UnreadableTrust names each role whose trust document is unreadable this
	// run, with the reason stored on its row (trust_parse_error), so
	// policy_documents names it beside the unreadable policies (T3.3, D-71).
	UnreadableTrust []models.CoverageItem

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

	// The run's own generation (T1.5); scan_generation + 1 only for a caller
	// with no run.
	//
	// NO RESUME. The per-identity policy phase a checkpoint used to let a
	// second attempt skip no longer exists: the whole configuration is a
	// handful of paginated listings, re-read in full by every attempt, so
	// nothing here depends on what an interrupted attempt managed to write
	// (the spec is silent; the conservative reading, reported for review).
	generation := connector.ScanGeneration + 1
	if s.generation > 0 {
		generation = s.generation
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
		ConnectorID:     connectorID,
		AccountID:       connector.ScopeID,
		Generation:      generation,
		Policies:        map[string]awsdiscovery.IdentityPolicies{},
		ManagedPolicies: map[string]awsdiscovery.AttachedPolicy{},
		TrustPolicies:   map[string]string{},
	}

	// ---- the IAM configuration: authorization details (T3.1) ---------------
	//
	// One paginated call per filter, each its own surface (D-48). Everything
	// below is from this one read, so a principal, its attachments and the
	// documents they name are one picture. A policy document that could not be
	// read is recorded on that policy, never on the listing (§1.4).
	details := reader.AuthorizationDetails(ctx)

	// ---- roles -------------------------------------------------------------
	for _, role := range details.Roles {
		identity, err := s.upsertRole(workspaceID, connectorID, generation, role, coverage.Counters)
		if err != nil {
			return nil, err
		}
		if role.TrustPolicy != "" {
			snapshot.TrustPolicies[role.ARN] = role.TrustPolicy
		}
		if identity.TrustParseError != "" {
			snapshot.UnreadableTrust = append(snapshot.UnreadableTrust, models.CoverageItem{
				Policy: "trust policy of " + role.Name, Error: identity.TrustParseError,
			})
		}
		snapshot.addPolicies(role.ARN, role.Policies)
	}
	coverage.Surfaces[models.SurfaceIAMRoles] = surfaceResult(len(details.Roles), details.RolesErr)

	// ---- users and their access keys ---------------------------------------
	keyCount := 0
	var keysErr error
	userIDByARN := make(map[string]uuid.UUID, len(details.Users))
	for _, user := range details.Users {
		identity, err := s.upsertUser(workspaceID, connectorID, generation, user, coverage.Counters)
		if err != nil {
			return nil, err
		}
		userIDByARN[user.ARN] = identity.ID
		snapshot.addPolicies(user.ARN, user.Policies)
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
	coverage.Surfaces[models.SurfaceIAMUsers] = surfaceResult(len(details.Users), details.UsersErr)
	coverage.Surfaces[models.SurfaceIAMAccessKeys] = surfaceResult(keyCount, keysErr)

	// ---- groups and memberships (035) --------------------------------------
	//
	// Groups are identities (§2.2). Their policies join snapshot.Policies like
	// any holder's, so the permission scanner writes them the same way. A
	// membership is written only when BOTH ends were read by this scan --
	// never against a user or group this read did not list.
	groupIDByARN := make(map[string]uuid.UUID, len(details.Groups))
	for _, g := range details.Groups {
		identity, err := s.upsertGroup(workspaceID, connectorID, generation, g, coverage.Counters)
		if err != nil {
			return nil, err
		}
		groupIDByARN[g.ARN] = identity.ID
		snapshot.addPolicies(g.ARN, g.Policies)
	}
	memberships := 0
	for userARN, groupARNs := range details.Members {
		uid, ok := userIDByARN[userARN]
		if !ok {
			continue
		}
		for _, gARN := range groupARNs {
			gid, ok := groupIDByARN[gARN]
			if !ok {
				continue
			}
			if err := s.policies.UpsertMembership(&models.CloudGroupMembership{
				WorkspaceID: workspaceID, ConnectorID: connectorID,
				UserIdentityID: uid, GroupIdentityID: gid,
				LastSeenGeneration: generation,
			}); err != nil {
				return nil, fmt.Errorf("record membership %s -> %s: %w", userARN, gARN, err)
			}
			memberships++
		}
	}
	coverage.Surfaces[models.SurfaceIAMGroups] = surfaceResult(len(details.Groups), details.GroupsErr)
	coverage.Counters["group_memberships"] = memberships

	// ---- policies ----------------------------------------------------------
	//
	// iam_policies is the LocalManagedPolicy listing's outcome: "reached when
	// the authorization-details listing completed" (§1.4). One document that
	// could not be fetched or parsed is NOT a reason to call it partial --
	// that would veto every policy partition in the account -- but a
	// FetchError on that one policy, reported under policy_documents.
	snapshot.ManagedPolicies = details.ManagedPolicies
	policyCount := len(details.ManagedPolicies)
	for _, p := range snapshot.Policies {
		policyCount += len(p.Inline)
	}
	coverage.Surfaces[models.SurfaceIAMPolicies] = surfaceResult(policyCount, details.PoliciesErr)
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
		removedMemberships, err := s.policies.ReconcileMemberships(workspaceID, connectorID, generation)
		if err != nil {
			return nil, err
		}
		coverage.Counters["memberships_removed"] = int(removedMemberships)
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
	reportCount, reportErr := s.scanCredentialReport(ctx, workspaceID, connectorID, details.Users)
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

// addPolicies hands one principal's policies to the permission scanner. An
// identity with none has no entry.
func (snap *IAMSnapshot) addPolicies(arn string, p awsdiscovery.IdentityPolicies) {
	if len(p.Attached) > 0 || len(p.Inline) > 0 || p.Boundary != nil {
		snap.Policies[arn] = p
	}
}

/* -------------------------------- upserts --------------------------------- */

// roleAttrsNotRead are the attrs keys RoleDetail does not carry (D-48). A
// role's stored description and max session duration -- written by an
// earlier GetRole-based read -- are KEPT rather than blanked, because this
// read says nothing about them: for the same role only (same unique id),
// never inherited by one recreated under its ARN. Everything else in attrs is
// replaced: tags and the permissions boundary ARE in the listing, so their
// removal in AWS must be observed as removal.
var roleAttrsNotRead = []string{"description", "max_session_duration"}

func (s *AWSIAMScanner) upsertRole(
	workspaceID, connectorID uuid.UUID, generation int,
	role awsdiscovery.IAMRole, counters map[string]int,
) (*models.CloudIdentity, error) {
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
	profiles := instanceProfiles(role.InstanceProfiles)
	if err := identity.SetAWSAttrs(models.AWSIdentityAttrs{
		UniqueID:               role.UniqueID,
		Path:                   role.Path,
		Tags:                   role.Tags,
		HasTrustPolicy:         role.TrustPolicy != "",
		PermissionsBoundaryARN: role.PermissionsBoundaryARN,
		// D-52: in attrs, replaced on every read (it is not in
		// roleAttrsNotRead), so a role taken out of a profile loses it.
		InstanceProfiles: profiles,
	}); err != nil {
		return nil, err
	}
	setRoleTrustDocument(identity, role.TrustPolicy)

	listed := listedPolicyFacts(role.Policies)
	// As plain maps, so the redactor walks them like every other fact.
	profileFacts := make([]any, 0, len(profiles))
	for _, p := range profiles {
		profileFacts = append(profileFacts, map[string]any{"arn": p.ARN, "name": p.Name})
	}
	listed["instance_profiles"] = profileFacts
	// The role's observation CARRIES its trust document (§4.8): can_assume
	// evidence is the role's own observation. Decoded, so the redactor walks it
	// like any other fact; the text itself when it is not JSON.
	listed["trust_document"] = trustDocumentFact(role.TrustPolicy)
	listed["trust_document_hash"] = identity.TrustDocumentHash
	listed["trust_parse_error"] = identity.TrustParseError
	if err := s.recordIdentity(identity, counters, listed, roleAttrsNotRead...); err != nil {
		return nil, err
	}
	return identity, nil
}

// setRoleTrustDocument records a role's trust document on its row (035; T3.1
// collects it, T3.3 judges it). The document verbatim as jsonb -- NULL when it
// is not JSON, which a jsonb column refuses -- the sha256 of the text as read,
// and trust_parse_error: the verdict of the trust parser the projector runs
// (awsdiscovery.ValidateTrustDocument, D-45), so a role recorded readable here
// cannot fail to parse there. Non-empty means that role's trust edges go stale,
// never ended (§4.10). A role whose entry carried no document at all is
// unreadable too: it cannot be read as trusting nobody.
//
// Written on EVERY scan through the fenced UpsertIdentity, which names the
// three columns, so a document fixed in AWS clears its error.
func setRoleTrustDocument(identity *models.CloudIdentity, doc string) {
	var raw json.RawMessage
	if doc != "" {
		raw = json.RawMessage(doc)
		identity.TrustDocumentHash = documentHash(doc)
		if json.Valid(raw) {
			identity.TrustDocument = raw
		}
	}
	identity.TrustParseError = awsdiscovery.ValidateTrustDocument(raw)
}

// instanceProfiles is a role's InstanceProfileList as attrs store it, sorted by
// ARN so an unchanged list is an unchanged row and an unchanged observation.
// Nil for none, so the key is absent rather than an empty list.
func instanceProfiles(in []awsdiscovery.InstanceProfileRef) []models.AWSInstanceProfile {
	if len(in) == 0 {
		return nil
	}
	out := make([]models.AWSInstanceProfile, 0, len(in))
	for _, p := range in {
		out = append(out, models.AWSInstanceProfile{ARN: p.ARN, Name: p.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ARN < out[j].ARN })
	return out
}

// trustDocumentFact is the trust document as an observation fact: decoded when
// it is JSON, so the redactor sees its keys; the raw text otherwise.
func trustDocumentFact(doc string) any {
	if doc == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		return doc
	}
	return v
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
		// Console sign-in (PasswordLastUsed) is deliberately never written to
		// last_used_at: that column means "this identity did something", and a
		// human logging in says nothing about whether the credential a workload
		// uses is live. Authorization details do not carry it anyway.
		ProviderCreatedAt:  user.CreatedAt,
		Enabled:            true,
		LastSeenGeneration: generation,
	}
	if err := identity.SetAWSAttrs(models.AWSIdentityAttrs{
		UniqueID: user.UniqueID,
		Path:     user.Path,
		Tags:     user.Tags,
		// Read for the first time (§1.3): with it, the user's statements are
		// stored 'bounded' instead of 'unconstrained'.
		PermissionsBoundaryARN: user.PermissionsBoundaryARN,
	}); err != nil {
		return nil, err
	}
	listed := listedPolicyFacts(user.Policies)
	// member_of evidence is the user's observation, which lists the group
	// (§4.8): the entry's GroupList, verbatim and sorted.
	groups := append([]string{}, user.GroupNames...)
	sort.Strings(groups)
	listed["groups"] = groups
	if err := s.recordIdentity(identity, counters, listed); err != nil {
		return nil, err
	}
	return identity, nil
}

// upsertGroup records one IAM group. GroupId is its creation boundary, carried
// in attrs.unique_id like RoleId and UserId, so a group deleted and recreated
// under the same name is a different object (§2.4).
func (s *AWSIAMScanner) upsertGroup(
	workspaceID, connectorID uuid.UUID, generation int,
	group awsdiscovery.IAMGroup, counters map[string]int,
) (*models.CloudIdentity, error) {
	identity := &models.CloudIdentity{
		WorkspaceID:        workspaceID,
		ConnectorID:        connectorID,
		Kind:               models.CloudIdentityIAMGroup,
		NativeID:           group.ARN,
		Name:               group.Name,
		ProviderCreatedAt:  group.CreatedAt,
		Enabled:            true,
		LastSeenGeneration: generation,
	}
	if err := identity.SetAWSAttrs(models.AWSIdentityAttrs{
		UniqueID: group.UniqueID,
		Path:     group.Path,
	}); err != nil {
		return nil, err
	}
	if err := s.recordIdentity(identity, counters, listedPolicyFacts(group.Policies)); err != nil {
		return nil, err
	}
	return identity, nil
}

// listedPolicyFacts is what a principal's entry lists about its policies, for
// its observation: grant and assignment evidence is the policy version's
// observation AND the holder's, "whose authorization-details entry lists the
// attachment" (§4.8). ARNs and names only, sorted; the documents are the
// policies' own observations.
func listedPolicyFacts(p awsdiscovery.IdentityPolicies) map[string]any {
	attached := make([]string, 0, len(p.Attached))
	for _, a := range p.Attached {
		attached = append(attached, a.ARN)
	}
	inline := make([]string, 0, len(p.Inline))
	for _, in := range p.Inline {
		inline = append(inline, in.Name)
	}
	sort.Strings(attached)
	sort.Strings(inline)
	return map[string]any{"attached_policies": attached, "inline_policies": inline}
}

func (s *AWSIAMScanner) recordIdentity(
	identity *models.CloudIdentity, counters map[string]int, listed map[string]any, keepAttrs ...string,
) error {
	stored, created, err := s.identities.UpsertIdentity(identity, keepAttrs...)
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
	if err := s.recordIdentityEvidence(stored, identity, listed); err != nil {
		log.Printf("aws iam scan: evidence for %s: %v", identity.NativeID, err)
	}
	return nil
}

func (s *AWSIAMScanner) recordIdentityEvidence(
	stored *models.CloudIdentity, identity *models.CloudIdentity, listed map[string]any,
) error {
	if s.evidence == nil || stored == nil {
		return nil
	}
	attrs := identity.AWSAttrs()
	// One observation per role, user and group, citing the call that returned
	// it (§1.4): every one of them is an authorization-details entry now.
	const api = "iam:GetAccountAuthorizationDetails"
	surface := models.SurfaceIAMRoles
	switch identity.Kind {
	case models.CloudIdentityIAMUser:
		surface = models.SurfaceIAMUsers
	case models.CloudIdentityIAMGroup:
		surface = models.SurfaceIAMGroups
	}
	// observed_at is the provider's own creation time where AWS gave one. It is
	// not "now": conflating them makes a delayed scan look like a change.
	observed := time.Now()
	if identity.ProviderCreatedAt != nil {
		observed = *identity.ProviderCreatedAt
	}
	// What THIS read returned, and nothing it did not: a description or max
	// session kept from an earlier read (D-48) is not a fact this observation
	// can vouch for.
	facts := map[string]any{
		"kind":                     identity.Kind,
		"native_id":                identity.NativeID,
		"name":                     identity.Name,
		"unique_id":                attrs.UniqueID,
		"path":                     attrs.Path,
		"tags":                     attrs.Tags,
		"has_trust_policy":         attrs.HasTrustPolicy,
		"permissions_boundary_arn": attrs.PermissionsBoundaryARN,
	}
	for k, v := range listed {
		facts[k] = v
	}
	return s.evidence.Record(
		IdentitySubject(stored.ID), api, surface, s.evidenceSurfaceState(surface),
		observed, stored.NativeID, facts,
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
	// T3.5: the key's observation, keyed by the key id (cloud_aws_collection_evidence.go).
	s.recordAccessKeyEvidence(identityID, key)
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
		merged.Surfaces[models.SurfaceIAMCredentialReport] = credentialReportSurface
	}
	// T3.8: SCPs are never read, and coverage says so on every AWS scan rather
	// than staying silent. unsupported: Complete() skips it, no partition
	// requires it, so it gates nothing (§1.4).
	merged.Surfaces[models.SurfaceOrganizations] = models.OrganizationsCoverage()

	// A scanner that returned an error before producing a snapshot at all
	// (could not assume the role, connector vanished mid-scan, …) gets one
	// surface entry standing in for the surfaces it never got to attempt --
	// the same reasoning as workload_scan.go's own "compute:region" entry.
	//
	// Each carries the call and the AWS code the failure named, when it named
	// them (§5.3 /coverage api, error_code; D-71): a role that could not be
	// assumed for the permission scan says sts:AssumeRole and AWS's code, not
	// only prose.
	if permErr != nil && permSurfaces == nil {
		merged.Surfaces[models.SurfacePermissionScan] = withFailedCall(models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Error: permErr.Error(),
		}, permErr)
	}
	for k, v := range permSurfaces {
		merged.Surfaces[k] = v
	}
	if workloadErr != nil && workloadSurfaces == nil {
		merged.Surfaces[models.SurfaceWorkloadScan] = withFailedCall(models.SurfaceCoverage{
			State: models.CloudCoverageDenied, Error: workloadErr.Error(),
		}, workloadErr)
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

// surfacePartial reports a surface that was listed successfully but whose
// contents are not fully known -- for example a listing whose per-item detail
// call failed for some items. (The IAM read no longer has one: authorization
// details carry every detail in the listing itself. Kept for the other
// scanners' detail calls.)
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

// surfaceResult turns a read's outcome into a coverage entry.
//
// The count is reported even on failure, where it is a FLOOR rather than a
// total — we read this many before we were stopped. The state is what tells a
// reader which of the two it is.
//
// A failure that names its call (awsdiscovery.APICallError) also stamps the
// call and AWS's error code as fields (D-71), so /coverage reports them
// without parsing the prose. Any other error leaves both empty: unknown is
// said as unknown, never inferred from the message.
func surfaceResult(count int, err error) models.SurfaceCoverage {
	// unsupported and partial (T3.6-T3.8), and any failure a reader named
	// with its call: see cloud_aws_collection_coverage.go.
	if cov, ok := collectionCoverage(count, err); ok {
		return cov
	}
	var out models.SurfaceCoverage
	switch {
	case err == nil:
		return models.SurfaceCoverage{State: models.CloudCoverageReached, Count: count}
	case errors.Is(err, awsdiscovery.ErrThrottled):
		out = models.SurfaceCoverage{State: models.CloudCoverageThrottled, Count: count, Error: err.Error()}
	default:
		out = models.SurfaceCoverage{State: models.CloudCoverageDenied, Count: count, Error: err.Error()}
	}
	var call *awsdiscovery.APICallError
	if errors.As(err, &call) {
		out.API, out.ErrorCode = call.API, call.Code
	}
	if out.API == "" && out.ErrorCode == "" {
		// Neither named layer caught it: the SDK's own operation error, or
		// nothing when it carries none.
		out = withFailedCall(out, err)
	}
	return out
}

// withFailedCall records the call and the AWS error code the failure carried,
// as the SDK stated them (§5.3 /coverage error_code, api) -- and nothing when
// it carried neither.
func withFailedCall(s models.SurfaceCoverage, err error) models.SurfaceCoverage {
	s.API, s.ErrorCode = awsdiscovery.FailedCall(err)
	return s
}

func ptrTime(t time.Time) *time.Time { return &t }
