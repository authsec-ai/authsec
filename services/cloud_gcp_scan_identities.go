package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

/* cloud_gcp_scan_identities.go holds Phase 1's collectors: service accounts and
   their user-managed keys.

   SEPARATE FROM THE RUNNER ON PURPOSE. A collector takes a context, a client, a
   snapshot and an accumulator, and returns. It never allocates a generation,
   never writes coverage, never reconciles and never decides whether a scan was
   complete. That boundary is what lets the runner's goroutine be replaced by a
   leased worker later without any of this code changing.

   THE RECOGNITION KEY. cloud_identity.native_id is built from the service
   account's uniqueId, not its email. GCP's own guidance and the GCP plan's
   section 3 agree: an email is an address and a unique id is an identity.
   Delete a service account and create a new one at the same address and GCP
   issues a new unique id -- keying on the email would silently merge the two,
   and the new account would inherit the old one's history under a
   UNIQUE(workspace_id, native_id) upsert. The email is kept in attrs, where it
   belongs: it is how every IAM binding and every human refers to the account,
   and it is the join key for policy data in a later phase. */

// gcpMaxPages bounds pagination per project, per surface.
//
// Not expected to bind. It exists so a provider that keeps handing back a page
// token cannot turn one project into an unbounded scan -- the same guard
// internal/awsdiscovery/iam.go:72 keeps for the same reason.
const gcpMaxPages = 200

// gcpServiceAccountPageSize is the page size requested from GCP.
const gcpServiceAccountPageSize = 100

// errTooManyGCPPages means pagination hit the ceiling.
//
// Returned as an error rather than silently truncating, because a truncated
// read must not be reported as reached. A capped read that reports success is
// precisely how cloud_usage rows get deleted for identities past a cap
// elsewhere in this codebase; nothing here repeats it.
var errTooManyGCPPages = fmt.Errorf("gcp: pagination exceeded %d pages", gcpMaxPages)

/* ------------------------------ project set --------------------------------- */

// resolveProjects determines which projects this scan will read.
//
// A project connector is its own project set and needs no enumeration -- the
// common case, and the one that costs exactly one call either way.
//
// An org or folder connector must enumerate, because iam.serviceAccounts.list
// is project-scoped and has no organization-wide form. If the reader cannot
// enumerate, this returns an error and BOTH Phase 1 surfaces are recorded
// not-reached: a connector that cannot see the projects has not discovered an
// empty estate, it has failed to look.
func (s *GCPScanner) resolveProjects(
	ctx context.Context, connector *models.CloudConnector,
	attrs models.GCPConnectorAttrs, authOpt option.ClientOption, governor *gcp.Governor,
) ([]gcpProject, error) {
	if connector.ScopeKind == models.CloudScopeProject {
		return []gcpProject{{ProjectID: connector.ScopeID}}, nil
	}

	// Onboarding already probed whether the tree can be walked and stored the
	// answer. Asking GCP again would cost calls to learn something already
	// known -- and a probe that came back unknown is not proof of refusal, so
	// only a definite "no" short-circuits here.
	if enum := decodeScopeEnumeration(attrs.ScopeEnumeration); enum != nil && !enum.Usable() && !enum.Unknown {
		return nil, fmt.Errorf("%w: the reader cannot enumerate projects below %s/%s",
			gcp.ErrPermissionDenied, connector.ScopeKind, connector.ScopeID)
	}

	enumCtx, cancel := context.WithTimeout(ctx, gcpEnumerateTimeout)
	defer cancel()

	rm, err := s.newRMClient(enumCtx, authOpt)
	if err != nil {
		return nil, err
	}

	query, err := gcpProjectSearchQuery(connector.ScopeKind, connector.ScopeID)
	if err != nil {
		return nil, err
	}

	// Paginated by hand rather than with .Pages(), so that EACH page is
	// separately rate-limited and separately retried.
	//
	// The generated .Pages() helper walks every page inside one call, which
	// would put the whole walk inside one Retry and one limiter token: a
	// hundred-page enumeration would take one token and, on a 429 at page
	// ninety, discard eighty-nine good pages and re-fetch them all. Under
	// throttling that issues MORE calls, not fewer, which is the opposite of
	// backing off.
	var (
		projects  []gcpProject
		pageToken string
	)
	for page := 0; page < gcpMaxPages; page++ {
		var resp *cloudresourcemanager.SearchProjectsResponse
		token := pageToken
		if err := gcp.Retry(enumCtx, func() error {
			if err := governor.ResourceManager.Wait(enumCtx); err != nil {
				return err
			}
			out, callErr := rm.Projects.Search().
				Query(query).PageToken(token).Context(enumCtx).Do()
			if callErr != nil {
				return callErr
			}
			resp = out
			return nil
		}); err != nil {
			return nil, err
		}

		for _, p := range resp.Projects {
			// A project being deleted is not part of the estate and its service
			// accounts are on their way out with it. Reading it would add rows
			// that the next scan correctly removes.
			if p.State != "" && p.State != "ACTIVE" {
				continue
			}
			projects = append(projects, gcpProject{
				ProjectID: p.ProjectId,
				Number:    projectNumberFromName(p.Name),
			})
		}

		if resp.NextPageToken == "" {
			return projects, nil
		}
		pageToken = resp.NextPageToken
	}
	// Ran out of page budget with more to come. Returned as an error so the
	// surfaces record not-reached: a truncated project list would otherwise
	// look exactly like an org that owns fewer projects than it does.
	return nil, errTooManyGCPPages
}

// gcpProjectSearchQuery builds the Resource Manager search filter for a scope.
func gcpProjectSearchQuery(scopeKind, scopeID string) (string, error) {
	switch scopeKind {
	case models.CloudScopeOrg:
		return "parent:organizations/" + scopeID, nil
	case models.CloudScopeFolder:
		return "parent:folders/" + scopeID, nil
	default:
		return "", fmt.Errorf("%w: cannot enumerate projects for scope kind %q",
			gcp.ErrInvalidGrant, scopeKind)
	}
}

// projectNumberFromName pulls the immutable number out of "projects/123456".
func projectNumberFromName(name string) string {
	return strings.TrimPrefix(name, "projects/")
}

/* --------------------------- service accounts ------------------------------- */

// collectIdentities reads every service account in each project.
//
// Returns the identities it durably wrote, so the key phase reads keys only for
// accounts that actually exist as rows -- a key whose identity was never
// written has nothing to hang off, and cloud_secret.identity_id is NOT NULL.
func (s *GCPScanner) collectIdentities(
	ctx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	client *iam.Service, governor *gcp.Governor, acc *gcpSurfaceAcc,
) []gcpWrittenIdentity {
	var (
		mu      sync.Mutex
		written []gcpWrittenIdentity
		wg      sync.WaitGroup
	)

	for _, project := range snapshot.Projects {
		// Checked before acquiring rather than inside the goroutine, so a dead
		// context stops SCHEDULING work rather than spawning goroutines that
		// immediately give up.
		if err := ctx.Err(); err != nil {
			acc.observe(err, 0)
			break
		}

		// Acquired on this goroutine, released on the worker's. That ordering is
		// what actually bounds the fan-out: the loop blocks here once the
		// governor's slots are taken, so at most ProjectConcurrency() projects
		// are ever in flight no matter how many an org owns.
		release, err := governor.AcquireProject(ctx)
		if err != nil {
			acc.observe(err, 0)
			break
		}

		wg.Add(1)
		go func(project gcpProject, release func()) {
			defer wg.Done()
			defer release()

			accounts, listErr := s.listServiceAccounts(ctx, client, governor, project)
			if listErr != nil {
				// Recorded against this project; the others still run. One
				// denied project must not cost the ones that can be read.
				acc.observe(listErr, 0)
				return
			}

			rows := make([]gcpWrittenIdentity, 0, len(accounts))
			var writeErr error
			for _, sa := range accounts {
				row, err := s.upsertServiceAccount(workspaceID, snapshot, project, sa)
				if err != nil {
					writeErr = err
					break
				}
				rows = append(rows, row)
			}

			mu.Lock()
			written = append(written, rows...)
			mu.Unlock()

			// A database failure is not a coverage state -- it says nothing
			// about what GCP would have returned. It still has to stop this
			// project being called reached, because rows are missing.
			acc.observe(writeErr, len(rows))
		}(project, release)
	}

	wg.Wait()
	return written
}

// gcpWrittenIdentity is an identity row the key phase needs to address.
type gcpWrittenIdentity struct {
	IdentityID uuid.UUID
	// Email is the address the keys API addresses the account by. The identity
	// itself is IdentityID; this is a locator, exactly as it is in attrs.
	Email string
}

func (s *GCPScanner) listServiceAccounts(
	ctx context.Context, client *iam.Service, governor *gcp.Governor, project gcpProject,
) ([]*iam.ServiceAccount, error) {
	// Per-page limiter token and per-page retry -- see resolveProjects for why
	// the generated .Pages() helper is not used.
	var (
		accounts  []*iam.ServiceAccount
		pageToken string
	)
	for page := 0; page < gcpMaxPages; page++ {
		var resp *iam.ListServiceAccountsResponse
		token := pageToken
		if err := gcp.Retry(ctx, func() error {
			if err := governor.IAM.Wait(ctx); err != nil {
				return err
			}
			out, callErr := client.Projects.ServiceAccounts.
				List("projects/" + project.ProjectID).
				PageSize(gcpServiceAccountPageSize).
				PageToken(token).
				Context(ctx).
				Do()
			if callErr != nil {
				return callErr
			}
			resp = out
			return nil
		}); err != nil {
			return nil, err
		}

		accounts = append(accounts, resp.Accounts...)
		if resp.NextPageToken == "" {
			return accounts, nil
		}
		pageToken = resp.NextPageToken
	}
	return nil, errTooManyGCPPages
}

func (s *GCPScanner) upsertServiceAccount(
	workspaceID uuid.UUID, snapshot *GCPScanSnapshot, project gcpProject, sa *iam.ServiceAccount,
) (gcpWrittenIdentity, error) {
	if sa.UniqueId == "" {
		// Without the unique id there is no stable identity to key on, and
		// falling back to the email would create exactly the silent-merge this
		// collector exists to avoid. Skipping is wrong too -- it would look
		// like the account does not exist -- so this is an error, which marks
		// the project not-reached and protects the estate from reconciliation.
		return gcpWrittenIdentity{}, fmt.Errorf(
			"gcp: service account %q in project %s has no uniqueId", sa.Email, project.ProjectID)
	}

	identity := &models.CloudIdentity{
		WorkspaceID: workspaceID,
		ConnectorID: snapshot.ConnectorID,
		Kind:        models.CloudIdentityGCPServiceAccount,
		NativeID:    gcpServiceAccountNativeID(sa),
		Name:        gcpServiceAccountName(sa),
		// GCP does not return a creation timestamp for a service account, and
		// inventing one would turn "we do not know how old this is" into a
		// date. Left nil, which is what nil means here.
		ProviderCreatedAt: nil,
		// Populating last_used_at needs Policy Analyzer, which is a later
		// phase. nil means UNKNOWN, never "never used".
		LastUsedAt:         nil,
		Enabled:            !sa.Disabled,
		LastSeenGeneration: snapshot.Generation,
	}
	if err := identity.SetGCPAttrs(models.GCPIdentityAttrs{
		UniqueID:       sa.UniqueId,
		Email:          sa.Email,
		ProjectID:      projectIDOf(project, sa),
		ProjectNumber:  project.Number,
		Description:    sa.Description,
		OAuth2ClientID: sa.Oauth2ClientId,
		Disabled:       sa.Disabled,
		IdentityKind:   "service_account",
	}); err != nil {
		return gcpWrittenIdentity{}, err
	}

	// Not a partial read: GCP lists service accounts with their full shape in one
	// call, and a project it could not read fails the scan outright rather than
	// yielding a half-populated account. So this always carries a complete blob,
	// and attrs is refreshed as before -- Disabled in particular is a state
	// transition that must land.
	stored, _, err := s.identities.UpsertIdentity(identity, false)
	if err != nil {
		return gcpWrittenIdentity{}, err
	}
	return gcpWrittenIdentity{IdentityID: stored.ID, Email: sa.Email}, nil
}

// gcpServiceAccountNativeID is the join key, and it is the service account's
// unique id ALONE -- no project segment.
//
// A GCP service account unique id is already globally unique and immutable, so
// a container adds nothing to identity. Including one actively breaks it: a
// project-scoped connector knows only the project ID string, while an
// org-scoped connector enumerates project NUMBERS, so the same service account
// seen through the two would produce two different native_ids and, under
// UNIQUE(workspace_id, native_id), two rows for one principal. Onboarding a
// project and later onboarding its parent org would fork the estate, and the
// orphaned half would then be reconciled away by a connector that never saw it.
//
// The project is not lost -- GCPIdentityAttrs carries both the id and the
// number. It is simply not part of the identity.
//
// The //iam.googleapis.com/ prefix stays: it keeps the value self-describing
// and cannot collide with an AWS ARN in the shared workspace-wide namespace.
func gcpServiceAccountNativeID(sa *iam.ServiceAccount) string {
	return "//iam.googleapis.com/serviceAccounts/" + sa.UniqueId
}

func gcpServiceAccountName(sa *iam.ServiceAccount) string {
	if sa.DisplayName != "" {
		return sa.DisplayName
	}
	return sa.Email
}

func projectIDOf(project gcpProject, sa *iam.ServiceAccount) string {
	if project.ProjectID != "" {
		return project.ProjectID
	}
	return sa.ProjectId
}

/* ------------------------------- keys --------------------------------------- */

// collectKeys reads user-managed keys for each service account written above.
//
// ONLY USER-MANAGED. A google-managed key is rotated by Google, never leaves
// it, and cannot be leaked by a customer -- recording it would add rows that
// look like credentials at risk and are not. The API is asked to filter rather
// than filtering here, so the unwanted keys are never returned at all.
//
// The key value is never touched. ServiceAccountKey carries PrivateKeyData, and
// nothing in this function reads that field: the shared schema has no column
// that accepts a secret value, and this is the code-side half of that promise.
func (s *GCPScanner) collectKeys(
	ctx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	client *iam.Service, governor *gcp.Governor, acc *gcpSurfaceAcc,
	identities []gcpWrittenIdentity, identitiesReached bool,
) {
	if len(identities) == 0 {
		// Nothing to read keys for, and what that MEANS depends entirely on why.
		//
		// If the identity phase reached everything and simply found no service
		// accounts, then there were no keys to read either and this surface was
		// vacuously fully covered -- reached, count zero. Leaving it unknown
		// would make an empty-but-fully-read estate permanently incapable of a
		// complete scan, and so permanently unreconcilable.
		//
		// If the identity phase did NOT reach everything, there may well be
		// keys behind the part it could not see. The surface stays unknown and
		// the scan stays partial, which is the whole point of the distinction.
		if identitiesReached {
			acc.observeVacuous()
		}
		return
	}

	for _, identity := range identities {
		if err := ctx.Err(); err != nil {
			acc.observe(err, 0)
			return
		}

		keys, listErr := s.listServiceAccountKeys(ctx, client, governor, identity)
		if listErr != nil {
			acc.observe(listErr, 0)
			continue
		}

		count := 0
		var writeErr error
		for _, key := range keys {
			if err := s.upsertServiceAccountKey(workspaceID, snapshot, identity, key); err != nil {
				writeErr = err
				break
			}
			count++
		}
		acc.observe(writeErr, count)
	}
}

func (s *GCPScanner) listServiceAccountKeys(
	ctx context.Context, client *iam.Service, governor *gcp.Governor, identity gcpWrittenIdentity,
) ([]*iam.ServiceAccountKey, error) {
	var keys []*iam.ServiceAccountKey
	err := gcp.Retry(ctx, func() error {
		keys = nil
		if err := governor.IAM.Wait(ctx); err != nil {
			return err
		}
		resp, err := client.Projects.ServiceAccounts.Keys.
			List("projects/-/serviceAccounts/" + identity.Email).
			KeyTypes("USER_MANAGED").
			Context(ctx).
			Do()
		if err != nil {
			return err
		}
		keys = resp.Keys
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *GCPScanner) upsertServiceAccountKey(
	workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	identity gcpWrittenIdentity, key *iam.ServiceAccountKey,
) error {
	keyID := gcpKeyIDFromName(key.Name)
	if keyID == "" {
		return fmt.Errorf("gcp: service account key %q has no parseable key id", key.Name)
	}

	secret := &models.CloudSecret{
		WorkspaceID: workspaceID,
		ConnectorID: snapshot.ConnectorID,
		IdentityID:  identity.IdentityID,
		Kind:        models.CloudSecretGCPServiceAccountKey,
		// Keyed on the key id: rotating a key is a lifecycle event on the same
		// identity, and the new key is a new row rather than a new principal.
		NativeID:           keyID,
		ProviderCreatedAt:  parseGCPTime(key.ValidAfterTime),
		ExpiresAt:          gcpKeyExpiry(key.ValidBeforeTime),
		LastUsedAt:         nil, // UNKNOWN until Policy Analyzer lands.
		Status:             gcpKeyStatus(key),
		LastSeenGeneration: snapshot.Generation,
	}
	if err := secret.SetGCPAttrs(models.GCPSecretAttrs{
		// The provider's own values for both, kept apart. keyOrigin says who
		// generated the material; keyType says who rotates it.
		KeyOrigin:           key.KeyOrigin,
		KeyType:             key.KeyType,
		KeyAlgorithm:        key.KeyAlgorithm,
		DisableReason:       key.DisableReason,
		ServiceAccountEmail: identity.Email,
	}); err != nil {
		return err
	}

	_, _, err := s.identities.UpsertSecret(secret)
	return err
}

// gcpKeyIDFromName pulls the key id out of
// "projects/<p>/serviceAccounts/<email>/keys/<keyId>".
func gcpKeyIDFromName(name string) string {
	idx := strings.LastIndex(name, "/keys/")
	if idx < 0 {
		return ""
	}
	return name[idx+len("/keys/"):]
}

func gcpKeyStatus(key *iam.ServiceAccountKey) string {
	if key.Disabled {
		return models.CloudSecretInactive
	}
	return models.CloudSecretActive
}

// gcpNeverExpiresYear is the year GCP uses to mean "this key does not expire".
//
// Confirmed against the live API: a user-managed service-account key created
// through the console comes back with validBeforeTime "9999-12-31T23:59:59Z".
// It is a sentinel, not a date.
const gcpNeverExpiresYear = 9999

// gcpKeyExpiry converts validBeforeTime into an expiry, mapping GCP's
// never-expires sentinel to nil.
//
// Storing 9999-12-31 literally would be the wrong kind of true. The shared
// schema's contract for CloudSecret.ExpiresAt is that nil means the provider
// has no expiry -- it is how AWS records every access key, and it is what makes
// "which credentials never expire" an `expires_at IS NULL` query rather than a
// magic-date comparison every caller has to know about. A non-expiring key is
// the finding here, so it has to be expressed the way the schema expresses it.
func gcpKeyExpiry(validBeforeTime string) *time.Time {
	t := parseGCPTime(validBeforeTime)
	if t == nil {
		return nil
	}
	if t.UTC().Year() >= gcpNeverExpiresYear {
		return nil
	}
	return t
}

// parseGCPTime reads an RFC 3339 timestamp, returning nil when absent or
// unparseable. nil means the provider did not tell us, which is a different
// fact from a zero date.
func parseGCPTime(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}
	return &t
}
