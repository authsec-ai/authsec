// provision.go is Google Authentication's write-API adapter: it configures
// the SAME Workload Identity Federation resources setup-reader.sh already
// creates by hand (reader service account, WIF pool, WIF provider, the
// workloadIdentityUser binding, reader IAM roles, required API enablement),
// driven by a human's short-lived OAuth access token instead of a customer
// typing gcloud commands into Cloud Shell.
//
// This file is PROVISIONING INFRASTRUCTURE ONLY -- it never constructs an
// authenticated GCP client for AuthSec's own persistent use, never reads
// this workspace's connector for ongoing access, and knows nothing about
// cloud_connector rows. Persistent authentication remains exactly
// ResolveWIFCredential (auth.go, untouched): once this file finishes
// creating GCP-side resources, the caller (services/gcp_oauth_provision_service.go)
// hands off to the existing, unmodified onboarding path, which re-derives
// and re-proves everything the normal way. Nothing here is a second
// implementation of WIF authentication.
//
// Every Ensure* function below is idempotent by construction (GET-then-create
// for resources, read-merge-write-with-etag for IAM policies) so that
// retrying this whole sequence after a partial failure converges rather than
// duplicating or erroring -- see EnsureWorkloadIdentityBinding and
// EnsureReaderRoles for the read-merge-write shape, and EnsureWIFPool /
// EnsureWIFProvider for the GET-then-create shape, mirroring
// setup-reader.sh's own `|| echo "(already exists — continuing)"` tolerance.
package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	iam "google.golang.org/api/iam/v1"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

// ReaderServiceAccountID is the fixed account id setup-reader.sh's own
// READER_SA_NAME uses. Kept as a literal constant here (not imported from
// setup-reader.sh, which is a template, not Go source) so the two can never
// silently drift without a reviewer noticing both files in the same diff.
const ReaderServiceAccountID = "authsec-reader"

// ReaderServiceAccountDisplayName mirrors setup-reader.sh's own
// --display-name="AuthSec Reader".
const ReaderServiceAccountDisplayName = "AuthSec Reader"

// RequiredServices is every API discovery reads, plus the ones onboarding
// itself needs. Mirrored verbatim by setup-reader.sh's own
// `gcloud services enable` list, which renders from this same slice.
//
// WHY THE WHOLE LIST, AND NOT JUST WHAT ONBOARDING USES. "Not enabled" and
// "denied" are different customer conversations, and only one of them is
// anybody's fault. Discovering at scan time that a project never had
// aiplatform enabled produces a support ticket; discovering it at onboarding
// produces a sentence in the setup output. Enabling an API a customer never
// uses costs them nothing -- Google bills usage, not enablement.
//
// The list is split into CoreServices and DiscoveryServices below, because
// the two are treated very differently on failure. RequiredServices is their
// concatenation, and is what the enablement READ reports on.
var RequiredServices = append(append([]string{}, CoreServices...), DiscoveryServices...)

// CoreServices are the APIs onboarding ITSELF cannot proceed without. Failing
// to enable one of these is fatal in both the Go path and the setup script:
// without them the service account, the federation resources, the token
// exchange and every later read are impossible, so continuing would only
// produce a connector that cannot work.
var CoreServices = []string{
	"iam.googleapis.com",
	"iamcredentials.googleapis.com",
	"cloudresourcemanager.googleapis.com",
	"sts.googleapis.com",
	"cloudasset.googleapis.com",
	"serviceusage.googleapis.com",
}

// DiscoveryServices are the read surfaces discovery depends on. Failing to
// enable one of these is NOT fatal.
//
// This split is load-bearing, and was learned the hard way. The setup script
// runs under `set -euo pipefail`, so a single `gcloud services enable` naming
// all twenty-one APIs aborts the entire script the moment ONE of them is
// unavailable — before the service account, the pool, the provider or the
// binding are created. agentregistry is Beta and is not enableable in every
// project; recommender and policyanalyzer are not universally available
// either. The result was a customer whose script died at the first step and
// whose later credential exchange then failed, because the pool it referred
// to had never been created.
//
// An unavailable surface is a capability limit, not a failed onboarding. The
// probe reports it, ReadAPIEnablement records it, and the connector still
// works for everything else.
var DiscoveryServices = []string{
	"logging.googleapis.com",
	"policyanalyzer.googleapis.com",
	"recommender.googleapis.com",
	"run.googleapis.com",
	"cloudfunctions.googleapis.com",
	"compute.googleapis.com",
	"container.googleapis.com",
	"aiplatform.googleapis.com",
	"agentregistry.googleapis.com",
	"secretmanager.googleapis.com",
	"bigquery.googleapis.com",
	"storage.googleapis.com",
	"pubsub.googleapis.com",
	"cloudkms.googleapis.com",
	"sqladmin.googleapis.com",
}

// batchEnableMaxServices is the documented ceiling on how many service ids one
// BatchEnable call accepts. Only CoreServices is sent as a single batch, and a
// test asserts it stays under this.
const batchEnableMaxServices = 20

// API enablement states recorded per service on the connector.
//
// APIStateUnknown is not a placeholder to be tidied away later: it is the
// correct answer whenever the reader could not read enablement state, and
// rendering it as "not enabled" would invent a fact. Unknown is never zero.
const (
	APIStateEnabled    = "enabled"
	APIStateNotEnabled = "not_enabled"
	APIStateUnknown    = "unknown"
)

// WorkloadIdentityUserRole is the fixed role setup-reader.sh binds the WIF
// principal to on the reader service account.
const WorkloadIdentityUserRole = "roles/iam.workloadIdentityUser"

// ProvisioningReaderProjectPermissions is the permission set a preflight
// check must confirm against the READER project (the project the service
// account, pool and provider live in) before EnableServices,
// EnsureReaderServiceAccount, EnsureWIFPool, EnsureWIFProvider or
// EnsureWorkloadIdentityBinding run. Each string is the exact permission
// documented for the corresponding write call below.
var ProvisioningReaderProjectPermissions = []string{
	"iam.workloadIdentityPools.create",
	"iam.workloadIdentityPools.update",
	"iam.serviceAccounts.create",
	"iam.serviceAccounts.setIamPolicy",
	"serviceusage.services.enable",
}

/* ---------------------------- service enablement -------------------------- */

// EnableServices enables RequiredServices on projectID. Idempotent: Service
// Usage's BatchEnable is a documented no-op success for an already-enabled
// service, so this can always be called unconditionally, including on a retry.
//
// Core is fatal, discovery is not. BatchEnable is all-or-nothing, so a single
// unavailable API in a batch takes every other API in that batch down with it
// -- and some of these are Beta (agentregistry) or not universally available
// (recommender, policyanalyzer). An org that cannot enable one of them must
// still get every other one enabled and still finish onboarding; what it
// loses is that surface, which the enablement read records honestly.
func EnableServices(ctx context.Context, su *serviceusage.Service, projectID string) error {
	// Core first, and fatal. Nothing downstream can be created without these,
	// so continuing would only build a connector guaranteed not to work.
	if _, err := su.Services.BatchEnable("projects/"+projectID, &serviceusage.BatchEnableServicesRequest{
		ServiceIds: CoreServices,
	}).Context(ctx).Do(); err != nil {
		return fmt.Errorf("%w: enabling required APIs: %v", ErrGoogleOAuthProvisioningFailed, err)
	}

	// Discovery surfaces, one service at a time and never fatal.
	//
	// One at a time rather than batched, because BatchEnable is all-or-nothing:
	// a single unavailable API in a batch of fifteen would take the other
	// fourteen down with it, and Beta or regionally-unavailable APIs are
	// exactly the ones this list contains. A surface that cannot be enabled is
	// a capability limit the probe and ReadAPIEnablement will record, not a
	// failed onboarding.
	for _, svc := range DiscoveryServices {
		_, _ = su.Services.BatchEnable("projects/"+projectID, &serviceusage.BatchEnableServicesRequest{
			ServiceIds: []string{svc},
		}).Context(ctx).Do()
	}
	return nil
}

// ReadAPIEnablement reports the state of every RequiredServices entry on
// projectID, as one map the connector row can carry.
//
// This is the half that makes "not enabled" a fact discovery can read before
// its first call, instead of an inference from an empty result afterwards. It
// is a pure read and is the only enablement path available on the manual
// onboarding route, which holds no credential that could enable anything.
//
// Every failure resolves to unknown, never to not_enabled. A reader without
// serviceusage.services.list learns nothing about enablement, and recording
// that as "the API is off" would be a fabrication that reads identically to
// the truth.
func ReadAPIEnablement(ctx context.Context, su *serviceusage.Service, projectID string) map[string]string {
	state := make(map[string]string, len(RequiredServices))
	for _, svc := range RequiredServices {
		state[svc] = APIStateUnknown
	}

	parent := "projects/" + projectID
	err := su.Services.List(parent).Filter("state:ENABLED").Pages(ctx,
		func(page *serviceusage.ListServicesResponse) error {
			for _, svc := range page.Services {
				// svc.Name is "projects/<num>/services/<api>"; the config
				// name is the bare API host, which is what RequiredServices
				// holds. Config is a pointer and the API may omit it, so this
				// falls back to the tail of the resource name rather than
				// skipping a service that is genuinely enabled.
				name := ""
				if svc.Config != nil {
					name = svc.Config.Name
				}
				if name == "" {
					if i := strings.LastIndex(svc.Name, "/"); i >= 0 {
						name = svc.Name[i+1:]
					}
				}
				if name == "" {
					continue
				}
				if _, wanted := state[name]; wanted {
					state[name] = APIStateEnabled
				}
			}
			return nil
		})
	if err != nil {
		// Everything stays unknown. Deliberately not partial: a listing that
		// died halfway would otherwise mark the services it had not reached
		// yet as not_enabled purely because of where the page boundary fell.
		return state
	}

	for svc, v := range state {
		if v == APIStateUnknown {
			state[svc] = APIStateNotEnabled
		}
	}
	return state
}

/* ------------------------------ service account ---------------------------- */

// EnsureReaderServiceAccount returns the reader service account's email,
// creating it first if it does not already exist. GET-then-create: the
// account id is deterministic (ReaderServiceAccountID), so existence is a
// simple lookup, not a search.
func EnsureReaderServiceAccount(ctx context.Context, iamSvc *iam.Service, projectID string) (string, error) {
	email := ReaderServiceAccountID + "@" + projectID + ".iam.gserviceaccount.com"
	name := "projects/" + projectID + "/serviceAccounts/" + email

	if _, err := iamSvc.Projects.ServiceAccounts.Get(name).Context(ctx).Do(); err == nil {
		return email, nil
	} else if !isNotFound(err) {
		return "", fmt.Errorf("%w: checking for the reader service account: %v", ErrGoogleOAuthProvisioningFailed, err)
	}

	_, err := iamSvc.Projects.ServiceAccounts.Create("projects/"+projectID, &iam.CreateServiceAccountRequest{
		AccountId: ReaderServiceAccountID,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: ReaderServiceAccountDisplayName,
		},
	}).Context(ctx).Do()
	if err != nil && !isConflict(err) {
		return "", fmt.Errorf("%w: creating the reader service account: %v", ErrGoogleOAuthProvisioningFailed, err)
	}
	return email, nil
}

/* --------------------------------- WIF pool -------------------------------- */

// EnsureWIFPool creates the workload identity pool identified by poolID
// (internal/gcp.DeriveWIFParams' deterministic output) in projectID, if it
// does not already exist. GET-then-create, and -- per GCP's documented
// 30-day soft-delete window on a pool -- Undelete if a prior attempt's pool
// was found in the DELETED state rather than attempting a CREATE that would
// fail with ALREADY_EXISTS for up to 30 days. Create is a long-running
// operation; this function polls it to completion before returning, since
// EnsureWIFProvider cannot run against a pool that isn't ACTIVE yet.
func EnsureWIFPool(ctx context.Context, iamSvc *iam.Service, projectID, poolID string) error {
	name := "projects/" + projectID + "/locations/global/workloadIdentityPools/" + poolID

	pool, err := iamSvc.Projects.Locations.WorkloadIdentityPools.Get(name).Context(ctx).Do()
	switch {
	case err == nil && pool.State == "DELETED":
		op, uerr := iamSvc.Projects.Locations.WorkloadIdentityPools.
			Undelete(name, &iam.UndeleteWorkloadIdentityPoolRequest{}).Context(ctx).Do()
		if uerr != nil {
			return fmt.Errorf("%w: undeleting a previously soft-deleted workload identity pool (created within the last ~30 days): %v", ErrGoogleOAuthProvisioningFailed, uerr)
		}
		return pollIAMOperation(ctx, iamSvc, op)
	case err == nil:
		return nil // already exists and active
	case !isNotFound(err):
		return fmt.Errorf("%w: checking for the workload identity pool: %v", ErrGoogleOAuthProvisioningFailed, err)
	}

	op, err := iamSvc.Projects.Locations.WorkloadIdentityPools.
		Create("projects/"+projectID+"/locations/global", &iam.WorkloadIdentityPool{
			DisplayName: "AuthSec Reader Pool",
		}).
		WorkloadIdentityPoolId(poolID).Context(ctx).Do()
	if err != nil {
		if isConflict(err) {
			return nil
		}
		return fmt.Errorf("%w: creating the workload identity pool: %v", ErrGoogleOAuthProvisioningFailed, err)
	}
	return pollIAMOperation(ctx, iamSvc, op)
}

/* ------------------------------- WIF provider ------------------------------ */

// EnsureWIFProvider creates the OIDC provider identified by providerID under
// poolID, if it does not already exist. The AttributeMapping and IssuerUri
// below MUST stay byte-identical to setup-reader.sh's own
// --attribute-mapping="google.subject=assertion.sub" and --issuer-uri flags:
// ResolveWIFCredential (auth.go, untouched) authenticates against
// whatever provider actually exists in GCP, not against what this function
// thinks it configured, so any drift here would silently break WIF token
// exchange for connectors provisioned this way.
//
// When the provider already exists, its live configuration is verified
// against those same two values and patched in place when it has drifted
// (ensureWIFProviderMatches) -- e.g. a provider created by an earlier manual
// setup-reader.sh run, or by a previous automatic Provision under a rotated
// local-tunnel issuer hostname. Every other Ensure* in this file converges
// on retry by construction (GET-then-create, additive merges); the provider
// was the one resource silently kept stale, which made the final STS
// exchange fail persistently after otherwise-successful provisioning. The
// repair is an in-place update of the existing provider, never a delete or a
// recreate.
func EnsureWIFProvider(ctx context.Context, iamSvc *iam.Service, projectID, poolID, providerID, issuerURL string) error {
	poolName := "projects/" + projectID + "/locations/global/workloadIdentityPools/" + poolID
	name := poolName + "/providers/" + providerID

	provider, err := iamSvc.Projects.Locations.WorkloadIdentityPools.Providers.Get(name).Context(ctx).Do()
	switch {
	case err == nil && provider.State == "DELETED":
		op, uerr := iamSvc.Projects.Locations.WorkloadIdentityPools.Providers.
			Undelete(name, &iam.UndeleteWorkloadIdentityPoolProviderRequest{}).Context(ctx).Do()
		if uerr != nil {
			return fmt.Errorf("%w: undeleting a previously soft-deleted workload identity pool provider: %v", ErrGoogleOAuthProvisioningFailed, uerr)
		}
		return pollIAMOperation(ctx, iamSvc, op)
	case err == nil:
		return ensureWIFProviderMatches(ctx, iamSvc, name, provider, issuerURL)
	case !isNotFound(err):
		return fmt.Errorf("%w: checking for the workload identity pool provider: %v", ErrGoogleOAuthProvisioningFailed, err)
	}

	op, err := iamSvc.Projects.Locations.WorkloadIdentityPools.Providers.
		Create(poolName, &iam.WorkloadIdentityPoolProvider{
			AttributeMapping: map[string]string{"google.subject": "assertion.sub"},
			Oidc:             &iam.Oidc{IssuerUri: issuerURL},
		}).
		WorkloadIdentityPoolProviderId(providerID).Context(ctx).Do()
	if err != nil {
		if isConflict(err) {
			return nil
		}
		return fmt.Errorf("%w: creating the workload identity pool provider: %v", ErrGoogleOAuthProvisioningFailed, err)
	}
	return pollIAMOperation(ctx, iamSvc, op)
}

// ensureWIFProviderMatches verifies an already-existing provider still
// carries the OIDC configuration ResolveWIFCredential authenticates against,
// patching it in place when it has drifted and returning nil when it already
// matches (a no-op, with zero API writes, for idempotent retries).
//
// Only the two fields AuthSec owns are ever written: the attribute mapping
// and the OIDC issuer URI, via updateMask so nothing else on the provider
// (description, disabled flag, allowed audiences, conditions) is touched.
func ensureWIFProviderMatches(ctx context.Context, iamSvc *iam.Service, name string, provider *iam.WorkloadIdentityPoolProvider, issuerURL string) error {
	// Unknown shape: the GET response carries no OIDC configuration at all,
	// so there is nothing to compare against -- keep the historical no-op.
	// A real OIDC provider GET always populates oidc.issuerUri (it is a
	// required field of the resource), so in production this branch never
	// masks genuine drift; it only covers minimal fakes that return a bare
	// {state} body.
	if provider.Oidc == nil || provider.Oidc.IssuerUri == "" {
		return nil
	}
	if provider.AttributeMapping["google.subject"] == "assertion.sub" && provider.Oidc.IssuerUri == issuerURL {
		return nil // already matches -- no write needed
	}

	op, err := iamSvc.Projects.Locations.WorkloadIdentityPools.Providers.
		Patch(name, &iam.WorkloadIdentityPoolProvider{
			AttributeMapping: map[string]string{"google.subject": "assertion.sub"},
			Oidc:             &iam.Oidc{IssuerUri: issuerURL},
		}).
		UpdateMask("attributeMapping,oidc.issuerUri").Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("%w: updating the existing workload identity pool provider to trust this deployment's sign-in service failed: %v -- in the Google Cloud console, update the provider's OIDC issuer to %s, or use the Workload Identity Federation option instead",
			ErrGoogleOAuthProvisioningFailed, err, issuerURL)
	}
	return pollIAMOperation(ctx, iamSvc, op)
}

/* ------------------------------ project number ----------------------------- */

// ProjectNumber resolves the numeric project number ParseProviderResource /
// the provider_resource string format require (auth.go's ParseProviderResource: "projects/<NUM>/
// locations/..."), from the reader project's own ID.
func ProjectNumber(ctx context.Context, rm *cloudresourcemanager.Service, projectID string) (string, error) {
	p, err := rm.Projects.Get("projects/" + projectID).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("%w: resolving the reader project's number: %v", ErrGoogleOAuthProvisioningFailed, err)
	}
	// p.Name is "projects/<number>".
	parts := strings.SplitN(p.Name, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("%w: reader project has no resolvable project number", ErrGoogleOAuthProvisioningFailed)
	}
	return parts[1], nil
}

/* --------------------------- workload identity binding ---------------------- */

// EnsureWorkloadIdentityBinding grants WorkloadIdentityUserRole on
// readerSAEmail to the exact single WIF subject principal -- scoped to ONE
// subject, never the wildcard principalSet://.../* form, mirroring
// setup-reader.sh's own comment on why. Read-merge-write with etag: an
// existing policy (and any binding a customer added by hand) is preserved;
// only the one member string is appended if it is not already present. A
// no-op, with zero API writes, if the binding already exists -- both for
// idempotent retries and so a repeated Provision call never needlessly
// touches an otherwise-untouched policy.
func EnsureWorkloadIdentityBinding(ctx context.Context, iamSvc *iam.Service, projectID, readerSAEmail, projectNumber, poolID, wifSubject string) error {
	resource := "projects/" + projectID + "/serviceAccounts/" + readerSAEmail
	member := fmt.Sprintf(
		"principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/%s",
		projectNumber, poolID, wifSubject,
	)

	policy, err := iamSvc.Projects.ServiceAccounts.GetIamPolicy(resource).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("%w: reading the reader service account's IAM policy: %v", ErrGoogleOAuthProvisioningFailed, err)
	}

	for _, b := range policy.Bindings {
		if b.Role == WorkloadIdentityUserRole && containsString(b.Members, member) {
			return nil // already bound -- no write needed
		}
	}

	found := false
	for _, b := range policy.Bindings {
		if b.Role == WorkloadIdentityUserRole {
			b.Members = append(b.Members, member)
			found = true
			break
		}
	}
	if !found {
		policy.Bindings = append(policy.Bindings, &iam.Binding{
			Role:    WorkloadIdentityUserRole,
			Members: []string{member},
		})
	}

	if _, err := iamSvc.Projects.ServiceAccounts.SetIamPolicy(resource, &iam.SetIamPolicyRequest{
		Policy: policy, // carries the etag GetIamPolicy returned, for optimistic concurrency
	}).Context(ctx).Do(); err != nil {
		return fmt.Errorf("%w: binding workloadIdentityUser on the reader service account: %v", ErrGoogleOAuthProvisioningFailed, err)
	}
	return nil
}

/* ------------------------------- reader roles ------------------------------ */

// EnsureReaderRoles grants every role in roles to readerSAEmail at whichever
// GCP resource scopeKind/scopeID names (org, folder or project) -- the API
// equivalent of internal/gcp/setup.go's RoleGrantCommands, reading that same
// exported role list rather than duplicating it. One read-merge-write cycle
// covers all roles at once (read the policy once, append every missing
// member, write once), rather than one read-modify-write per role, both for
// efficiency and to avoid independent etag races within a single
// provisioning call.
func EnsureReaderRoles(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID, readerSAEmail string, roles []string) error {
	resource, err := scopeResourceName(scopeKind, scopeID)
	if err != nil {
		return err
	}
	member := "serviceAccount:" + readerSAEmail

	policy, err := getScopeIamPolicy(ctx, rm, scopeKind, resource)
	if err != nil {
		return fmt.Errorf("%w: reading the IAM policy at %s: %v", ErrGoogleOAuthProvisioningFailed, resource, err)
	}

	changed := false
	for _, role := range roles {
		hasRole := false
		for _, b := range policy.Bindings {
			if b.Role == role {
				hasRole = true
				if !containsString(b.Members, member) {
					b.Members = append(b.Members, member)
					changed = true
				}
				break
			}
		}
		if !hasRole {
			policy.Bindings = append(policy.Bindings, &cloudresourcemanager.Binding{
				Role:    role,
				Members: []string{member},
			})
			changed = true
		}
	}
	if !changed {
		return nil
	}

	if err := setScopeIamPolicy(ctx, rm, scopeKind, resource, policy); err != nil {
		return fmt.Errorf("%w: granting reader roles at %s: %v", ErrGoogleOAuthProvisioningFailed, resource, err)
	}
	return nil
}

/* -------------------------------- preflight -------------------------------- */

// TestReaderProjectPermissions returns the subset of
// ProvisioningReaderProjectPermissions the caller does NOT hold on
// readerProjectID.
func TestReaderProjectPermissions(ctx context.Context, rm *cloudresourcemanager.Service, readerProjectID string) ([]string, error) {
	return testMissingPermissions(ctx, rm, models.CloudScopeProject, readerProjectID, ProvisioningReaderProjectPermissions)
}

// TestScopePermission returns whether the caller holds the single
// setIamPolicy permission required to grant reader roles at scopeKind/scopeID
// -- as a (missing []string, error) pair for symmetry with
// TestReaderProjectPermissions, so both can be combined by the caller into
// one missing-permissions list.
func TestScopePermission(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string) ([]string, error) {
	return testMissingPermissions(ctx, rm, scopeKind, scopeID, []string{ProvisioningScopePermission(scopeKind)})
}

/* -------------------------------- listing ---------------------------------- */

// ListAccessibleProjects returns the GCP projects the caller (the OAuth
// access token's identity) can see, via Resource Manager's Search --
// eventually-consistent per its own docs, fine for a one-time picker.
func ListAccessibleProjects(ctx context.Context, rm *cloudresourcemanager.Service) ([]*cloudresourcemanager.Project, error) {
	var projects []*cloudresourcemanager.Project
	err := rm.Projects.Search().Context(ctx).Pages(ctx, func(page *cloudresourcemanager.SearchProjectsResponse) error {
		projects = append(projects, page.Projects...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: listing accessible projects: %v", ErrGoogleOAuthProvisioningFailed, err)
	}
	return projects, nil
}

/* --------------------------------- helpers ---------------------------------- */

func containsString(items []string, target string) bool {
	for _, it := range items {
		if it == target {
			return true
		}
	}
	return false
}

// pollIAMOperation waits for a long-running IAM operation (WIF pool/provider
// Create returns one) to finish, with a short bounded interval -- these
// operations complete quickly in practice; this exists so
// EnsureWIFProvider is never called against a pool that Google's API has
// accepted but not yet finished creating.
func pollIAMOperation(ctx context.Context, iamSvc *iam.Service, op *iam.Operation) error {
	if op.Done {
		if op.Error != nil {
			return fmt.Errorf("%w: %s", ErrGoogleOAuthProvisioningFailed, op.Error.Message)
		}
		return nil
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			cur, err := iamSvc.Projects.Locations.WorkloadIdentityPools.Operations.Get(op.Name).Context(ctx).Do()
			if err != nil {
				return fmt.Errorf("%w: polling operation %s: %v", ErrGoogleOAuthProvisioningFailed, op.Name, err)
			}
			if cur.Done {
				if cur.Error != nil {
					return fmt.Errorf("%w: %s", ErrGoogleOAuthProvisioningFailed, cur.Error.Message)
				}
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%w: operation %s did not complete in time", ErrGoogleOAuthProvisioningFailed, op.Name)
			}
		}
	}
}
