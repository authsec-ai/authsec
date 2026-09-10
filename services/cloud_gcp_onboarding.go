package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"gorm.io/gorm"
)

// newIAMClientFunc and newResourceManagerClientFunc default to internal/gcp's
// real client factories, and exist as package vars ONLY so
// cloud_gcp_onboarding_test.go (same package, so it can reassign an
// unexported var) can point them at a fake server instead — no live GCP call
// in that test tier, per this ticket's own instruction. Production code
// never reassigns these; auth.go itself is not touched, since
// both factories' real signatures are reused unchanged.
var (
	newIAMClientFunc             = gcp.NewIAMClient
	newResourceManagerClientFunc = gcp.NewResourceManagerClient
)

// GCP onboarding: connect a customer's GCP scope (org, folder or project)
// read-only, prove the connection works, and record it as the
// cloud_connector row every later GCP scan resolves against.
//
// Mirrors services/cloud_aws_onboarding.go's shape and ordering exactly:
// prove the connection AND the scope BEFORE any write, so an account that
// cannot be read leaves no row and no stored secret behind. The two
// connectors differ in mechanics (assume-role vs. WIF/JSON-key,
// GetCallerIdentity vs. iam.serviceAccounts.get, one flat account vs. a
// scope hierarchy with a parent to record) but not in that discipline.

/* --------------------------------- errors ---------------------------------- */

// Sentinel errors specific to GCP onboarding's own request/scope validation.
// GCP-03's four (invalid_grant, wif_pool_missing, key_invalid,
// permission_denied — internal/gcp/errors.go) are reused via errors.Is, not
// redefined here.
var (
	// ErrScopeNotReadable means the credential (either auth path, already
	// proven to resolve to the claimed reader SA) could not read the claimed
	// scope — organizations.get/folders.get/projects.get denied or not found.
	// Always the customer's own scope/grant configuration, never AuthSec's.
	ErrScopeNotReadable = errors.New("gcp: the claimed scope could not be read with this credential")

	// ErrInvalidScopeID means the request itself is malformed: an
	// unsupported scope_kind, or a missing scope_id/reader_project_id.
	// Caught before any GCP or Vault call.
	ErrInvalidScopeID = errors.New("gcp: scope_kind, scope_id or reader_project_id is invalid")

	// ErrKeyedOnboardingClosed means a caller asked to create a connector with
	// auth.method "json_key". No new GCP connector may authenticate with a
	// stored service-account key.
	//
	// The console stopped offering the keyed path some time ago, but the HTTP
	// surface still accepted it, so a keyed connector could be created through
	// the API and handed to discovery — which quietly defeated the guarantee
	// that no scan depends on stored key material. Closing it at the door is
	// the only place the guarantee actually holds.
	//
	// Existing keyed connectors keep working: they still verify, and they
	// still revoke cleanly with their Vault secret purged. What is refused is
	// creating another one.
	ErrKeyedOnboardingClosed = errors.New("gcp: connecting with a service account key is no longer supported; use workload identity federation")

	// ErrConnectorRevoked means the caller asked to verify a connector whose
	// status is already 'revoked'. Caught before any credential is loaded or
	// GCP call is attempted — see GCP-E2E-MANUAL-TEST-GUIDE.md §12 finding
	// #3 (live-confirmed 2026-09-02): without this guard, VerifyConnector
	// would run the normal probe, fail (the WIF auth_ref is empty and the
	// json_key Vault secret was purged by revoke), and MarkError would flip
	// the row from 'revoked' to 'error' — losing the fact that this
	// connector was deliberately disconnected, not merely broken. A revoked
	// connector must stay 'revoked' until it is reconnected (POST
	// /connectors again), never silently reinterpreted as an error state.
	ErrConnectorRevoked = errors.New("gcp: this connector has been revoked; reconnect it to verify again")
)

/* --------------------------------- request ---------------------------------- */

// GCPAuthInput is the auth half of a GCPOnboardInput.
type GCPAuthInput struct {
	// Method is "json_key" or "wif" (GCPAuthMethodJSONKey / GCPAuthMethodWIF).
	Method string `json:"method"`
	// KeyJSON is the raw uploaded service-account key, json_key only. The
	// controller (cloud_gcp_controller.go's gcpCreateConnectorRequest) binds
	// the key file's text from a JSON STRING field in the request body (the
	// key file is itself JSON, carried as an escaped string) and converts it
	// to []byte before constructing this struct. json:"-" here is belt and
	// suspenders: this type is never itself the target of a JSON bind, so
	// there is no tag for a stray log/error %+v to pick up.
	KeyJSON []byte `json:"-"`
	// ProviderResource and ReaderSAEmail are wif only: the two values
	// GCP-D9's flow has the customer paste back from setup-reader.sh's
	// final output lines.
	ProviderResource string `json:"provider_resource,omitempty"`
	ReaderSAEmail    string `json:"reader_sa_email,omitempty"`
}

// GCPOnboardInput is what the console posts to create or reconnect a GCP
// connector.
type GCPOnboardInput struct {
	ScopeKind       string       `json:"scope_kind"`
	ScopeID         string       `json:"scope_id"`
	ReaderProjectID string       `json:"reader_project_id"`
	Auth            GCPAuthInput `json:"auth"`
	DisplayName     string       `json:"display_name"`

	// Hints are optional customer-declared context no GCP API reports —
	// environment, naming convention, owning team. Onboarding is the only
	// point in the lifecycle where someone who knows the answer is present, so
	// it is asked here even though nothing in onboarding uses it.
	Hints *models.GCPOnboardingHints `json:"hints,omitempty"`
}

/* --------------------------------- service ----------------------------------- */

// GCPOnboardingService owns the policy around connecting a GCP scope:
// validation, proving the connection and the scope, where credential
// material lives, and the connector row. GCP itself is reached only through
// the typed clients internal/gcp/auth.go builds.
type GCPOnboardingService struct {
	db      *gorm.DB
	repo    repositories.CloudConnectorRepository
	authSvc *GCPAuthService
}

// NewGCPOnboardingService constructs the service. vc may be nil (the
// json_key path then fails explicitly at StoreKey/LoadCredential, exactly
// like AWSOnboardingService requires vault); issuer may be nil (the wif
// path then fails explicitly at BuildWIFCredential) — see GCPAuthService's
// own constructor comment.
func NewGCPOnboardingService(db *gorm.DB, vc vault.VaultClient, issuer gcp.CloudOnboardingTokenIssuer) *GCPOnboardingService {
	return &GCPOnboardingService{
		db:      db,
		repo:    repositories.NewCloudConnectorRepository(db),
		authSvc: NewGCPAuthService(vc, issuer),
	}
}

/* -------------------------------- onboarding --------------------------------- */

// Onboard proves the connection and the scope, then records the connector.
// Reports whether the connector was newly created, exactly like
// AWSOnboardingService.Onboard, for the same 200-vs-201 and
// rollback-eligibility reasons.
//
// Ordering (copied from the landed AWS Onboard, per this ticket's own
// instruction): validate connection AND scope BEFORE any write. For
// json_key: Vault write before Upsert, rolled back if Upsert fails on a NEW
// connector. For wif: no Vault write at all, ever — straight to Upsert once
// validation passes.
func (s *GCPOnboardingService) Onboard(
	ctx context.Context, workspaceID uuid.UUID, in GCPOnboardInput, actor string,
) (*models.CloudConnector, bool, error) {
	_ = actor // recorded by the caller via CreatedBy on the connector, not used here directly

	scopeKind := strings.TrimSpace(in.ScopeKind)
	scopeID := strings.TrimSpace(in.ScopeID)
	readerProjectID := strings.TrimSpace(in.ReaderProjectID)
	// Refused before validation, before Vault, before any GCP call: there is
	// no state worth building for a connector that will not be created.
	if in.Auth.Method == GCPAuthMethodJSONKey {
		return nil, false, ErrKeyedOnboardingClosed
	}
	if !isSupportedGCPScopeKind(scopeKind) {
		return nil, false, fmt.Errorf("%w: scope_kind must be org, folder or project", ErrInvalidScopeID)
	}
	if scopeID == "" {
		return nil, false, fmt.Errorf("%w: scope_id is required", ErrInvalidScopeID)
	}
	if readerProjectID == "" {
		return nil, false, fmt.Errorf("%w: reader_project_id is required", ErrInvalidScopeID)
	}

	// Same reason as the onboarding-package endpoint: these reach the rendered
	// setup script, which is a template with no shell escaping. Validated here
	// too so a caller cannot skip the read endpoint and inject through Onboard.
	if err := gcp.ValidateProjectID("reader_project_id", readerProjectID); err != nil {
		return nil, false, fmt.Errorf("%w: %s", ErrInvalidScopeID, err)
	}
	if err := gcp.ValidateScopeID(scopeKind, scopeID); err != nil {
		return nil, false, fmt.Errorf("%w: %s", ErrInvalidScopeID, err)
	}

	// Resolve the credential's ClientOption WITHOUT touching Vault yet (json_key)
	// and without any network call yet (wif — minting a cloud-onboarding token
	// is a local signing operation, not a call to GCP). The actual GCP calls
	// start below, at the connectivity and scope checks. The same credential
	// is reused for both clients below — see ResolveWIFCredential's own doc
	// comment for why the wif path requests every scope both clients need
	// up front, in this one credential.
	authOpt, readerSAEmail, err := s.resolveOnboardingCredential(ctx, workspaceID, scopeID, in.Auth)
	if err != nil {
		return nil, false, err
	}

	iamClient, err := newIAMClientFunc(ctx, authOpt)
	if err != nil {
		return nil, false, err
	}
	rmClient, err := newResourceManagerClientFunc(ctx, authOpt)
	if err != nil {
		return nil, false, err
	}

	// The GCP-03 connectivity primitive: proves the credential resolves to
	// the reader SA the customer claimed, before trusting it for anything else.
	if _, err := s.authSvc.ResolveReaderIdentity(ctx, iamClient, readerSAEmail, in.Auth.Method); err != nil {
		return nil, false, err
	}

	parentScopeID, err := validateGCPScope(ctx, rmClient, scopeKind, scopeID)
	if err != nil {
		return nil, false, err
	}

	// No Vault write anywhere in this function: the only auth method that
	// reaches here is wif, whose auth_ref is a non-secret GCP resource name.
	// The rollback this used to need — delete the stored key if the upsert
	// fails on a new connector — went with the keyed path, because there is
	// no longer anything to roll back.
	authRef := "wif:" + in.Auth.ProviderResource

	now := time.Now()
	connector := &models.CloudConnector{
		WorkspaceID:   workspaceID,
		Provider:      models.CloudProviderGCP,
		ScopeKind:     scopeKind,
		ScopeID:       scopeID,
		ParentScopeID: parentScopeID,
		AuthRef:       authRef,
		Status:        models.CloudConnectorActive,
		VerifiedAt:    &now,
		CreatedBy:     actor,
		// Every surface, pre-created and explicitly unknown, rather than the
		// empty object this used to write. A surface missing from coverage is
		// indistinguishable from one a scan reached and found empty, so the
		// first scan must UPDATE this list rather than invent one.
		Coverage: NewGCPCoverageSkeleton(),
	}

	poolID, providerID, wifSubject := gcp.DeriveWIFParams(workspaceID, scopeID)
	attrs := models.GCPConnectorAttrs{
		DisplayName:        strings.TrimSpace(in.DisplayName),
		AuthMethod:         in.Auth.Method,
		ReaderProjectID:    readerProjectID,
		ReaderSAEmail:      readerSAEmail,
		CAIQuotaProject:    readerProjectID,
		RoleSetStatus:      gcp.CurrentRoleSetStatus,
		RoleSetVersion:     gcp.ReaderRoleSetVersion,
		SetupScriptVersion: gcp.Version,
		Hints:              in.Hints,
	}
	// Provenance is empty here on every path: the Google Authentication route
	// stamps ProvisionedVia AFTER Onboard returns, so at this point a connector
	// it created is indistinguishable from a manual one and correctly reads as
	// manual_wif. That route corrects the value when it stamps.
	attrs.OnboardingPath = gcpOnboardingPath(in.Auth.Method, attrs.ProvisionedVia)
	if in.Auth.Method == GCPAuthMethodWIF {
		attrs.WIFProviderResource = in.Auth.ProviderResource
		attrs.WIFSubject = wifSubject
		attrs.PoolID = poolID
		attrs.ProviderID = providerID
	}
	if err := connector.SetGCPAttrs(attrs); err != nil {
		return nil, false, err
	}

	stored, created, err := s.repo.Upsert(connector)
	if err != nil {
		return nil, false, fmt.Errorf("failed to record the connector: %w", err)
	}

	// Probe AFTER the upsert, and never fail the onboarding on it. The
	// connection is already proven at this point; what the probe adds is a
	// description of what that connection can reach. A connector that
	// connects but cannot be profiled is a connector with an empty capability
	// profile — which reads as "not yet probed" and is honest — whereas
	// refusing to record it at all would throw away a working connection over
	// a report.
	s.refreshCapabilityProfile(ctx, stored, authOpt)

	return stored, created, nil
}

// refreshCapabilityProfile runs the live permission probe and merges the
// result into the connector's attrs. Best-effort by design: every failure
// path leaves the existing profile untouched rather than half-overwriting it,
// because a stale-but-complete profile is more useful than a fresh empty one.
//
// It takes the already-resolved credential rather than rebuilding one, so the
// probe describes exactly the principal the caller just proved.
func (s *GCPOnboardingService) refreshCapabilityProfile(
	ctx context.Context, c *models.CloudConnector, authOpt option.ClientOption,
) {
	rmClient, err := newResourceManagerClientFunc(ctx, authOpt)
	if err != nil {
		return
	}

	result, err := gcp.ProbeReaderCapabilities(ctx, rmClient, c.ScopeKind, c.ScopeID)
	if err != nil {
		return
	}

	attrs := c.GCPAttrs()
	attrs.CapabilityProfile = result.Surfaces
	attrs.ProbedPermissions = result.Held
	attrs.WritePermissionsHeld = result.WriteHeld
	probedAt := result.ProbedAt
	attrs.ProbedAt = &probedAt
	attrs.RoleSetVersion = gcp.ReaderRoleSetVersion

	// Enablement is read against the QUOTA project, not the scanned scope.
	// Cloud Asset Inventory bills every call to the caller's quota project, so
	// that is the project whose APIs have to be on for the spine to work at
	// all — a scanned project with cloudasset enabled and a quota project
	// without it fails on the first call, with an error that names neither.
	quotaProject := attrs.CAIQuotaProject
	if quotaProject == "" {
		quotaProject = attrs.ReaderProjectID
	}
	if quotaProject != "" {
		if suClient, err := newServiceUsageClientFunc(ctx, authOpt); err == nil {
			attrs.APIEnablement = gcp.ReadAPIEnablement(ctx, suClient, quotaProject)
		}
		// A failure to build the client leaves APIEnablement as it was.
		// Overwriting it with an all-unknown map would discard a good reading
		// from a previous verify in exchange for nothing.
	}

	// The quota project is probed on its own, because it is allowed to sit
	// OUTSIDE the onboarded scope -- and when it does, the reader roles bound
	// at the scope grant nothing on it. That connector reads its scope
	// perfectly and fails every Cloud Asset call, which is the single failure
	// most likely to be misread as "the estate is empty".
	usable, known := gcp.QuotaProjectUsable(ctx, rmClient, quotaProject)
	attrs.CapabilityLimits = setGCPCapabilityLimit(attrs.CapabilityLimits, models.GCPLimitQuotaProjectUnusable, known && !usable)

	// A connector still authenticating with a stored key. No new one can be
	// created this way; this marks the ones that predate the change, so
	// discovery can apply its own policy to them rather than having to infer
	// the credential kind from an auth_ref prefix.
	attrs.CapabilityLimits = setGCPCapabilityLimit(attrs.CapabilityLimits,
		models.GCPLimitKeyedCredential, attrs.AuthMethod == GCPAuthMethodJSONKey)

	// Whether the reader can walk below the top scope. Recorded rather than
	// acted on: onboarding does not build the tree, it establishes that
	// building one is possible, so a later empty result can be told apart
	// from an impossible one.
	if enum, err := json.Marshal(gcp.ProbeScopeEnumeration(ctx, rmClient, c.ScopeKind, c.ScopeID)); err == nil {
		attrs.ScopeEnumeration = enum
	}

	if !result.Clean() {
		// Loud, because this is the one thing in the probe that is a finding
		// rather than a measurement. The permissions are non-secret identifiers
		// and naming them is the point — an operator cannot act on "something
		// is writable".
		log.Printf("[gcp] ZERO-WRITE ASSERTION FAILED connector=%s scope=%s/%s write_permissions_held=%v write_check_unknown=%v",
			c.ID, c.ScopeKind, c.ScopeID, result.WriteHeld, result.WriteCheckUnknown)
	}

	// Derived last, from everything written above, so the verdict and the
	// evidence behind it are always the same age. Recomputed rather than
	// incrementally maintained — a stored judgement drifts from its inputs and
	// then the console and the scheduler disagree about the same connector.
	attrs.DiscoveryReadiness, attrs.DiscoveryReadinessReasons = DeriveGCPReadiness(attrs, c.Status)

	if err := c.SetGCPAttrs(attrs); err != nil {
		return
	}
	if err := s.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", c.WorkspaceID, c.ID).
		Update("attrs", c.Attrs).Error; err != nil {
		log.Printf("[gcp] could not persist capability profile for connector=%s: %v", c.ID, err)
	}
}

// resolveOnboardingCredential builds the option.ClientOption for either auth
// path and returns the reader SA email the credential claims to be — for
// json_key this is parsed from the uploaded key's own client_email field
// (the customer never types it separately for this path); for wif it is
// exactly what the customer pasted back. The single returned credential is
// reused for every client (IAM, Resource Manager, Cloud Asset) the caller
// builds — see ResolveWIFCredential's own doc comment for why the wif path
// requests every scope those clients need up front, in one credential,
// rather than resolving one per client.
func (s *GCPOnboardingService) resolveOnboardingCredential(
	ctx context.Context, workspaceID uuid.UUID, scopeID string, auth GCPAuthInput,
) (option.ClientOption, string, error) {
	switch auth.Method {
	case GCPAuthMethodWIF:
		if auth.ReaderSAEmail == "" {
			return nil, "", fmt.Errorf("%w: reader_sa_email is required for the wif auth method", ErrInvalidScopeID)
		}
		// Cross-check the pasted provider_resource against what
		// DeriveWIFParams derives for THIS (workspace_id, scope_id) BEFORE any
		// network call — catches a stale paste or wrong-project mistake,
		// mirroring AWS Onboard()'s own account/ARN cross-check.
		pastedPool, pastedProvider, ok := gcp.ParseProviderResource(auth.ProviderResource)
		wantPool, wantProvider, _ := gcp.DeriveWIFParams(workspaceID, scopeID)
		if !ok || pastedPool != wantPool || pastedProvider != wantProvider {
			// The mismatch itself is the whole message. Logging what was
			// pasted against what was derived was for one investigation, now
			// closed, and the caller already gets told which value is wrong.
			return nil, "", fmt.Errorf("%w: the pasted provider_resource does not match what was derived for this workspace and scope", gcp.ErrWIFPoolMissing)
		}

		opt, err := s.authSvc.BuildWIFCredential(ctx, workspaceID, scopeID, auth.ProviderResource, auth.ReaderSAEmail)
		if err != nil {
			return nil, "", err
		}
		return opt, auth.ReaderSAEmail, nil

	default:
		return nil, "", fmt.Errorf("%w: auth.method must be \"wif\"", ErrInvalidScopeID)
	}
}

// isSupportedGCPScopeKind rejects "account"/"subscription" (AWS/Azure scope
// kinds the shared CHECK constraint also allows, since cloud_connector is
// provider-generic) before any GCP call is attempted.
func isSupportedGCPScopeKind(scopeKind string) bool {
	switch scopeKind {
	case models.CloudScopeOrg, models.CloudScopeFolder, models.CloudScopeProject:
		return true
	default:
		return false
	}
}

// validateGCPScope reads the claimed scope with the credential and returns
// the bare parent id to record as parent_scope_id (nil for an org, which has
// no parent). Any failure — denied, not found, or a transport error — maps
// to ErrScopeNotReadable: from the caller's point of view all three mean the
// same thing, "we cannot confirm this credential can read this scope."
func validateGCPScope(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string) (*string, error) {
	switch scopeKind {
	case models.CloudScopeOrg:
		if _, err := rm.Organizations.Get("organizations/" + scopeID).Context(ctx).Do(); err != nil {
			return nil, classifyScopeError(err)
		}
		return nil, nil

	case models.CloudScopeFolder:
		f, err := rm.Folders.Get("folders/" + scopeID).Context(ctx).Do()
		if err != nil {
			return nil, classifyScopeError(err)
		}
		return parentIDOf(f.Parent), nil

	case models.CloudScopeProject:
		p, err := rm.Projects.Get("projects/" + scopeID).Context(ctx).Do()
		if err != nil {
			return nil, classifyScopeError(err)
		}
		return parentIDOf(p.Parent), nil

	default:
		// Unreachable: Onboard/VerifyConnector call isSupportedGCPScopeKind
		// first. Guarded anyway so this function is safe to call on its own.
		return nil, fmt.Errorf("%w: scope_kind must be org, folder or project", ErrInvalidScopeID)
	}
}

// parentIDOf strips a GCP resource-name parent ("organizations/123" or
// "folders/456") down to the bare id cloud_connector.parent_scope_id stores
// — the same bare-identifier convention scope_id itself uses. Empty input
// (a project or folder GCP reports with no parent) returns nil, not a
// pointer to an empty string.
func parentIDOf(parent string) *string {
	if parent == "" {
		return nil
	}
	id := parent
	if idx := strings.LastIndex(parent, "/"); idx >= 0 {
		id = parent[idx+1:]
	}
	return &id
}

func classifyScopeError(err error) error {
	// A scope refused by a perimeter or an org policy is not an unreadable
	// scope in the sense this function's other answer means. The reader may be
	// perfectly configured; something else said no, and the customer needs to
	// hear which. Checked first, since both arrive as a 403.
	if constrained := gcp.ClassifyConstraint(err); constrained != nil {
		return constrained
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case http.StatusForbidden, http.StatusNotFound:
			return ErrScopeNotReadable
		}
	}
	return ErrScopeNotReadable
}

/* -------------------------------- verify -------------------------------- */

// VerifyConnector re-proves an existing connection and scope. For a wif
// connector this mints a FRESH cloud-onboarding token and rebuilds the
// external-account credential from scratch — there is no long-lived
// credential object to reuse between calls (GCP-D9's design: every
// verify/scan call mints fresh, never caches).
//
// A failure is recorded on the row, not raised and forgotten — status
// becomes 'error' with the sanitized reason, verified_at is left alone so
// the console can still show when the connection last genuinely worked, and
// nothing the connector previously discovered is touched.
func (s *GCPOnboardingService) VerifyConnector(
	ctx context.Context, workspaceID, id uuid.UUID,
) (*models.CloudConnector, error) {
	c, err := s.repo.Get(workspaceID, id)
	if err != nil {
		return nil, err
	}
	if c.Provider != models.CloudProviderGCP {
		return nil, fmt.Errorf("connector %s is a %s connector", id, c.Provider)
	}
	if c.Status == models.CloudConnectorRevoked {
		return c, ErrConnectorRevoked
	}
	attrs := c.GCPAttrs()

	var authOpt option.ClientOption
	switch attrs.AuthMethod {
	case GCPAuthMethodJSONKey:
		authOpt, err = s.authSvc.LoadCredential(c.AuthRef)
	case GCPAuthMethodWIF:
		authOpt, err = s.authSvc.BuildWIFCredential(ctx, workspaceID, c.ScopeID, attrs.WIFProviderResource, attrs.ReaderSAEmail)
	default:
		err = fmt.Errorf("%w: connector has no recognised auth method recorded", ErrInvalidScopeID)
	}
	if err != nil {
		updated, uerr := s.repo.MarkError(workspaceID, id, sanitizedReason(err))
		if uerr != nil {
			return nil, uerr
		}
		return updated, err
	}

	iamClient, err := newIAMClientFunc(ctx, authOpt)
	if err == nil {
		_, err = s.authSvc.ResolveReaderIdentity(ctx, iamClient, attrs.ReaderSAEmail, attrs.AuthMethod)
	}
	var freshParent *string
	if err == nil {
		var rmClient *cloudresourcemanager.Service
		rmClient, err = newResourceManagerClientFunc(ctx, authOpt)
		if err == nil {
			freshParent, err = validateGCPScope(ctx, rmClient, c.ScopeKind, c.ScopeID)
		}
	}
	if err != nil {
		updated, uerr := s.repo.MarkError(workspaceID, id, sanitizedReason(err))
		if uerr != nil {
			return nil, uerr
		}
		return updated, err
	}

	// Re-probe on every successful verify. This is what makes the role set
	// extensible without a re-onboard: a customer who grants a later phase's
	// roles out of band gets them picked up by hitting verify, with no new
	// endpoint and nothing to re-run on their side.
	//
	// It sits here, after the revoked short-circuit above and after the
	// credential and scope have both been re-proven, so a revoked or broken
	// connector is never probed — there would be nothing to learn, and the
	// calls would fail anyway.
	s.refreshCapabilityProfile(ctx, c, authOpt)

	// Re-record the parent. A project or folder can be MOVED in the hierarchy
	// after onboarding, and a stale parent silently misplaces the connector in
	// every inheritance-aware calculation built on top of it. The check costs
	// nothing -- validateGCPScope already read it above and the value was
	// previously thrown away.
	s.refreshParentScope(ctx, c, freshParent)

	// MarkVerified is passed nil so it leaves the attrs blob alone: the probe
	// above already wrote the only attrs this call changes, and handing
	// MarkVerified a second copy would race it against itself.
	return s.repo.MarkVerified(workspaceID, id, nil)
}

// sanitizedReason turns a service error into the safe string
// cloud_connector.last_error stores. Every error this package and
// internal/gcp return already carries a static, sanitized message (see
// internal/gcp/errors.go's own doc comment) — this just calls Error() on
// something already safe to store, never on a raw provider error.
func sanitizedReason(err error) string {
	return err.Error()
}

/* -------------------------------- revoke -------------------------------- */

// RevokeConnector soft-revokes a connector: purges the Vault credential for
// json_key (a documented no-op for wif — see GCPAuthService.RevokeCredential),
// then marks the row 'revoked' and KEEPS it, for audit (plan §9).
//
// This is a DELIBERATE, KNOWN difference from the landed AWS DELETE, which
// hard-deletes the row — not something awaiting further alignment. The URL
// stays DELETE /authsec/discovery/gcp/connectors/:id to keep the route shape
// consistent with AWS despite the differing behaviour underneath it.
func (s *GCPOnboardingService) RevokeConnector(workspaceID, id uuid.UUID) error {
	c, err := s.repo.Get(workspaceID, id)
	if err != nil {
		return err
	}
	if c.Provider != models.CloudProviderGCP {
		return fmt.Errorf("connector %s is a %s connector", id, c.Provider)
	}
	attrs := c.GCPAttrs()

	if err := s.authSvc.RevokeCredential(attrs.AuthMethod, c.AuthRef); err != nil {
		return err
	}

	// repository/cloud_connector_repository.go has no soft-revoke method (only
	// Delete, which hard-deletes — the landed AWS semantics this ticket
	// deliberately diverges from) and is reused unmodified per this ticket's
	// own file list, so the status flip is one direct, minimal UPDATE here
	// rather than a new repository method.
	return s.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Update("status", models.CloudConnectorRevoked).Error
}

/* -------------------------------- reads -------------------------------- */

// Connectors lists the workspace's GCP connectors.
func (s *GCPOnboardingService) Connectors(workspaceID uuid.UUID) ([]models.CloudConnector, error) {
	return s.repo.List(workspaceID, models.CloudProviderGCP)
}

// Connector reads one.
func (s *GCPOnboardingService) Connector(workspaceID, id uuid.UUID) (*models.CloudConnector, error) {
	c, err := s.repo.Get(workspaceID, id)
	if err != nil {
		return nil, err
	}
	if c.Provider != models.CloudProviderGCP {
		return nil, repositories.ErrCloudConnectorNotFound
	}
	return c, nil
}

/* --------------------------- capability limits ------------------------------ */

// setGCPCapabilityLimit adds or removes one capability limit, returning the
// updated set. Named with the GCP prefix because it lives in the shared
// services package alongside 77 other files -- a bare setLimit there is a
// collision waiting for whoever writes the Azure connector.
//
// Removal matters as much as addition: a limit is a claim about the present,
// and a customer who fixes a missing grant must see it clear on the next
// verify. A set that only ever grows would leave every repaired connector
// permanently marked broken.
//
// Only ever called with a limit this code path actually evaluated, so a limit
// owned by some other path is never silently dropped.
func setGCPCapabilityLimit(limits []string, limit string, present bool) []string {
	out := make([]string, 0, len(limits)+1)
	for _, l := range limits {
		if l != limit {
			out = append(out, l)
		}
	}
	if present {
		out = append(out, limit)
	}
	sort.Strings(out)
	return out
}

// refreshParentScope writes parent_scope_id when the provider now reports a
// different parent from the one on the row.
//
// Best-effort and write-only-on-change: a verify that cannot update the parent
// is still a successful verify, and rewriting an unchanged value on every
// verify would churn updated_at for no reason.
func (s *GCPOnboardingService) refreshParentScope(ctx context.Context, c *models.CloudConnector, fresh *string) {
	if sameGCPParentScope(c.ParentScopeID, fresh) {
		return
	}
	if err := s.db.WithContext(ctx).Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", c.WorkspaceID, c.ID).
		Update("parent_scope_id", fresh).Error; err != nil {
		log.Printf("[gcp] could not refresh parent_scope_id for connector=%s: %v", c.ID, err)
		return
	}
	c.ParentScopeID = fresh
}

// sameGCPParentScope compares two nullable strings by VALUE. The schema treats
// NULL as "no parent / not applicable", so nil and a pointer to "" are not
// interchangeable and must not compare equal.
func sameGCPParentScope(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
