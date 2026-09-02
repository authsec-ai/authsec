package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/gcp/scripts"
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
// never reassigns these; internal/gcp/client.go itself is not touched, since
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
}

/* --------------------------------- service ----------------------------------- */

// GCPOnboardingService owns the policy around connecting a GCP scope:
// validation, proving the connection and the scope, where credential
// material lives, and the connector row. GCP itself is reached only through
// the typed clients internal/gcp/client.go builds.
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
	if !isSupportedGCPScopeKind(scopeKind) {
		return nil, false, fmt.Errorf("%w: scope_kind must be org, folder or project", ErrInvalidScopeID)
	}
	if scopeID == "" {
		return nil, false, fmt.Errorf("%w: scope_id is required", ErrInvalidScopeID)
	}
	if readerProjectID == "" {
		return nil, false, fmt.Errorf("%w: reader_project_id is required", ErrInvalidScopeID)
	}

	// Resolve the credential's ClientOption WITHOUT touching Vault yet (json_key)
	// and without any network call yet (wif — minting a cloud-onboarding token
	// is a local signing operation, not a call to GCP). The actual GCP calls
	// start below, at the connectivity and scope checks.
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

	// Existing-or-new decided BEFORE any write, exactly like AWS's Onboard:
	// after the upsert there is no way to tell.
	existing, err := s.repo.GetByScope(workspaceID, models.CloudProviderGCP, scopeID)
	if err != nil && !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		return nil, false, err
	}
	isNewConnector := existing == nil

	var authRef string
	switch in.Auth.Method {
	case GCPAuthMethodJSONKey:
		authRef, err = s.authSvc.StoreKey(workspaceID, scopeID, in.Auth.KeyJSON)
		if err != nil {
			return nil, false, err
		}
	case GCPAuthMethodWIF:
		// No Vault write at all for this path, by design (GCP-D9).
		authRef = "wif:" + in.Auth.ProviderResource
	}

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
		// Set explicitly for the same reason AWS's Onboard does: a NOT NULL
		// jsonb column is the wrong place to rely on GORM's zero-value-omits-
		// default inference.
		Coverage: json.RawMessage("{}"),
	}

	poolID, providerID, wifSubject := gcp.DeriveWIFParams(workspaceID, scopeID)
	attrs := models.GCPConnectorAttrs{
		DisplayName:        strings.TrimSpace(in.DisplayName),
		AuthMethod:         in.Auth.Method,
		ReaderProjectID:    readerProjectID,
		ReaderSAEmail:      readerSAEmail,
		CAIQuotaProject:    readerProjectID,
		RoleSetStatus:      gcp.CurrentRoleSetStatus,
		SetupScriptVersion: scripts.Version,
	}
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
		// Roll the secret back only when this scope was not already connected —
		// same reasoning as AWS's Onboard: deleting it on a re-onboard would
		// strand a working connector with a dangling auth_ref.
		if isNewConnector && in.Auth.Method == GCPAuthMethodJSONKey {
			_ = s.authSvc.DeleteCredential(authRef)
		}
		return nil, false, fmt.Errorf("failed to record the connector: %w", err)
	}
	return stored, created, nil
}

// resolveOnboardingCredential builds the option.ClientOption for either auth
// path and returns the reader SA email the credential claims to be — for
// json_key this is parsed from the uploaded key's own client_email field
// (the customer never types it separately for this path); for wif it is
// exactly what the customer pasted back.
func (s *GCPOnboardingService) resolveOnboardingCredential(
	ctx context.Context, workspaceID uuid.UUID, scopeID string, auth GCPAuthInput,
) (option.ClientOption, string, error) {
	switch auth.Method {
	case GCPAuthMethodJSONKey:
		email, err := parseServiceAccountEmail(auth.KeyJSON)
		if err != nil {
			return nil, "", err
		}
		opt, err := gcp.ResolveJSONKeyCredential(auth.KeyJSON)
		if err != nil {
			return nil, "", err
		}
		return opt, email, nil

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
			return nil, "", fmt.Errorf("%w: the pasted provider_resource does not match what was derived for this workspace and scope", gcp.ErrWIFPoolMissing)
		}

		opt, err := s.authSvc.BuildWIFCredential(ctx, workspaceID, scopeID, auth.ProviderResource, auth.ReaderSAEmail)
		if err != nil {
			return nil, "", err
		}
		return opt, auth.ReaderSAEmail, nil

	default:
		return nil, "", fmt.Errorf("%w: auth.method must be \"json_key\" or \"wif\"", ErrInvalidScopeID)
	}
}

// serviceAccountKeyEmail is the one field this file needs out of an uploaded
// json_key's JSON — NOT a re-implementation of internal/gcp's structural
// validation (ResolveJSONKeyCredential, called separately above, still owns
// that). This exists only because the caller needs to know which email to
// pass to ResolveReaderIdentity before it can build the connectivity check,
// and internal/gcp's own key-shape struct is unexported by design (GCP-03's
// file, not edited here).
type serviceAccountKeyEmail struct {
	ClientEmail string `json:"client_email"`
}

func parseServiceAccountEmail(keyJSON []byte) (string, error) {
	var shape serviceAccountKeyEmail
	if err := json.Unmarshal(keyJSON, &shape); err != nil || shape.ClientEmail == "" {
		return "", fmt.Errorf("%w: could not read client_email from the uploaded key", gcp.ErrKeyInvalid)
	}
	return shape.ClientEmail, nil
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
	if err == nil {
		var rmClient *cloudresourcemanager.Service
		rmClient, err = newResourceManagerClientFunc(ctx, authOpt)
		if err == nil {
			_, err = validateGCPScope(ctx, rmClient, c.ScopeKind, c.ScopeID)
		}
	}
	if err != nil {
		updated, uerr := s.repo.MarkError(workspaceID, id, sanitizedReason(err))
		if uerr != nil {
			return nil, uerr
		}
		return updated, err
	}

	// Nothing new to record in attrs on a bare verify — pass nil so
	// MarkVerified leaves the existing blob (reader project, WIF params, role
	// set status) untouched, exactly as its own doc comment describes.
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
