package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Azure onboarding: consent the AuthSec application into the Entra tenants an
// operator can see, and prove whether that consent bought ARM read access.
//
// The shape of the flow, and why it is four steps rather than one:
//
//  1. The operator signs in with their own Azure work account. AuthSec keeps the
//     resulting delegated ARM token, and nothing else about them.
//  2. AuthSec lists the tenants THAT ACCOUNT can see -- the same list the portal
//     shows under "Manage tenants". Not every tenant that exists; not a
//     directory enumeration. The operator's own access is the boundary.
//  3. For each tenant they choose, an administrator of that tenant grants admin
//     consent on Microsoft's own consent page. AuthSec never grants it.
//  4. Someone assigns Reader to the consented application in that tenant's
//     subscriptions, and AuthSec checks whether that actually happened.
//
// Step 4 is separate from step 3 because consent and authorisation are different
// things in Azure and are performed by different people. An application can be
// fully consented in a directory and still able to read nothing at all. Recording
// consent as if it were access is the mistake this split exists to prevent.

const (
	// Environment. The client secret is read here and nowhere else.
	azureClientIDEnv     = "AZURE_CLIENT_ID"
	azureClientSecretEnv = "AZURE_CLIENT_SECRET"
	azureRedirectURIEnv  = "AZURE_REDIRECT_URI"

	// How long a browser has to complete one redirect. Long enough for an
	// administrator to read a consent page properly, short enough that an
	// abandoned tab is not a standing capability.
	azureStateTTL = 15 * time.Minute

	// How long a delegated sign-in stays usable. Bounded by the refresh token,
	// which Microsoft may revoke sooner.
	azureSessionTTL = 8 * time.Hour

	// Bounds one call to Microsoft from inside an HTTP handler.
	azureCallTimeout = 45 * time.Second
)

// ErrAzureWorkspaceAmbiguous means /login was reached without a workspace and
// the deployment has more than one to choose from.
var ErrAzureWorkspaceAmbiguous = errors.New(
	"this deployment has more than one workspace; call /api/azure/login?workspace_id=<uuid>")

// AzureOnboardService is the Azure onboarding orchestration.
type AzureOnboardService struct {
	db    *gorm.DB
	repo  repositories.AzureConnectorRepository
	vault vault.VaultClient
	azure azureonboard.Client

	clientID    string
	redirectURI string
}

// NewAzureOnboardService builds the service against the live Microsoft
// client. Returns ErrNotConfigured when the deployment has no Entra app.
func NewAzureOnboardService(db *gorm.DB, vc vault.VaultClient) (*AzureOnboardService, error) {
	clientID := strings.TrimSpace(os.Getenv(azureClientIDEnv))
	clientSecret := strings.TrimSpace(os.Getenv(azureClientSecretEnv))
	redirectURI := strings.TrimSpace(os.Getenv(azureRedirectURIEnv))

	var missing []string
	if clientID == "" {
		missing = append(missing, azureClientIDEnv)
	}
	if clientSecret == "" {
		missing = append(missing, azureClientSecretEnv)
	}
	if redirectURI == "" {
		missing = append(missing, azureRedirectURIEnv)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: set %s", azureonboard.ErrNotConfigured, strings.Join(missing, ", "))
	}

	return &AzureOnboardService{
		db:          db,
		repo:        repositories.NewAzureConnectorRepository(db),
		vault:       vc,
		azure:       azureonboard.NewHTTPClient(clientID, clientSecret),
		clientID:    clientID,
		redirectURI: redirectURI,
	}, nil
}

// WithClient swaps the Microsoft client. Test seam, mirroring the AWS service.
func (s *AzureOnboardService) WithClient(c azureonboard.Client) *AzureOnboardService {
	s.azure = c
	return s
}

/* --------------------------------- login --------------------------------- */

// StartLogin mints a one-shot state and returns where to send the browser.
//
// adminConsent merges tenant-wide consent into the sign-in itself. Opt-in: it
// requires the signer to be a Global Administrator of the tenant, so forcing it
// on would lock out every operator who is not one.
func (s *AzureOnboardService) StartLogin(workspaceID uuid.UUID, actor string, adminConsent bool) (string, error) {
	state, err := azureonboard.NewLoginState()
	if err != nil {
		return "", err
	}
	if err := s.repo.CreateState(&models.AzureOAuthState{
		State:       state,
		WorkspaceID: workspaceID,
		Purpose:     models.AzureOAuthPurposeLogin,
		CreatedBy:   actor,
		ExpiresAt:   time.Now().Add(azureStateTTL),
	}); err != nil {
		return "", err
	}
	_ = s.repo.PurgeExpiredStates()
	return azureonboard.AuthorizeURL(s.clientID, s.redirectURI, state, adminConsent), nil
}

// ResolveLoginWorkspace decides which workspace a sign-in belongs to.
//
// /api/azure/login is reached by a top-level browser navigation, so it cannot
// carry a bearer token and cannot read the workspace from one. An explicit
// workspace_id is therefore accepted, and validated against the workspaces
// table so a typo fails here rather than orphaning a session nothing can read.
// A single-workspace deployment -- the on-prem default -- needs neither.
//
// This decides only where the operator's own token is filed. Nothing is written
// to azure_connectors on this path: that happens on the consent callback, whose
// state is minted by an authenticated, RBAC-checked endpoint.
func (s *AzureOnboardService) ResolveLoginWorkspace(explicit string) (uuid.UUID, error) {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		id, err := uuid.Parse(explicit)
		if err != nil {
			return uuid.Nil, errors.New("workspace_id is not a uuid")
		}
		var count int64
		if err := s.db.Model(&models.Workspace{}).Where("id = ?", id).Count(&count).Error; err != nil {
			return uuid.Nil, err
		}
		if count == 0 {
			return uuid.Nil, errors.New("workspace_id does not exist")
		}
		return id, nil
	}

	var only []models.Workspace
	if err := s.db.Model(&models.Workspace{}).Limit(2).Find(&only).Error; err != nil {
		return uuid.Nil, err
	}
	if len(only) != 1 {
		return uuid.Nil, ErrAzureWorkspaceAmbiguous
	}
	return only[0].ID, nil
}

// AzureCallbackResult is what the callback handler needs to answer with.
type AzureCallbackResult struct {
	// Step is "logged_in" or "consented".
	Step string

	// WorkspaceID the redeemed state was issued for.
	WorkspaceID uuid.UUID

	// SessionID is set on the login branch. It addresses the stored token and is
	// the value the browser gets back in a cookie.
	SessionID string

	// Connector is set on the consent branch.
	Connector *models.AzureConnector
	Created   bool
}

// AzureCallbackInput is the callback's query string, already parsed.
type AzureCallbackInput struct {
	Code             string
	State            string
	Tenant           string
	AdminConsent     string
	Error            string
	ErrorDescription string
}

// HandleCallback services both redirects.
//
// Everything trusted is read from the redeemed state row. Microsoft's tenant
// query parameter is compared against it and never used on its own -- a callback
// is a request an attacker can also make, and the tenant parameter decides which
// directory gets written into this workspace's inventory.
func (s *AzureOnboardService) HandleCallback(ctx context.Context, in AzureCallbackInput) (*AzureCallbackResult, error) {
	if in.State == "" {
		return nil, repositories.ErrAzureStateInvalid
	}

	// Shape first: a login state must never be redeemable into the consent
	// branch, and the shape check runs before the row is spent.
	purpose, stateTenant, ok := azureonboard.StatePurpose(in.State)
	if !ok {
		return nil, repositories.ErrAzureStateInvalid
	}

	st, err := s.repo.ConsumeState(in.State)
	if err != nil {
		return nil, err
	}
	if st.Purpose != purpose {
		return nil, repositories.ErrAzureStateInvalid
	}

	// Microsoft reports refusals on the redirect itself.
	if in.Error != "" {
		if purpose == models.AzureOAuthPurposeConsent {
			return nil, fmt.Errorf("%w: %s", azureonboard.ErrConsentDenied,
				strings.TrimSpace(in.Error+" "+in.ErrorDescription))
		}
		return nil, fmt.Errorf("azure sign-in failed: %s",
			strings.TrimSpace(in.Error+" "+in.ErrorDescription))
	}

	if purpose == models.AzureOAuthPurposeConsent {
		return s.finishConsent(ctx, st, stateTenant, in)
	}
	return s.finishLogin(ctx, st, in)
}

func (s *AzureOnboardService) finishLogin(
	ctx context.Context, st *models.AzureOAuthState, in AzureCallbackInput,
) (*AzureCallbackResult, error) {
	if in.Code == "" {
		return nil, errors.New("callback carried no authorization code")
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	tok, err := s.azure.ExchangeCode(callCtx, in.Code, s.redirectURI)
	if err != nil {
		return nil, err
	}

	sessionID, err := s.saveSession(st.WorkspaceID, tok)
	if err != nil {
		return nil, err
	}
	return &AzureCallbackResult{
		Step:        "logged_in",
		WorkspaceID: st.WorkspaceID,
		SessionID:   sessionID,
	}, nil
}

func (s *AzureOnboardService) finishConsent(
	_ context.Context, st *models.AzureOAuthState, stateTenant string, in AzureCallbackInput,
) (*AzureCallbackResult, error) {
	// Three independent statements of which tenant this is. All three must
	// agree: the state row, the tenant encoded in the state string, and what
	// Microsoft appended. Only the first two are ours.
	if st.TenantID == "" || st.TenantID != stateTenant {
		return nil, repositories.ErrAzureStateInvalid
	}
	if tenantParam := strings.TrimSpace(in.Tenant); tenantParam != "" &&
		!strings.EqualFold(tenantParam, st.TenantID) {
		return nil, azureonboard.ErrTenantMismatch
	}

	// admin_consent=True is the grant. Anything else -- False, absent, or a
	// value we do not recognise -- is not consent, and must not write a row that
	// claims it was.
	if !strings.EqualFold(strings.TrimSpace(in.AdminConsent), "true") {
		return nil, azureonboard.ErrConsentDenied
	}

	// Display fields come from whatever the earlier tenant listing recorded;
	// the consent callback carries none. COALESCE in the repository keeps an
	// existing name rather than blanking it.
	display, domain := "", ""
	if existing, err := s.repo.Get(st.WorkspaceID, st.TenantID); err == nil {
		display, domain = existing.DisplayName, existing.Domain
	}

	stored, created, err := s.repo.UpsertConsent(st.WorkspaceID, st.TenantID, display, domain)
	if err != nil {
		return nil, err
	}
	return &AzureCallbackResult{
		Step:        "consented",
		WorkspaceID: st.WorkspaceID,
		Connector:   stored,
		Created:     created,
	}, nil
}

/* -------------------------------- tenants -------------------------------- */

// AzureTenantView is one row of the tenant picker.
type AzureTenantView struct {
	TenantID         string   `json:"tenantId"`
	DisplayName      string   `json:"displayName,omitempty"`
	Domains          []string `json:"domains"`
	AlreadyConnected bool     `json:"alreadyConnected"`
	ARMReaderOK      bool     `json:"armReaderOk"`
}

// ListTenants returns the tenants the signed-in operator can see.
//
// This is ARM's tenant list, which is scoped to that person's own access -- the
// same set the Azure portal shows under "Manage tenants". It is not a directory
// enumeration and cannot become one: no Graph call is involved.
func (s *AzureOnboardService) ListTenants(
	ctx context.Context, workspaceID uuid.UUID, sessionID string,
) ([]AzureTenantView, error) {
	tok, err := s.loadSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	tenants, err := s.azure.ListTenants(callCtx, tok.AccessToken)
	if err != nil {
		return nil, err
	}

	connected, err := s.repo.ConnectedTenantIDs(workspaceID)
	if err != nil {
		return nil, err
	}

	out := make([]AzureTenantView, 0, len(tenants))
	for _, t := range tenants {
		view := AzureTenantView{
			TenantID:         t.TenantID,
			DisplayName:      t.DisplayName,
			Domains:          t.Domains,
			AlreadyConnected: connected[t.TenantID],
		}
		if view.Domains == nil {
			view.Domains = []string{}
		}
		if view.AlreadyConnected {
			if row, gErr := s.repo.Get(workspaceID, t.TenantID); gErr == nil {
				view.ARMReaderOK = row.ARMReaderOK
			}
		}
		out = append(out, view)
	}
	return out, nil
}

/* -------------------------------- consent -------------------------------- */

// StartConsent mints a consent state for one tenant and returns where to send
// the administrator's browser.
func (s *AzureOnboardService) StartConsent(
	workspaceID uuid.UUID, actor, tenantID string,
) (string, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return "", err
	}
	state, err := azureonboard.NewConsentState(tenantID)
	if err != nil {
		return "", err
	}
	if err := s.repo.CreateState(&models.AzureOAuthState{
		State:       state,
		WorkspaceID: workspaceID,
		Purpose:     models.AzureOAuthPurposeConsent,
		TenantID:    tenantID,
		CreatedBy:   actor,
		ExpiresAt:   time.Now().Add(azureStateTTL),
	}); err != nil {
		return "", err
	}
	_ = s.repo.PurgeExpiredStates()
	return azureonboard.AdminConsentURL(s.clientID, s.redirectURI, tenantID, state), nil
}

/* ------------------------------- arm reader ------------------------------ */

// AzureARMResult is the outcome of an ARM Reader check.
type AzureARMResult struct {
	TenantID      string                      `json:"tenantId"`
	ARMReaderOK   bool                        `json:"arm_reader_ok"`
	Subscriptions []azureonboard.Subscription `json:"subscriptions,omitempty"`
	Count         int                         `json:"subscription_count"`
	Error         string                      `json:"error,omitempty"`

	// ReaderSetup is attached whenever the check did NOT pass, so the caller can
	// act on the failure without a second round trip.
	ReaderSetup *azureonboard.ReaderSetup `json:"reader_setup,omitempty"`
}

// ValidateARM proves whether the consented application can actually read ARM.
//
// App-only, not delegated: the question is what AUTHSEC can read in that tenant,
// and asking with the operator's own token would answer a different question and
// pass whenever the operator happens to be privileged.
func (s *AzureOnboardService) ValidateARM(
	ctx context.Context, workspaceID uuid.UUID, tenantID string,
) (*AzureARMResult, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	// Must already be consented: a client-credentials grant in a tenant that
	// never consented cannot succeed, and a row is what the verdict is recorded
	// against.
	if _, err := s.repo.Get(workspaceID, tenantID); err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	result := &AzureARMResult{TenantID: tenantID}

	tok, err := s.azure.ClientCredentials(callCtx, tenantID)
	if err != nil {
		result.Error = err.Error()
		if _, sErr := s.repo.SetARMResult(workspaceID, tenantID, false, result.Error); sErr != nil {
			return nil, sErr
		}
		return result, nil
	}

	subs, err := s.azure.ListSubscriptions(callCtx, tok.AccessToken)
	if err != nil {
		result.Error = err.Error()
		if _, sErr := s.repo.SetARMResult(workspaceID, tenantID, false, result.Error); sErr != nil {
			return nil, sErr
		}
		return result, nil
	}

	result.Subscriptions = subs
	result.Count = len(subs)

	// Persist what ARM named, then record coverage per scope. Listing a
	// subscription and being able to read it are the same fact here -- ARM only
	// returns subscriptions the caller has a role on -- but they are stored
	// separately so a later per-scope probe can disagree without losing the row.
	if err := s.persistSubscriptions(workspaceID, tenantID, subs); err != nil {
		return nil, err
	}

	// A 200 alone is NOT the pass condition.
	//
	// ARM answers 200 with an empty list when the token is valid but the
	// application holds no role assignment anywhere -- which is exactly the
	// state this check exists to detect. Treating that as success reports a
	// tenant as fully onboarded while the app can read nothing at all, and it
	// was observed doing so against a real tenant. The verdict is therefore
	// "ARM returned at least one subscription", not "ARM answered".
	if len(subs) == 0 {
		result.Error = "azure accepted the app-only token but returned no subscriptions: " +
			"the Reader role is not assigned to the AuthSec application in this tenant"
		result.ReaderSetup = s.readerSetup(tenantID, tok, subs)
		if _, sErr := s.repo.SetARMResult(workspaceID, tenantID, false, result.Error); sErr != nil {
			return nil, sErr
		}
		return result, nil
	}

	result.ARMReaderOK = true
	if _, err := s.repo.SetARMResult(workspaceID, tenantID, true, ""); err != nil {
		return nil, err
	}
	if tok.PrincipalObjectID != "" {
		_ = s.repo.SetPrincipalObjectID(workspaceID, tenantID, tok.PrincipalObjectID)
	}
	return result, nil
}

// readerSetup builds the role-assignment instructions for a tenant, targeting
// the first subscription ARM will admit to when there is one.
func (s *AzureOnboardService) readerSetup(
	tenantID string, tok *azureonboard.TokenSet, subs []azureonboard.Subscription,
) *azureonboard.ReaderSetup {
	scope := ""
	scopes := make([]string, 0, len(subs))
	for _, sub := range subs {
		scopes = append(scopes, "/subscriptions/"+sub.SubscriptionID)
	}
	if len(scopes) > 0 {
		scope = scopes[0]
	}
	oid := ""
	if tok != nil {
		oid = tok.PrincipalObjectID
	}
	setup := azureonboard.BuildReaderSetup(tenantID, oid, scope, scopes)
	return &setup
}

// ReaderSetup returns the role-assignment instructions for a consented tenant.
//
// Separate from ValidateARM because an operator needs it BEFORE the check can
// pass, not only after it fails. Requires consent to have completed: the
// service principal object id comes from an app-only token, which a tenant that
// never consented cannot issue.
func (s *AzureOnboardService) ReaderSetup(
	ctx context.Context, workspaceID uuid.UUID, tenantID string,
) (*azureonboard.ReaderSetup, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	if _, err := s.repo.Get(workspaceID, tenantID); err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	tok, err := s.azure.ClientCredentials(callCtx, tenantID)
	if err != nil {
		return nil, err
	}
	if tok.PrincipalObjectID != "" {
		_ = s.repo.SetPrincipalObjectID(workspaceID, tenantID, tok.PrincipalObjectID)
	}

	// Best effort: if ARM already answers, the real subscription ids go into the
	// commands instead of a placeholder.
	subs, _ := s.azure.ListSubscriptions(callCtx, tok.AccessToken)
	return s.readerSetup(tenantID, tok, subs), nil
}

/* ------------------------------- connectors ------------------------------ */

// Connectors lists this workspace's consented tenants.
func (s *AzureOnboardService) Connectors(workspaceID uuid.UUID) ([]models.AzureConnector, error) {
	return s.repo.List(workspaceID)
}

/* --------------------------------- session -------------------------------- */

// The operator's delegated token goes to the secrets store, not to a cookie and
// not to a process-memory map: a cookie would put a live ARM bearer token in a
// browser, and a memory map would drop every sign-in on restart and would not
// exist at all on the other replica.
func azureSessionPath(workspaceID uuid.UUID, sessionID string) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/cloud-discovery/azure/sessions/%s",
		workspaceID, sessionID)
}

func (s *AzureOnboardService) saveSession(
	workspaceID uuid.UUID, tok *azureonboard.TokenSet,
) (string, error) {
	if s.vault == nil {
		return "", errors.New("vault client not configured; the azure sign-in token cannot be stored")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	sessionID := base64.RawURLEncoding.EncodeToString(raw)

	if err := s.vault.WriteSecret(azureSessionPath(workspaceID, sessionID), map[string]interface{}{
		"access_token":  tok.AccessToken,
		"refresh_token": tok.RefreshToken,
		"expires_at":    tok.ExpiresAt.UTC().Format(time.RFC3339),
		"session_ends":  time.Now().Add(azureSessionTTL).UTC().Format(time.RFC3339),
	}); err != nil {
		return "", fmt.Errorf("store azure sign-in: %w", err)
	}
	return sessionID, nil
}

// loadSession returns a usable delegated token, refreshing it when the access
// token has aged out but the sign-in itself has not.
func (s *AzureOnboardService) loadSession(
	ctx context.Context, workspaceID uuid.UUID, sessionID string,
) (*azureonboard.TokenSet, error) {
	if sessionID == "" {
		return nil, azureonboard.ErrNoSession
	}
	// The id lands in a secrets-store path. Anything outside the alphabet it was
	// minted from is rejected rather than escaped.
	if !isBase64URL(sessionID) || len(sessionID) > 128 {
		return nil, azureonboard.ErrNoSession
	}
	if s.vault == nil {
		return nil, errors.New("vault client not configured")
	}

	path := azureSessionPath(workspaceID, sessionID)
	data, err := s.vault.ReadSecret(path)
	if err != nil || data == nil {
		return nil, azureonboard.ErrNoSession
	}

	if ends, ok := data["session_ends"].(string); ok {
		if t, pErr := time.Parse(time.RFC3339, ends); pErr == nil && time.Now().After(t) {
			_ = s.vault.DeleteSecret(path)
			return nil, azureonboard.ErrNoSession
		}
	}

	tok := &azureonboard.TokenSet{}
	tok.AccessToken, _ = data["access_token"].(string)
	tok.RefreshToken, _ = data["refresh_token"].(string)
	if exp, ok := data["expires_at"].(string); ok {
		if t, pErr := time.Parse(time.RFC3339, exp); pErr == nil {
			tok.ExpiresAt = t
		}
	}
	if !tok.Expired() {
		return tok, nil
	}
	if tok.RefreshToken == "" {
		return nil, azureonboard.ErrNoSession
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	refreshed, err := s.azure.Refresh(callCtx, tok.RefreshToken)
	if err != nil {
		return nil, azureonboard.ErrNoSession
	}
	// Microsoft may or may not rotate the refresh token; keep the old one when
	// it does not, or the next refresh has nothing to present.
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = tok.RefreshToken
	}
	if wErr := s.vault.WriteSecret(path, map[string]interface{}{
		"access_token":  refreshed.AccessToken,
		"refresh_token": refreshed.RefreshToken,
		"expires_at":    refreshed.ExpiresAt.UTC().Format(time.RFC3339),
		"session_ends":  orNow(data["session_ends"]),
	}); wErr != nil {
		return nil, wErr
	}
	return refreshed, nil
}

// EndSession discards a stored sign-in.
func (s *AzureOnboardService) EndSession(workspaceID uuid.UUID, sessionID string) {
	if s.vault == nil || sessionID == "" || !isBase64URL(sessionID) {
		return
	}
	_ = s.vault.DeleteSecret(azureSessionPath(workspaceID, sessionID))
}

func orNow(v interface{}) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return time.Now().Add(azureSessionTTL).UTC().Format(time.RFC3339)
}

func isBase64URL(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

/* --------------------------- assigning reader for them -------------------------- */

// AssignReaderResult reports what was granted, and where.
type AssignReaderResult struct {
	TenantID string                          `json:"tenantId"`
	Assigned []azureonboard.AssignmentResult `json:"assigned"`
	AllOK    bool                            `json:"all_ok"`

	// Fallback is attached when nothing could be granted, so an operator who
	// lacks the privilege is not left with only an error.
	Fallback *azureonboard.ReaderSetup `json:"fallback,omitempty"`
}

// AssignReader grants ARM Reader to the AuthSec application, without the
// customer running anything.
//
// It works by asking ARM on behalf of the SIGNED-IN OPERATOR. The application
// cannot grant itself a role; a human holding Owner or User Access
// Administrator can, and this performs exactly the request that human would
// make through the portal. If they do not hold it, ARM refuses and the manual
// instructions come back instead -- nothing is half-done.
//
// scope is optional. Empty means "every subscription this operator can see in
// the tenant", which is what makes it one click rather than one per
// subscription. A root management group scope covers future subscriptions too,
// but needs privilege at the root that most operators have to grant themselves
// first, so it is never assumed.
func (s *AzureOnboardService) AssignReader(
	ctx context.Context, workspaceID uuid.UUID, sessionID, tenantID, scope string,
) (*AssignReaderResult, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	if _, err := s.repo.Get(workspaceID, tenantID); err != nil {
		return nil, err
	}

	sess, err := s.loadSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.RefreshToken == "" {
		return nil, azureonboard.ErrNoSession
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	// An ARM token issued by the sign-in tenant is refused when writing into a
	// subscription that lives in a different directory, so trade the refresh
	// token for one this tenant accepts.
	userTok, err := s.azure.RefreshForTenant(callCtx, sess.RefreshToken, tenantID)
	if err != nil {
		return nil, err
	}

	// The principal being granted access is the application's service principal
	// in this tenant, which only an app-only token can name.
	appTok, err := s.azure.ClientCredentials(callCtx, tenantID)
	if err != nil {
		return nil, err
	}
	principal := appTok.PrincipalObjectID
	if principal == "" {
		return nil, errors.New("could not determine the service principal object id for this tenant")
	}
	_ = s.repo.SetPrincipalObjectID(workspaceID, tenantID, principal)

	scopes := []string{}
	if scope = strings.TrimSpace(scope); scope != "" {
		scopes = append(scopes, scope)
	} else {
		// The OPERATOR's token, not the application's: the whole point is that
		// the operator can already see these and the application cannot yet.
		subs, sErr := s.azure.ListSubscriptions(callCtx, userTok.AccessToken)
		if sErr != nil {
			return nil, sErr
		}
		for _, sub := range subs {
			scopes = append(scopes, "/subscriptions/"+sub.SubscriptionID)
		}
	}

	result := &AssignReaderResult{TenantID: tenantID}
	if len(scopes) == 0 {
		result.Fallback = s.readerSetup(tenantID, appTok, nil)
		return result, nil
	}

	allOK := true
	for _, sc := range scopes {
		r := s.azure.AssignRole(callCtx, userTok.AccessToken, sc, principal,
			azureonboard.ReaderRoleDefinitionID)
		result.Assigned = append(result.Assigned, r)
		if !r.OK {
			allOK = false
		}
	}
	result.AllOK = allOK
	if !allOK {
		result.Fallback = s.readerSetup(tenantID, appTok, nil)
	}
	return result, nil
}

/* ------------------------- subscriptions and plane 1 ------------------------- */

// persistSubscriptions records the subscriptions ARM returned and marks each
// one readable, since ARM only lists subscriptions the caller holds a role on.
func (s *AzureOnboardService) persistSubscriptions(
	workspaceID uuid.UUID, tenantID string, subs []azureonboard.Subscription,
) error {
	if len(subs) == 0 {
		return nil
	}
	rows := make([]models.AzureSubscription, 0, len(subs))
	readable := make(map[string]bool, len(subs))
	for _, sub := range subs {
		rows = append(rows, models.AzureSubscription{
			SubscriptionID: sub.SubscriptionID,
			DisplayName:    sub.DisplayName,
			State:          sub.State,
		})
		readable[sub.SubscriptionID] = true
	}
	if err := s.repo.UpsertSubscriptions(workspaceID, tenantID, rows); err != nil {
		return err
	}
	return s.repo.SetSubscriptionReader(workspaceID, tenantID, readable)
}

// Subscriptions lists what is known about one tenant's subscriptions.
func (s *AzureOnboardService) Subscriptions(
	workspaceID uuid.UUID, tenantID string,
) ([]models.AzureSubscription, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	return s.repo.ListSubscriptions(workspaceID, tenantID)
}

// AzureGraphResult is the outcome of a Microsoft Graph authorisation check.
type AzureGraphResult struct {
	TenantID string   `json:"tenantId"`
	GraphOK  bool     `json:"graph_ok"`
	Granted  []string `json:"granted_roles"`
	Missing  []string `json:"missing_roles"`
	Error    string   `json:"error,omitempty"`
	Hint     string   `json:"hint,omitempty"`

	// Capabilities is what the granted permissions can actually reach. A
	// permission can be granted and still withhold its data -- sign-in logs
	// need an Entra ID P1/P2 licence regardless of consent -- and a discovery
	// reader that does not know which is which fails in a way that reads as a
	// bug. Reported separately from GraphOK because a licence gate is a
	// customer purchasing decision, not a missing grant.
	Capabilities []azureonboard.GraphCapability `json:"capabilities,omitempty"`
}

// ValidateGraph proves whether admin consent actually granted anything.
//
// The counterpart to ValidateARM, and needed for the same reason: consent and
// capability are different facts. A tenant can complete admin consent and hold
// no permission at all -- which is what happens when the application declares
// none, since .default grants only what is declared. Recording consented_at and
// moving on reports a success nobody checked.
//
// The verdict comes from the roles claim of an app-only Graph token, not from
// calling Graph. That works even when nothing was granted, costs no extra
// request, and names the individual permissions that are missing.
func (s *AzureOnboardService) ValidateGraph(
	ctx context.Context, workspaceID uuid.UUID, tenantID string,
) (*AzureGraphResult, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	if _, err := s.repo.Get(workspaceID, tenantID); err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	result := &AzureGraphResult{TenantID: tenantID, Granted: []string{}, Missing: []string{}}

	tok, err := s.azure.GraphToken(callCtx, tenantID)
	if err != nil {
		result.Error = err.Error()
		result.Missing = azureonboard.RequiredGraphRoles()
		if errors.Is(err, azureonboard.ErrAppNotInTenant) {
			result.Hint = "admin consent has not completed in this tenant; run POST /api/azure/consent"
		}
		if _, sErr := s.repo.SetGraphResult(workspaceID, tenantID, false, nil, result.Error); sErr != nil {
			return nil, sErr
		}
		return result, nil
	}

	auth := azureonboard.AuthorizationFromToken(tok.AccessToken)
	result.GraphOK = auth.OK
	result.Granted = auth.Granted
	result.Missing = auth.Missing

	// Only worth probing once something was actually granted; with nothing
	// granted every capability would fail for the obvious reason.
	if len(auth.Granted) > 0 {
		result.Capabilities = s.azure.ProbeGraphCapabilities(callCtx, tok.AccessToken)
	}

	if !auth.OK {
		if len(auth.Granted) == 0 {
			// The specific, and by far the most common, failure: consent
			// succeeded and granted nothing because the app registration
			// declares no application permissions.
			result.Error = "admin consent completed but the application holds no permissions in this tenant"
			result.Hint = "the app registration declares no Microsoft Graph APPLICATION permissions, " +
				"so .default consent grants nothing; declare them on the registration " +
				"(Type must be Application, not Delegated) and consent again"
		} else {
			result.Error = "some required graph permissions are not granted"
			result.Hint = "re-run admin consent for this tenant after declaring the missing permissions"
		}
	}

	if _, err := s.repo.SetGraphResult(workspaceID, tenantID, auth.OK, auth.Granted, result.Error); err != nil {
		return nil, err
	}
	if tok.PrincipalObjectID != "" {
		_ = s.repo.SetPrincipalObjectID(workspaceID, tenantID, tok.PrincipalObjectID)
	}
	return result, nil
}

/* ----------------------- checking our own app registration ----------------------- */

// azureHomeTenantEnv names the tenant the App Registration itself lives in.
//
// Needed because an application object exists ONLY in its home tenant -- a
// customer tenant holds a service principal instead -- so a self-check must use
// a home-tenant token. Falls back to AZURE_SIGNIN_TENANT when that is a GUID,
// which it is on any deployment that had to pin sign-in.
const azureHomeTenantEnv = "AZURE_HOME_TENANT"

// AppCheckFinding is one thing the app registration gets wrong.
type AppCheckFinding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"` // "error" blocks onboarding, "warning" does not
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

// AppCheckResult is the verdict on our own App Registration.
type AppCheckResult struct {
	AppID          string `json:"app_id"`
	DisplayName    string `json:"display_name"`
	SignInAudience string `json:"sign_in_audience"`
	HomeTenant     string `json:"home_tenant"`

	RedirectURIs        []string `json:"redirect_uris"`
	DeclaredPermissions []string `json:"declared_permissions"`
	MissingPermissions  []string `json:"missing_permissions"`

	SecretCount int        `json:"secret_count"`
	CertCount   int        `json:"cert_count"`
	CredExpires *time.Time `json:"credential_expires_at,omitempty"`

	OK       bool              `json:"ok"`
	Findings []AppCheckFinding `json:"findings"`
}

// CheckAppRegistration asserts the App Registration matches what this code
// requires, read-only.
//
// WHY THIS EXISTS. Every field it checks is something the runbook currently asks
// a human to verify by eye in the portal, and one of them -- undeclared
// application permissions -- produced a consent that succeeded while granting
// nothing, and read as a code bug for an hour. A machine checks all of them in
// one call.
//
// WHY IT NEEDS NO NEW PERMISSION. Application.Read.All is already required for
// identity discovery, and reading one application is within it. It needs no
// WRITE access, which matters: a check that can only report and never repair
// cannot itself become a way to repoint the product at a different application.
//
// It also serves both setup paths. Whether the registration was created by hand
// in the portal or by an automated bootstrap, this is the single assertion that
// says the end state is correct.
func (s *AzureOnboardService) CheckAppRegistration(ctx context.Context) (*AppCheckResult, error) {
	home := strings.TrimSpace(os.Getenv(azureHomeTenantEnv))
	if home == "" && azureonboard.ValidateTenantID(azureonboard.SignInTenant) == nil {
		home = azureonboard.SignInTenant
	}
	if err := azureonboard.ValidateTenantID(home); err != nil {
		return nil, fmt.Errorf("cannot check the app registration: set %s to the tenant the "+
			"registration was created in (an application object exists only in its home tenant)",
			azureHomeTenantEnv)
	}

	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	tok, err := s.azure.GraphToken(callCtx, home)
	if err != nil {
		return nil, err
	}
	app, err := s.azure.ReadOwnApp(callCtx, tok.AccessToken, s.clientID)
	if err != nil {
		return nil, err
	}

	res := &AppCheckResult{
		AppID:               app.AppID,
		DisplayName:         app.DisplayName,
		SignInAudience:      app.SignInAudience,
		HomeTenant:          home,
		RedirectURIs:        app.Web.RedirectURIs,
		DeclaredPermissions: []string{},
		MissingPermissions:  []string{},
		Findings:            []AppCheckFinding{},
	}

	// 1. Multi-tenant, or no customer can ever consent.
	if app.SignInAudience != "AzureADMultipleOrgs" {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "sign_in_audience",
			Severity: "error",
			Detail: fmt.Sprintf("signInAudience is %q; a customer tenant cannot consent to "+
				"anything but AzureADMultipleOrgs", app.SignInAudience),
			Fix: "portal -> Authentication -> Supported account types -> " +
				"Accounts in any organizational directory (Multitenant)",
		})
	}

	// 2. The configured redirect URI must be registered, or Microsoft refuses
	//    with AADSTS50011 before a password is typed.
	registered := false
	for _, u := range app.Web.RedirectURIs {
		if u == s.redirectURI {
			registered = true
			break
		}
	}
	if !registered {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "redirect_uri",
			Severity: "error",
			Detail: fmt.Sprintf("AZURE_REDIRECT_URI is %q but the registration lists %v",
				s.redirectURI, app.Web.RedirectURIs),
			Fix: "add that exact URI under Authentication -> Web. A registration holds a " +
				"list, so add it alongside the existing entries rather than replacing them",
		})
	}

	// 3. Declared application permissions. The application object stores role
	//    IDs, never names, so the comparison is by ID.
	declared := map[string]bool{}
	for _, r := range app.RequiredResourceAccess {
		if r.ResourceAppID != azureonboard.GraphResourceAppID {
			continue
		}
		for _, a := range r.ResourceAccess {
			// "Role" is an application permission; "Scope" is delegated, and a
			// delegated grant never appears in an app-only token's roles claim.
			if a.Type == "Role" {
				declared[a.ID] = true
			}
		}
	}
	for name, id := range azureonboard.RequiredGraphRoleIDs() {
		if declared[id] {
			res.DeclaredPermissions = append(res.DeclaredPermissions, name)
		} else {
			res.MissingPermissions = append(res.MissingPermissions, name)
		}
	}
	sort.Strings(res.DeclaredPermissions)
	sort.Strings(res.MissingPermissions)

	if len(res.MissingPermissions) > 0 {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "declared_permissions",
			Severity: "error",
			Detail: fmt.Sprintf("not declared as APPLICATION permissions: %s. Admin consent uses "+
				"scope=.default, which grants only what the application declares, so consent "+
				"would succeed and grant nothing",
				strings.Join(res.MissingPermissions, ", ")),
			Fix: "portal -> API permissions -> Add a permission -> Microsoft Graph -> " +
				"Application permissions (not Delegated) -> add them -> Grant admin consent",
		})
	}

	// 4. Credentials, and how long they have left. A secret nobody is watching
	//    expires and breaks every consented tenant at once.
	res.SecretCount = len(app.PasswordCredentials)
	res.CertCount = len(app.KeyCredentials)

	var soonest *time.Time
	for _, c := range app.PasswordCredentials {
		if c.EndDateTime != nil && (soonest == nil || c.EndDateTime.Before(*soonest)) {
			soonest = c.EndDateTime
		}
	}
	for _, c := range app.KeyCredentials {
		if c.EndDateTime != nil && (soonest == nil || c.EndDateTime.Before(*soonest)) {
			soonest = c.EndDateTime
		}
	}
	res.CredExpires = soonest

	switch {
	case res.SecretCount == 0 && res.CertCount == 0:
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credentials",
			Severity: "error",
			Detail:   "the registration has no client secret and no certificate",
			Fix:      "portal -> Certificates & secrets -> New client secret, or upload a certificate",
		})
	case soonest != nil && time.Until(*soonest) < 30*24*time.Hour:
		sev := "warning"
		if time.Until(*soonest) <= 0 {
			sev = "error"
		}
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credential_expiry",
			Severity: sev,
			Detail: fmt.Sprintf("the soonest credential expires %s (%d days)",
				soonest.UTC().Format("2006-01-02"), int(time.Until(*soonest).Hours()/24)),
			Fix: "issue a new secret or certificate before then. This credential is global: " +
				"when it lapses, every consented tenant stops working at once",
		})
	}

	// A certificate is preferable, but a secret is not a defect.
	if res.CertCount == 0 && res.SecretCount > 0 {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credential_type",
			Severity: "warning",
			Detail:   "authenticating with a client secret rather than a certificate",
			Fix: "a certificate signs an assertion instead of sending the credential, so it " +
				"never crosses the network and can live in an HSM as non-exportable",
		})
	}

	res.OK = true
	for _, f := range res.Findings {
		if f.Severity == "error" {
			res.OK = false
		}
	}
	return res, nil
}
