package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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

	// azureAllowRootElevationEnv opts a deployment into letting AuthSec raise
	// the operator to root User Access Administrator when a tenant-wide Reader
	// grant is refused. Off unless set: see assignReaderTenantWide.
	azureAllowRootElevationEnv = "AZURE_ALLOW_ROOT_ELEVATION"
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

	// homeTenant is the directory the App Registration was created in. Empty
	// means "fall back to the environment"; ForWorkspace fills it from a stored
	// configuration. An application object exists only in its home tenant, so
	// checking our own registration cannot be done without it.
	homeTenant string

	// appCfg is resolved lazily so the zero-value service used by tests needs no
	// database.
	appCfg repositories.AzureAppConfigRepository

	// clientFixed marks a Microsoft client injected by WithClient. ForWorkspace
	// must not replace it, or a test would silently start talking to Azure.
	clientFixed bool

	// credKind is which credential form this service authenticates with, for the
	// check to report. Never the value.
	//
	// It matters because the two questions differ: an application can have a
	// certificate uploaded AND be configured here with a secret, in which case
	// the registration looks exemplary while every token request still sends a
	// password.
	credKind azureonboard.CredentialKind

	// credThumbprint identifies WHICH uploaded certificate is ours, when the
	// credential is one. Without it the check can only say whether the
	// registration has some certificate, which is a different question.
	credThumbprint string

	// bindProblem is why a STORED application could not be used.
	//
	// ForWorkspace falls back to the environment when it cannot bind the row a
	// workspace submitted, and that fallback used to be silent. The result was
	// an error naming the wrong thing: with the row present and its secret
	// unreadable, Ready() reported "missing client id, redirect uri, client
	// secret" -- three values that were all sitting in the row -- and said
	// nothing about the secret it had failed to read. Debugging that starts by
	// checking the three things that are fine.
	bindProblem string
}

// NewAzureOnboardService builds the service against the live Microsoft
// client. Returns ErrNotConfigured when the deployment has no Entra app.
func NewAzureOnboardService(db *gorm.DB, vc vault.VaultClient) (*AzureOnboardService, error) {
	clientID := strings.TrimSpace(os.Getenv(azureClientIDEnv))
	clientSecret := strings.TrimSpace(os.Getenv(azureClientSecretEnv))
	redirectURI := strings.TrimSpace(os.Getenv(azureRedirectURIEnv))

	// Deliberately NOT an error when the environment is empty. A workspace can
	// now supply its own application through POST /api/azure/config, and that is
	// the whole point of the setup flow -- refusing to construct would make the
	// endpoint that fixes the problem unreachable. Ready() reports the state
	// instead, after the workspace is known and its stored row has been consulted.
	return &AzureOnboardService{
		db:    db,
		repo:  repositories.NewAzureConnectorRepository(db),
		vault: vc,
		// nil when the deployment has no secret. ForWorkspace may still supply
		// one from a stored configuration; Ready() reports the gap if not.
		azure:       azureClientOrNil(clientID, clientSecret),
		clientID:    clientID,
		redirectURI: redirectURI,
		// The environment supplies a secret and nothing else. A workspace that
		// stored a certificate overrides this in ForWorkspace.
		credKind: azureonboard.CredentialSecret,
	}, nil
}

// WithClient swaps the Microsoft client. Test seam, mirroring the AWS service.
func (s *AzureOnboardService) WithClient(c azureonboard.Client) *AzureOnboardService {
	s.azure = c
	s.clientFixed = true
	return s
}

// Ready reports whether this service has a usable Entra application, naming what
// is absent when it does not.
//
// Called AFTER ForWorkspace, never before: a deployment with no AZURE_* variables
// at all is perfectly usable by a workspace that submitted its own application,
// and answering from the environment alone would call that deployment broken.
func (s *AzureOnboardService) Ready() error {
	var missing []string
	if strings.TrimSpace(s.clientID) == "" {
		missing = append(missing, "client id")
	}
	if strings.TrimSpace(s.redirectURI) == "" {
		missing = append(missing, "redirect uri")
	}
	if s.azure == nil {
		missing = append(missing, "client secret")
	}
	// Checked BEFORE the missing list, and independently of it. A stored
	// application that could not be bound is a hard stop even when the
	// deployment has its own AZURE_* variables set, because the alternative is
	// falling back to a different application than the workspace submitted --
	// silently, and while reporting itself healthy.
	if s.bindProblem != "" {
		return fmt.Errorf("%w: this workspace has a stored application, but it could not "+
			"be used: %s", azureonboard.ErrNotConfigured, s.bindProblem)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s. Submit them with POST /api/azure/config, "+
			"or set %s / %s / %s on the deployment",
			azureonboard.ErrNotConfigured, strings.Join(missing, ", "),
			azureClientIDEnv, azureClientSecretEnv, azureRedirectURIEnv)
	}
	return nil
}

// azureClientOrNil avoids handing out a client that would authenticate with an
// empty secret and fail with a confusing AADSTS7000215 instead of a clear
// "not configured".
// rootElevationEnabled reports whether this deployment permits the privilege
// raise. Read per call rather than at startup so it can be turned on without a
// restart -- and so a test can set it.
func rootElevationEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(azureAllowRootElevationEnv)), "true")
}

func azureClientOrNil(clientID, clientSecret string) azureonboard.Client {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return nil
	}
	return azureonboard.NewHTTPClient(clientID, clientSecret)
}

/* --------------------------------- login --------------------------------- */

// StartLogin mints a one-shot state and returns where to send the browser.
//
// autoSetup marks the state as the FIRST leg of the automatic setup: when that
// callback returns, it sends the browser straight on to the tenant's admin
// consent page rather than answering, and the second callback starts the chain.
//
// Two redirects rather than one is not a shortcoming, it is the only thing that
// works. See AuthorizeURL: v2.0 rejects prompt=admin_consent outright, and one
// /authorize call carries one resource, so an ARM code and a Graph
// application-permission grant cannot come from the same screen.
//
// autoSetup MUST NOT be reachable from the unauthenticated /login route, and the
// controller does not read it from a query parameter for exactly that reason.
// The distinction is not cosmetic: this path writes an azure_connectors row, and
// /login is a browser navigation with no bearer token -- so honouring a query
// parameter there would let anyone who can reach the deployment sign in with a
// tenant of their choosing and file it into a workspace they hold no rights in,
// bypassing the discovery:admin check that guards every other write. Minting
// this state stays behind that check.
// tenantWide is only meaningful with autoSetup, and records which Reader
// strategy to use when the second callback runs. It is carried in the state
// rather than remembered here because the decision is made now and acted on two
// Microsoft round trips later.
func (s *AzureOnboardService) StartLogin(
	workspaceID uuid.UUID, actor string, autoSetup, tenantWide bool,
	signInTenant, loginHint string, pickAccount bool,
) (string, error) {
	// Validated here rather than trusted: it lands in the authority URL path.
	if t := strings.TrimSpace(signInTenant); t != "" {
		if err := azureonboard.ValidateSignInTenant(t); err != nil {
			return "", err
		}
		signInTenant = t
	}
	state, err := azureonboard.NewLoginState(autoSetup, tenantWide)
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
	return azureonboard.AuthorizeURL(s.clientID, s.redirectURI, state,
		signInTenant, loginHint, pickAccount), nil
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
// to azure_connectors on this path. A connector row is written on the consent
// callback, and on the merged sign-in-and-consent callback -- and the state for
// BOTH is minted by an authenticated, RBAC-checked endpoint, never by this one.
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

// ResolveSignInName answers "what do I type at the sign-in page for this tenant".
//
// An account whose credential lives outside the directory is represented there
// under a rewritten name -- someone@gmail.com becomes
// someone_gmail.com#EXT#@tenant.onmicrosoft.com -- and nobody knows their own.
// Typing the real address hands it to the consumer identity system, where a
// work-and-school application is not enabled, and Microsoft reports "You can't
// sign in here with a personal account" with no hint that a different username
// would work. This is the lookup that removes the guesswork.
//
// LIMIT: it needs an app-only Graph token, so the application must already be
// consented in that tenant. It helps a tenant that is onboarded or part-way
// through, not one nothing has touched yet.
func (s *AzureOnboardService) ResolveSignInName(
	ctx context.Context, tenantID, email string,
) (*azureonboard.SignInName, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, azureCallTimeout)
	defer cancel()

	tok, err := s.azure.GraphToken(callCtx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.azure.ResolveSignInName(callCtx, tok.AccessToken, email)
}

// PeekCallbackWorkspace says which workspace a pending redirect belongs to,
// without redeeming it. The callback needs this to bind the same Entra
// application the redirect was started with, before HandleCallback consumes the
// state.
func (s *AzureOnboardService) PeekCallbackWorkspace(state string) (uuid.UUID, error) {
	return s.repo.PeekStateWorkspace(strings.TrimSpace(state))
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

	// ConsentRedirect is where to send the browser NEXT, and is set only on the
	// first leg of an automatic setup. The sign-in succeeded; admin consent is a
	// second Microsoft screen, and the operator should not have to come back to
	// the console to ask for it.
	ConsentRedirect string

	// AutoSetupWide says the operator chose the tenant-wide Reader grant when
	// they started this. Never inferred: only a state minted by an operator who
	// asked for it can make this true, because that grant can briefly raise
	// their own privilege to root User Access Administrator.
	AutoSetupWide bool

	// AutoSetupWanted says this consent callback belongs to an automatic setup,
	// so the chain should be started. The service cannot start it itself: the
	// chain needs the sign-in session id, and only the caller can read the
	// cookie that carries it.
	AutoSetupWanted bool

	// AutoSetup reports that this callback started the background setup chain.
	AutoSetup bool

	// AutoSetupSkipped says why it did not, when the sign-in had asked for it.
	// Empty when nothing was asked for. An operator who reaches the console and
	// finds nothing happening deserves the reason rather than silence.
	AutoSetupSkipped string
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
	// Defence in depth. Every other entry point reaches this service through
	// serviceFor(), which checks Ready() -- but /callback is unauthenticated and
	// was able to arrive here with a nil Microsoft client, which crashed the
	// process on the code exchange. A guard at the boundary costs nothing and
	// does not depend on every future caller remembering.
	if err := s.Ready(); err != nil {
		return nil, err
	}

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
	res := &AzureCallbackResult{
		Step:        "logged_in",
		WorkspaceID: st.WorkspaceID,
		SessionID:   sessionID,
	}
	if !azureonboard.LoginStateAutoSetup(st.State) {
		return res, nil
	}

	// First leg of an automatic setup. Reaching here means the state was minted
	// behind discovery:admin, because that is the only place that can mark a
	// login state this way.
	//
	// NOTHING is recorded about consent yet, because nothing has been consented.
	// The sign-in proves who the operator is and gets an ARM token; the grant is
	// the next screen. Writing a connector row here -- which an earlier version
	// of this did, on the belief that one screen could do both -- would claim a
	// grant that may never happen.
	//
	// Which tenant to consent is not in the callback: /authorize does not name
	// one the way /adminconsent does. The token does, in tid.
	tenantID := azureonboard.TenantIDFromToken(tok.AccessToken)
	if tenantID == "" {
		res.AutoSetupSkipped = "could not determine which tenant was signed in to"
		return res, nil
	}

	consentURL, err := s.startAutoConsent(st.WorkspaceID, st.CreatedBy, tenantID,
		azureonboard.LoginStateTenantWide(st.State))
	if err != nil {
		// The sign-in itself worked and the session is usable, so this is not
		// fatal -- report it and let the operator finish by hand.
		res.AutoSetupSkipped = "could not start admin consent: " + err.Error()
		return res, nil
	}
	res.ConsentRedirect = consentURL
	return res, nil
}

// startAutoConsent mints the second leg's state and returns where to send the
// browser for admin consent.
//
// Separate from StartConsent because the state is marked, so that callback knows
// to run the chain rather than stopping at "consented".
func (s *AzureOnboardService) startAutoConsent(
	workspaceID uuid.UUID, actor, tenantID string, tenantWide bool,
) (string, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
		return "", err
	}
	state, err := azureonboard.NewConsentState(tenantID, true, tenantWide)
	if err != nil {
		return "", err
	}
	if err := s.repo.CreateState(&models.AzureOAuthState{
		State:       state,
		WorkspaceID: workspaceID,
		Purpose:     models.AzureOAuthPurposeConsent,
		TenantID:    tenantID,
		CreatedBy:   firstNonEmpty(actor, "auto-setup"),
		ExpiresAt:   time.Now().Add(azureStateTTL),
	}); err != nil {
		return "", err
	}
	return azureonboard.AdminConsentURL(s.clientID, s.redirectURI, tenantID, state), nil
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
		// Second leg of an automatic setup. The caller starts the chain, because
		// it needs the sign-in session id and only the caller can read the
		// cookie holding it.
		AutoSetupWanted: azureonboard.ConsentStateAutoSetup(st.State),
		AutoSetupWide:   azureonboard.ConsentStateTenantWide(st.State),
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
	state, err := azureonboard.NewConsentState(tenantID, false, false)
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

// keepRotatedRefresh stores the refresh token Entra handed back, replacing the
// one that was presented.
//
// Entra ROTATES a refresh token on redemption: the reply carries a new one, and
// the token presented is superseded. It keeps working for a short grace period
// and then stops. Discarding the replacement therefore does not fail
// immediately -- it fails on the third or fourth use of the same stored token,
// with an error that names consent rather than the token:
//
//	AADSTS65001: The user or administrator has not consented ...
//
// Every RefreshForTenant call must land here. It is deliberately best-effort:
// the caller already holds a usable access token, so a secrets-store hiccup
// should not fail the operation the operator asked for. The cost of losing the
// write is one extra sign-in later, which is what happened before this existed.
//
// Only the refresh token and the access token change. session_ends is preserved
// so this cannot extend a session past its original bound.
func (s *AzureOnboardService) keepRotatedRefresh(
	workspaceID uuid.UUID, sessionID string, tok *azureonboard.TokenSet,
) {
	if s.vault == nil || tok == nil || tok.RefreshToken == "" {
		return
	}
	if sessionID == "" || !isBase64URL(sessionID) {
		return
	}
	path := azureSessionPath(workspaceID, sessionID)
	existing, err := s.vault.ReadSecret(path)
	if err != nil || existing == nil {
		return
	}
	if prev, _ := existing["refresh_token"].(string); prev == tok.RefreshToken {
		return // not rotated; nothing to write
	}
	_ = s.vault.WriteSecret(path, map[string]interface{}{
		"access_token":  tok.AccessToken,
		"refresh_token": tok.RefreshToken,
		"expires_at":    tok.ExpiresAt.UTC().Format(time.RFC3339),
		"session_ends":  orNow(existing["session_ends"]),
	})
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

	// TenantWide says the grant was made once at the root management group and
	// therefore covers subscriptions created after it, rather than a snapshot of
	// the ones that existed at the time.
	TenantWide bool `json:"tenant_wide"`

	// Elevation is present only when the tenant-wide path had to raise the
	// operator's own privilege to complete. Always reported, never implied.
	Elevation *ElevationOutcome `json:"elevation,omitempty"`

	// Fallback is attached when nothing could be granted, so an operator who
	// lacks the privilege is not left with only an error.
	Fallback *azureonboard.ReaderSetup `json:"fallback,omitempty"`
}

// ElevationOutcome is the full account of a temporary root-scope privilege
// raise: whether it happened, and -- the part that matters -- whether it was
// given back.
//
// Every field is reported to the caller even on success. An operator has to be
// able to see that AuthSec briefly held the widest role in their tenant and then
// released it, without going to read an audit log to find out.
type ElevationOutcome struct {
	// Attempted is true once the direct assignment has been refused and this
	// path was entered at all.
	Attempted bool `json:"attempted"`

	// Elevated is true only when THIS call granted the role.
	Elevated bool `json:"elevated"`

	// Removed reports the outcome of putting it back. False alongside
	// Elevated:true is the one state that needs a human -- root User Access
	// Administrator does not expire on its own.
	Removed bool `json:"removed"`

	// AlreadyHeld means the operator held root User Access Administrator before
	// this call. Nothing was granted, and nothing is removed: it was not ours to
	// take away.
	AlreadyHeld bool `json:"already_held,omitempty"`

	Error string `json:"error,omitempty"`
}

const (
	// The tenant-wide path makes up to five ARM calls and waits out RBAC
	// propagation between them, so it needs a longer budget than one call.
	azureElevationTimeout = 3 * time.Minute

	// Removal runs on its own budget, deliberately NOT derived from the request
	// context. If the browser hangs up or the request deadline passes mid-flight,
	// the elevation still has to come back down.
	azureDeElevationTimeout = 45 * time.Second
)

// armPropagationBackoff paces the retry after elevating.
//
// A role assignment is authorised server-side per request, so no new token is
// needed -- but ARM caches the decision briefly, and a retry issued immediately
// after elevateAccess intermittently still sees 403. These delays cover the lag
// observed in practice without turning a failure into a two-minute hang.
var armPropagationBackoff = []time.Duration{
	2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second,
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
// subscription.
//
// tenantWide instead makes ONE assignment at the root management group, which
// covers subscriptions created after today rather than a snapshot of the ones
// that exist now. That scope needs User Access Administrator at the root, which
// nobody holds by default, so this is the only path allowed to raise the
// operator's own privilege -- briefly, explicitly, and only after the plain
// assignment has already been refused. See internal/azureonboard/elevate.go.
func (s *AzureOnboardService) AssignReader(
	ctx context.Context, workspaceID uuid.UUID, sessionID, tenantID, scope string, tenantWide bool,
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

	budget := azureCallTimeout
	if tenantWide {
		budget = azureElevationTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	// An ARM token issued by the sign-in tenant is refused when writing into a
	// subscription that lives in a different directory, so trade the refresh
	// token for one this tenant accepts.
	userTok, err := s.azure.RefreshForTenant(callCtx, sess.RefreshToken, tenantID)
	if err != nil {
		return nil, err
	}
	// Entra rotated the refresh token; keep the replacement or the next call
	// presents a superseded one. See keepRotatedRefresh.
	s.keepRotatedRefresh(workspaceID, sessionID, userTok)

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

	if tenantWide {
		return s.assignReaderTenantWide(callCtx, tenantID, userTok, appTok, principal), nil
	}

	scopes := []string{}
	if scope = strings.TrimSpace(scope); scope != "" {
		// Validated here for the same reason tenantID is: it is interpolated
		// into an ARM URL, and an unchecked one relocates the request.
		if err := azureonboard.ValidateARMScope(scope); err != nil {
			return nil, err
		}
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

// assignReaderTenantWide grants Reader once at the tenant root management group,
// covering every subscription including ones that do not exist yet.
//
// The ordering IS the safety argument, so it is spelled out rather than implied:
//
//  1. Try with the privilege the operator already has. Anyone who has done this
//     before is likely to still hold root User Access Administrator, and those
//     operators must never be elevated at all.
//  2. Only after a refusal, look for an EXISTING root elevation. If one is
//     there it reflects somebody's earlier decision, and removing it afterwards
//     would revoke standing access AuthSec never granted -- so this reports the
//     failure instead of touching it.
//  3. Otherwise elevate, retry, and give the privilege back. Removal runs on a
//     context of its own so a cancelled request cannot strand it.
//
// Returns rather than errors on every failure: the caller gets the fallback
// instructions, exactly as the per-subscription path does.
func (s *AzureOnboardService) assignReaderTenantWide(
	ctx context.Context, tenantID string,
	userTok, appTok *azureonboard.TokenSet, principal string,
) *AssignReaderResult {
	rootMG := azureonboard.RootManagementGroupScope(tenantID)
	result := &AssignReaderResult{TenantID: tenantID, TenantWide: true}

	assign := func() azureonboard.AssignmentResult {
		return s.azure.AssignRole(ctx, userTok.AccessToken, rootMG, principal,
			azureonboard.ReaderRoleDefinitionID)
	}

	// 1. The operator may already hold enough. Cheapest and least privileged.
	r := assign()
	result.Assigned = []azureonboard.AssignmentResult{r}
	if r.OK {
		result.AllOK = true
		return result
	}

	el := &ElevationOutcome{Attempted: true}
	result.Elevation = el

	// 1b. Everything below RAISES the operator to root User Access Administrator
	//     and is off unless a deployment turns it on.
	//
	//     Not because it is wrong -- it is careful, and thirteen tests hold its
	//     ordering -- but because it has never executed against Microsoft. Every
	//     run that reached this code did so with an operator who already held the
	//     privilege, so the assignment above succeeded and this branch was
	//     skipped. Code that can grant the widest role in Azure RBAC should not
	//     meet a customer's tenant for the first time in production.
	//
	//     The path that IS proven stays on: an operator holding Owner or User
	//     Access Administrator gets the tenant-wide grant at step 1, which is
	//     how it was verified end to end. Without the privilege they now get the
	//     fallback instructions instead of a silent elevation.
	//
	//     Remove this gate once it has been exercised against a real tenant.
	if !rootElevationEnabled() {
		el.Attempted = false
		el.Error = "the assignment was refused and automatic privilege elevation is disabled " +
			"on this deployment, so nothing was elevated. Either assign Reader at the tenant " +
			"root yourself, or set " + azureAllowRootElevationEnv + "=true to let AuthSec " +
			"raise and return the privilege for you"
		result.Fallback = s.readerSetup(tenantID, appTok, nil)
		return result
	}

	// 2. Do not touch an elevation somebody else put there.
	existing, err := s.azure.RootElevation(ctx, userTok.AccessToken, userTok.PrincipalObjectID)
	if err != nil {
		el.Error = "could not check for an existing root elevation, so did not elevate: " + err.Error()
		result.Fallback = s.readerSetup(tenantID, appTok, nil)
		return result
	}
	if existing != "" {
		el.AlreadyHeld = true
		el.Error = "the operator already holds User Access Administrator at root scope and the " +
			"assignment was still refused, so elevating would change nothing"
		result.Fallback = s.readerSetup(tenantID, appTok, nil)
		return result
	}

	// 3. From here on, removal is mandatory on every exit path.
	if err := s.azure.ElevateAccess(ctx, userTok.AccessToken); err != nil {
		el.Error = err.Error()

		// A refusal and a lost answer are not the same thing, and this used to
		// treat them alike -- returning before the removal defer exists. Some
		// failures are ambiguous: a timeout, a reset, a 5xx after the write.
		// ARM may well have applied the elevation, and nothing would ever have
		// taken it back. The status said elevated:false while the operator held
		// User Access Administrator at the tenant root, which is the one
		// outcome this whole dance exists to avoid.
		//
		// ErrNotGlobalAdmin is the exception: that one provably applied nothing,
		// so there is nothing to look for.
		if !errors.Is(err, azureonboard.ErrNotGlobalAdmin) {
			stray, lookErr := s.azure.RootElevation(
				ctx, userTok.AccessToken, userTok.PrincipalObjectID)
			switch {
			case lookErr != nil:
				el.Error = appendReason(el.Error,
					"and it could not be confirmed whether the elevation applied anyway: "+
						lookErr.Error()+". Check for a root-scope User Access Administrator "+
						"assignment on this operator and remove it by hand")
			case stray != "":
				// It did apply. Record it honestly and give it back.
				el.Elevated = true
				el.Error = appendReason(el.Error,
					"the elevation applied despite the error, and is being removed")
				s.removeElevation(userTok, el, stray)
			}
		}

		result.Fallback = s.readerSetup(tenantID, appTok, nil)
		return result
	}
	el.Elevated = true

	// Capture the assignment id NOW, while we know exactly one thing about the
	// world: ARM just granted it. Cleanup then addresses a known object instead
	// of re-deriving it from a filter later.
	//
	// This is not defensive tidiness. Deriving it at cleanup time means a lookup
	// that matches nothing is indistinguishable from "already removed" -- and a
	// simulation caught exactly that, reporting removed:true while root User
	// Access Administrator was still assigned.
	elevationID, idErr := s.azure.RootElevation(ctx, userTok.AccessToken, userTok.PrincipalObjectID)
	if idErr != nil {
		el.Error = appendReason(el.Error, "elevated, but could not read back the assignment id: "+idErr.Error())
	}
	defer s.removeElevation(userTok, el, elevationID)

	for _, wait := range armPropagationBackoff {
		select {
		case <-ctx.Done():
			el.Error = "gave up waiting for the elevated role to take effect: " + ctx.Err().Error()
			result.Fallback = s.readerSetup(tenantID, appTok, nil)
			return result
		case <-time.After(wait):
		}

		r = assign()
		result.Assigned = append(result.Assigned, r)
		if r.OK {
			result.AllOK = true
			return result
		}
	}

	result.Fallback = s.readerSetup(tenantID, appTok, nil)
	return result
}

// removeElevation gives the root-scope role back, and records whether it worked.
//
// The context is deliberately NOT derived from the request. A browser that hung
// up, or a deadline that passed mid-flight, must not be the reason a human is
// left holding User Access Administrator over an entire tenant -- and that role
// does not expire on its own.
//
// knownID is the assignment captured immediately after elevating. It is
// preferred over a fresh lookup for one reason: a lookup that matches nothing
// cannot be told apart from "already removed", and treating that as success
// reports removed:true while the role is still assigned.
//
// So Removed:true here means exactly one thing -- a DELETE was issued and ARM
// accepted it. Nothing weaker is allowed to set it.
func (s *AzureOnboardService) removeElevation(
	userTok *azureonboard.TokenSet, el *ElevationOutcome, knownID string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), azureDeElevationTimeout)
	defer cancel()

	id := knownID
	if id == "" {
		var err error
		id, err = s.azure.RootElevation(ctx, userTok.AccessToken, userTok.PrincipalObjectID)
		if err != nil {
			el.Error = appendReason(el.Error, "could not locate the elevation to remove: "+err.Error())
			return
		}
	}
	if id == "" {
		// We know a grant happened -- ARM accepted elevateAccess -- so finding
		// nothing is a failure to LOCATE it, never evidence it is gone.
		el.Error = appendReason(el.Error,
			"root User Access Administrator was granted but no matching assignment could be found "+
				"to remove it. Check by hand: Microsoft Entra ID -> Properties -> "+
				"Access management for Azure resources -> No")
		return
	}
	if err := s.azure.DeleteRoleAssignment(ctx, userTok.AccessToken, id); err != nil {
		el.Error = appendReason(el.Error,
			"FAILED to remove root User Access Administrator from the signed-in operator ("+id+
				"): "+err.Error()+". Remove it by hand: Microsoft Entra ID -> Properties -> "+
				"Access management for Azure resources -> No")
		return
	}
	el.Removed = true
}

func appendReason(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
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

// AvailableSubscriptions lists the subscriptions the SIGNED-IN OPERATOR can see
// in one tenant, so a caller can choose which of them to grant Reader on.
//
// Distinct from Subscriptions(), and the difference is which token asks:
//
//	Subscriptions()           the app's own view, from the database, and only
//	                          ever populated AFTER Reader was assigned
//	AvailableSubscriptions()  the operator's view, live from ARM, available
//	                          BEFORE any Reader exists
//
// Without this the choice cannot be offered at all: the only list the product
// held was one that does not exist until the grant it is meant to scope has
// already happened.
//
// It grants nothing and records nothing. It reports what a person can already
// see in their own portal.
func (s *AzureOnboardService) AvailableSubscriptions(
	ctx context.Context, workspaceID uuid.UUID, sessionID, tenantID string,
) ([]azureonboard.Subscription, error) {
	if err := azureonboard.ValidateTenantID(tenantID); err != nil {
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

	// Per-tenant, like every other ARM call here: a token issued by the sign-in
	// tenant is refused when reading a subscription in a different directory.
	userTok, err := s.azure.RefreshForTenant(callCtx, sess.RefreshToken, tenantID)
	if err != nil {
		return nil, err
	}
	// Entra rotated the refresh token; keep the replacement or the next call
	// presents a superseded one. See keepRotatedRefresh.
	s.keepRotatedRefresh(workspaceID, sessionID, userTok)
	return s.azure.ListSubscriptions(callCtx, userTok.AccessToken)
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
	TenantID string `json:"tenantId"`
	GraphOK  bool   `json:"graph_ok"`

	// Unreadable means the check could not obtain an app-only token at all, so
	// nothing is known about the permissions and Missing below is every required
	// one rather than an observation.
	//
	// Without this the two failures are indistinguishable from outside: both
	// leave Granted empty and Missing full. A caller reporting the missing list
	// then tells an operator "you granted nothing" when the application could
	// not authenticate -- and they re-grant four permissions that were never the
	// problem.
	Unreadable bool     `json:"unreadable,omitempty"`
	Granted    []string `json:"granted_roles"`
	Missing    []string `json:"missing_roles"`
	Error      string   `json:"error,omitempty"`
	Hint       string   `json:"hint,omitempty"`

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
		result.Unreadable = true
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

	// MissingARMScopes is the Azure Service Management DELEGATED permissions
	// that are not declared. A different API and a different permission type
	// from MissingPermissions, so a different field -- the portal path to fix
	// them is not the same one.
	MissingARMScopes []string `json:"missing_arm_scopes"`

	// MissingOptionalPermissions is what discovery would use if granted. Absent
	// ones do NOT make the check fail -- they narrow what gets collected, and
	// that is worth saying rather than discovering later from an empty table.
	MissingOptionalPermissions []string `json:"missing_optional_permissions"`

	SecretCount int `json:"secret_count"`

	// CredentialInUse is which form AuthSec authenticates with -- "secret" or
	// "certificate" -- as distinct from what the registration happens to hold.
	CredentialInUse string     `json:"credential_in_use,omitempty"`
	CertCount       int        `json:"cert_count"`
	CredExpires     *time.Time `json:"credential_expires_at,omitempty"`

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
	// The home tenant comes from the submitted configuration and nowhere else.
	//
	// It used to also be an environment variable, from before POST
	// /api/azure/config existed. That was one input too many: it is not a
	// secret, it is not a deployment property, and it belongs to a specific
	// application -- so keeping it beside the client id that it describes, in
	// the same row, is the only place it cannot drift out of step with.
	//
	// An application object exists ONLY in the directory it was created in; a
	// customer tenant holds a service principal instead. So this check has no
	// meaning without knowing that directory, and refusing is correct.
	home := strings.TrimSpace(s.homeTenant)
	if err := azureonboard.ValidateTenantID(home); err != nil {
		return nil, fmt.Errorf("%w: this workspace has no Entra application on record, so there "+
			"is nothing to check. Submit it with POST /api/azure/config, including the "+
			"Directory (tenant) ID the registration was created in",
			azureonboard.ErrNotConfigured)
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
		MissingARMScopes:    []string{},

		MissingOptionalPermissions: []string{},
		Findings:                   []AppCheckFinding{},
	}

	// 1. Multi-tenant, or no customer tenant can ever consent.
	//
	// Two values qualify, not one. AzureADandPersonalMicrosoftAccount is
	// AzureADMultipleOrgs plus consumer accounts, so every customer tenant can
	// still consent -- treating it as a defect would fail a deployment that
	// deliberately widened the audience.
	//
	// It is reported as a warning because it is not free: Microsoft caps such an
	// application at TWO client secrets and refuses it in the national clouds
	// (Gov, 21Vianet) outright. Both are permanent properties of the choice, and
	// both are easier to discover here than at a rotation or a Gov deployment.
	switch app.SignInAudience {
	case "AzureADMultipleOrgs":
	case "AzureADandPersonalMicrosoftAccount":
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "sign_in_audience",
			Severity: "warning",
			Detail: "signInAudience is AzureADandPersonalMicrosoftAccount, so personal Microsoft " +
				"accounts may sign in. Microsoft caps this audience at two client secrets and " +
				"does not support it in the national clouds",
			Fix: "intentional if personal accounts must be supported. Sign in via " +
				"/api/azure/login?tenant=common; note that a personal account with no Azure " +
				"subscription lands in the Microsoft Services tenant, which has no directory " +
				"and therefore nothing to onboard",
		})
	default:
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "sign_in_audience",
			Severity: "error",
			Detail: fmt.Sprintf("signInAudience is %q; a customer tenant cannot consent unless it "+
				"is AzureADMultipleOrgs or AzureADandPersonalMicrosoftAccount", app.SignInAudience),
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

	// 3. Declared permissions. The application object stores permission IDs,
	//    never names, so every comparison here is by ID.
	//
	//    Two resources, and both matter. Graph APPLICATION permissions are what
	//    the background discovery reads with. The Azure Service Management
	//    DELEGATED scope is what lets an operator assign Reader -- and it is the
	//    one that used to be missed, because sign-in obtains it by incremental
	//    consent and nothing here looked for it.
	declaredGraphRoles := map[string]bool{}
	declaredARMScopes := map[string]bool{}
	for _, r := range app.RequiredResourceAccess {
		switch r.ResourceAppID {
		case azureonboard.GraphResourceAppID:
			for _, a := range r.ResourceAccess {
				// "Role" is an application permission; "Scope" is delegated, and
				// a delegated grant never appears in an app-only token's roles
				// claim.
				if a.Type == "Role" {
					declaredGraphRoles[a.ID] = true
				}
			}
		case azureonboard.ARMResourceAppID:
			for _, a := range r.ResourceAccess {
				if a.Type == "Scope" {
					declaredARMScopes[a.ID] = true
				}
			}
		}
	}

	var missingGraph, missingARM, missingOptional []string
	for name, id := range azureonboard.RequiredGraphRoleIDs() {
		if declaredGraphRoles[id] {
			res.DeclaredPermissions = append(res.DeclaredPermissions, name)
		} else {
			missingGraph = append(missingGraph, name)
		}
	}
	// Optional ones are reported the same way and judged differently: granted,
	// they appear alongside the rest; missing, they are a warning rather than an
	// error, because discovery runs without them and only collects less.
	for name, id := range azureonboard.OptionalGraphRoleIDs() {
		if declaredGraphRoles[id] {
			res.DeclaredPermissions = append(res.DeclaredPermissions, name)
		} else {
			missingOptional = append(missingOptional, name)
		}
	}
	for name, id := range azureonboard.RequiredARMScopeIDs() {
		if declaredARMScopes[id] {
			res.DeclaredPermissions = append(res.DeclaredPermissions, "Azure Service Management / "+name)
		} else {
			missingARM = append(missingARM, name)
		}
	}
	sort.Strings(missingGraph)
	sort.Strings(missingARM)
	// Kept separate, and NOT merged into MissingPermissions.
	//
	// Every consumer of that field -- the console's "how to grant these" box,
	// the POST /config next hint -- renders it as "Microsoft Graph -> Application
	// permissions". Merging a DELEGATED scope on a DIFFERENT API into it made
	// them all instruct an operator to look for user_impersonation under Graph
	// application permissions, where it does not exist. Wrong instructions are
	// worse than none: this whole feature lost an afternoon to an error message
	// that named the wrong thing.
	res.MissingPermissions = missingGraph
	res.MissingARMScopes = missingARM
	sort.Strings(missingOptional)
	res.MissingOptionalPermissions = missingOptional
	sort.Strings(res.DeclaredPermissions)

	if len(missingGraph) > 0 {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "declared_permissions",
			Severity: "error",
			Detail: fmt.Sprintf("not declared as APPLICATION permissions: %s. Admin consent uses "+
				"scope=.default, which grants only what the application declares, so consent "+
				"would succeed and grant nothing",
				strings.Join(missingGraph, ", ")),
			Fix: "portal -> API permissions -> Add a permission -> Microsoft Graph -> " +
				"Application permissions (not Delegated) -> add them -> Grant admin consent",
		})
	}

	if len(missingOptional) > 0 {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check: "optional_permissions",
			// Warning, not error: onboarding is complete and discovery works.
			// Making this an error would tell every customer who does not want
			// Conditional Access in their access graph that their application
			// is broken.
			Severity: "warning",
			Detail: fmt.Sprintf("not declared, so discovery will not collect what they cover: %s. "+
				"Everything else still works", strings.Join(missingOptional, ", ")),
			Fix: "optional. To collect it: portal -> API permissions -> Add a permission -> " +
				"Microsoft Graph -> Application permissions -> expand Policy -> " +
				"Policy.Read.All -> Grant admin consent. The narrower " +
				"Policy.Read.ConditionalAccess does NOT work for this: it is granted, it " +
				"appears in the token, and the endpoint still answers AccessDenied",
		})
	}

	// Its own finding, because the failure it produces looks like something
	// else entirely and cost a real debugging session.
	if len(missingARM) > 0 {
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "declared_arm_scope",
			Severity: "error",
			Detail: fmt.Sprintf("not declared as a DELEGATED permission on the Azure Service "+
				"Management API: %s. Sign-in still obtains it by incremental consent, so this "+
				"looks fine until admin consent runs -- .default then replaces the delegated "+
				"grants with what the registration declares, deleting it. Reader assignment "+
				"afterwards fails with AADSTS65001 \"has not consented\", while Graph reports "+
				"fully consented",
				strings.Join(missingARM, ", ")),
			// The name to SEARCH FOR is the service principal's display name in
			// the directory, which is not what Microsoft's documentation calls
			// this API. Searching "Azure Service Management" returns No results,
			// and there is nothing on that screen to suggest why. The app id is
			// unambiguous and the search box accepts it.
			Fix: "portal -> API permissions -> Add a permission -> APIs my organization uses -> " +
				"search 797f4846-ba00-4fd7-ba43-dac1f8f63013 (its display name there is " +
				"\"Windows Azure Service Management API\", NOT \"Azure Service Management\") -> " +
				"Delegated permissions -> user_impersonation -> Add permissions -> " +
				"Grant admin consent",
		})
	}

	// 4. Credentials, and how long they have left. A secret nobody is watching
	//    expires and breaks every consented tenant at once.
	res.SecretCount = len(app.PasswordCredentials)
	res.CertCount = len(app.KeyCredentials)

	// The expiry of the credential IN USE, not the soonest on the registration.
	//
	// Those are different numbers whenever a registration carries credentials
	// AuthSec does not authenticate with -- which is the normal state after
	// switching from a secret to a certificate, because the old secrets are
	// still sitting there. Reporting the soonest told an operator "credential
	// expires 2027-03-07" while the certificate actually in use expired six
	// months later: they would plan a rotation for a credential nothing uses,
	// and get no warning for the one that matters.
	//
	// Observed exactly that against a real registration: two unused secrets, one
	// certificate, and the reported date belonged to a secret.
	var expires *time.Time
	ourCertUploaded := false
	switch s.credKind {
	case azureonboard.CredentialCertificate:
		for _, c := range app.KeyCredentials {
			if !sameThumbprint(c.CustomKeyIdentifier, s.credThumbprint) {
				continue
			}
			ourCertUploaded = true
			expires = c.EndDateTime
		}
	default:
		// A secret cannot be identified from the registration -- Graph returns
		// no value and no hash -- so the soonest is the honest answer, and it
		// is the right one when the secret in use is the only one.
		for _, c := range app.PasswordCredentials {
			if c.EndDateTime != nil && (expires == nil || c.EndDateTime.Before(*expires)) {
				expires = c.EndDateTime
			}
		}
	}
	res.CredExpires = expires

	switch {
	case res.SecretCount == 0 && res.CertCount == 0:
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credentials",
			Severity: "error",
			Detail:   "the registration has no client secret and no certificate",
			Fix:      "portal -> Certificates & secrets -> New client secret, or upload a certificate",
		})
	// The credential IN USE, so the warning fires on the date that matters.
	// Warning on the soonest credential on the registration meant nagging about
	// a secret nothing uses while the one being used quietly approached expiry.
	case expires != nil && time.Until(*expires) < 30*24*time.Hour:
		sev := "warning"
		if time.Until(*expires) <= 0 {
			sev = "error"
		}
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credential_expiry",
			Severity: sev,
			Detail: fmt.Sprintf("the %s AuthSec authenticates with expires %s (%d days)",
				firstNonEmpty(string(s.credKind), "credential"),
				expires.UTC().Format("2006-01-02"), int(time.Until(*expires).Hours()/24)),
			Fix: "issue a new one before then. This credential is global: when it lapses, " +
				"every consented tenant stops working at once",
		})
	}

	// What is IN USE, cross-referenced with what is registered.
	res.CredentialInUse = string(s.credKind)
	switch {
	case s.credKind == azureonboard.CredentialCertificate && !ourCertUploaded:
		// Configured to sign assertions against a certificate the registration
		// does not have. Every token request will be rejected, and the error
		// will be about the assertion rather than the missing upload.
		detail := "configured with a certificate, but the registration has no certificate " +
			"uploaded. Microsoft verifies the signed assertion against a public key it " +
			"holds, and there is none"
		if res.CertCount > 0 {
			// Worse than none, and much harder to spot: certificates ARE
			// uploaded, just not this one. "cert_count > 0" reads like success.
			detail = fmt.Sprintf("the registration has %d certificate(s) uploaded, but none of "+
				"them is the one AuthSec holds the key for. Signing will be refused with "+
				"AADSTS700027", res.CertCount)
		}
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credential_type",
			Severity: "error",
			Detail:   detail,
			Fix: "portal -> Certificates & secrets -> Certificates -> Upload certificate, " +
				"using the public certificate that matches the private key submitted here",
		})

	case s.credKind == azureonboard.CredentialSecret && res.CertCount > 0:
		// The registration looks exemplary and the credential still crosses the
		// network on every call. Worth saying plainly, because nothing else here
		// would reveal it.
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credential_type",
			Severity: "warning",
			Detail: "a certificate is uploaded on the registration, but AuthSec is configured " +
				"with a client secret, so the credential is still sent on every token request",
			Fix: "re-submit with generateCertificate to switch. Note that AuthSec makes its " +
				"own key pair, so the certificate already uploaded is not the one it will " +
				"use -- you will upload the new one and can then remove the old",
		})

	case s.credKind == azureonboard.CredentialSecret:
		// The ordinary case. Not a defect.
		res.Findings = append(res.Findings, AppCheckFinding{
			Check:    "credential_type",
			Severity: "warning",
			Detail:   "authenticating with a client secret rather than a certificate",
			Fix: "a certificate signs an assertion instead of sending the credential, so it " +
				"never crosses the network. Set generateCertificate and AuthSec will make the " +
				"key pair, keep the private half, and hand you the certificate to upload",
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

// sameThumbprint compares a Graph customKeyIdentifier with our x5t.
//
// The same twenty bytes, written two ways -- and comparing the strings never
// matches. The failure that produces is "your certificate is not uploaded" on a
// registration where it plainly is, which sends an operator to upload it again.
//
// HEX is what Graph actually returns for an X509 credential, observed against a
// real registration:
//
//	customKeyIdentifier  C2EC90B404B8213FC5B3FB2A61D2E8E2CDEE9CEB
//	x5t                  wuyQtAS4IT_Fs_sqYdLo4s3unOs
//
// The documentation describes the field as base64, and for other credential
// types it is, so both are tried rather than assuming either.
func sameThumbprint(graphKeyID, x5t string) bool {
	if graphKeyID == "" || x5t == "" {
		return false
	}
	decode := func(v string) []byte {
		if b, err := hex.DecodeString(v); err == nil && len(b) > 0 {
			return b
		}
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding,
			base64.URLEncoding, base64.RawURLEncoding,
		} {
			if b, err := enc.DecodeString(v); err == nil && len(b) > 0 {
				return b
			}
		}
		return nil
	}
	a, b := decode(graphKeyID), decode(x5t)
	return a != nil && b != nil && bytes.Equal(a, b)
}
