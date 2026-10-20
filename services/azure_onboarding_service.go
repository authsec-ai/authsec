package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// AzureOnboardingService connects a customer's Entra tenant and Azure
// subscriptions to an AuthSec workspace through AuthSec's ONE multi-tenant app
// registration.
//
// The customer's only actions are Microsoft's own consent and sign-in screens:
//
//  1. Start      -> admin-consent URL (leg 1). Granting it creates the
//     customer's service principal of the AuthSec app and grants the
//     Microsoft Graph application permissions configured on it.
//  2. Callback   -> leg 1 returns; the browser is sent straight on to a
//     delegated sign-in against the consented tenant (leg 2) for the
//     administrator's own Azure Resource Manager access.
//  3. Callback   -> leg 2 returns; the code is redeemed and the
//     administrator's ARM token is parked in Redis behind an opaque
//     session id, for at most azureOAuthSessionTTL.
//  4. Connect    -> verify the service principal and its Graph permissions,
//     check the signed-in user may bind the tenant, list subscriptions,
//     create the Reader assignment on each one AS THE ADMINISTRATOR, prove
//     each with AuthSec's OWN app-only token, and inventory the resources.
//
// Graph consent and Azure RBAC are separate grants. Admin consent gives the
// service principal directory read access and nothing in any subscription;
// the service principal holds no roleAssignments/write and so can never grant
// itself Reader. Every assignment is made with the delegated token of a human
// who holds that permission, through the same ARM API the portal uses.
//
// The managed flow persists no credential. AuthSec's client secret stays in
// the deployment environment (cloud_connector.auth_ref is the non-secret
// "azure-app:<id>"), no refresh token is ever requested, and the
// administrator's access token lives only in Redis until Connect consumes it or
// the TTL expires it -- the same one-shot discipline as
// GCPOAuthProvisionService. The own-app flow (ConnectCustom) stores the
// customer's client secret in Vault only, never in Postgres, and destroys it
// on revoke (azure_custom_app.go).
type AzureOnboardingService struct {
	db         *gorm.DB
	redis      *redis.Client
	cfg        azure.AppConfig
	api        *azure.Client
	vault      vault.VaultClient
	connectors repositories.CloudConnectorRepository
	inventory  repositories.CloudAzureRepository
}

// NewAzureOnboardingService constructs the service. redisClient may be nil, in
// which case Available reports false and every flow method fails with
// azure.ErrNotConfigured. vc is an optional Vault client for storing custom app
// credentials; nil disables the custom-app onboarding path.
func NewAzureOnboardingService(db *gorm.DB, redisClient *redis.Client, cfg azure.AppConfig, vc vault.VaultClient) *AzureOnboardingService {
	return &AzureOnboardingService{
		db:         db,
		redis:      redisClient,
		cfg:        cfg,
		api:        azure.NewClient(nil),
		vault:      vc,
		connectors: repositories.NewCloudConnectorRepository(db),
		inventory:  repositories.NewCloudAzureRepository(db),
	}
}

/* --------------------------------- errors ---------------------------------- */

var (
	// ErrAzureOAuthStateInvalid means the state Microsoft redirected back with
	// does not match a live, unexpired, unused Start (or leg-1) call.
	ErrAzureOAuthStateInvalid = errors.New("azure: this microsoft sign-in request could not be verified (missing, expired, or already used); please start again")

	// ErrAzureSessionInvalid means the session id does not match a live,
	// unexpired, unused sign-in.
	ErrAzureSessionInvalid = errors.New("azure: this microsoft sign-in session has expired or was already used; please connect again")

	// ErrAzureSessionMismatch means the session belongs to another workspace or
	// another AuthSec user. Checked before any Microsoft call.
	ErrAzureSessionMismatch = errors.New("azure: this microsoft sign-in session belongs to a different workspace or user")

	// ErrAzureConnectorRevoked means a verify was asked of a revoked connector.
	ErrAzureConnectorRevoked = errors.New("azure: this connection was revoked; connect the tenant again")

	// ErrAzureVaultNotConfigured means a custom app flow was attempted but
	// Vault (VAULT_ADDR/VAULT_TOKEN) is not configured, so the customer's
	// client secret has nowhere safe to be stored.
	ErrAzureVaultNotConfigured = errors.New("azure: vault is not configured; custom app credentials cannot be stored securely")
)

/* ------------------------------ redis payloads ------------------------------ */

const (
	azureOAuthStateTTL   = 10 * time.Minute
	azureOAuthSessionTTL = 15 * time.Minute

	azureStageConsent = "consent"
	azureStageSignIn  = "signin"

	// connectBudget bounds Connect below the 120s server timeout
	// (middlewares.TimeoutMiddleware does not cancel the request context, so
	// the service sets its own deadline).
	azureConnectBudget = 105 * time.Second
	// azureVerifyBudget is the most Connect waits for Azure to apply a new
	// Reader assignment before recording it as pending.
	azureVerifyBudget = 60 * time.Second
	// azureInventoryReserve is held back from the verification wait so the
	// inventory pass always gets to run.
	azureInventoryReserve = 30 * time.Second
	// azureAssignConcurrency bounds parallel ARM writes per tenant.
	azureAssignConcurrency = 4
)

func azureOAuthStateKey(state string) string       { return "azure:oauth:state:" + state }
func azureOAuthSessionKey(sessionID string) string { return "azure:oauth:session:" + sessionID }

// azureOAuthState is the CSRF state of one leg. The PKCE verifier is minted at
// Start and carried into leg 2, the only leg that redeems a code.
type azureOAuthState struct {
	WorkspaceID  string `json:"workspace_id"`
	CreatedBy    string `json:"created_by"`
	Stage        string `json:"stage"`
	TenantID     string `json:"tenant_id,omitempty"`
	CodeVerifier string `json:"code_verifier"`
	LoginHint    string `json:"login_hint,omitempty"`
}

// azureOAuthSession holds the administrator's delegated ARM token. This struct
// and the Redis value it is marshaled into are the ONLY place that token exists
// outside a single request's memory; it is never written to Postgres, Vault, a
// connector, an audit payload, a log line or a response.
type azureOAuthSession struct {
	WorkspaceID  string    `json:"workspace_id"`
	CreatedBy    string    `json:"created_by"`
	TenantID     string    `json:"tenant_id"`
	UserObjectID string    `json:"user_object_id"`
	Username     string    `json:"username"`
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

/* --------------------------------- availability ------------------------------ */

// Available reports whether the Entra onboarding option can be offered: the
// AZURE_AUTHSEC_* configuration is complete and Redis answers.
func (s *AzureOnboardingService) Available(ctx context.Context) bool {
	if s.redis == nil || !s.cfg.Configured() {
		return false
	}
	return s.redis.Ping(ctx).Err() == nil
}

/* ----------------------------------- start ----------------------------------- */

// Start begins the flow for the caller's workspace and returns the
// admin-consent URL to send the browser to. tenantHint (a tenant id or
// verified domain) and loginHint are optional.
func (s *AzureOnboardingService) Start(ctx context.Context, workspaceID uuid.UUID, actor, tenantHint, loginHint string) (string, string, error) {
	if !s.Available(ctx) {
		return "", "", azure.ErrNotConfigured
	}
	tenantHint = strings.TrimSpace(tenantHint)
	if tenantHint != "" && !azure.ValidTenantHint(tenantHint) {
		return "", "", fmt.Errorf("%w: tenant must be a tenant id or a domain name", azure.ErrInvalidInput)
	}
	loginHint = strings.TrimSpace(loginHint)
	if len(loginHint) > 256 || strings.ContainsAny(loginHint, " \t\r\n") {
		return "", "", fmt.Errorf("%w: login_hint must be a single sign-in name", azure.ErrInvalidInput)
	}

	state, err := gcpOAuthRandomToken(32)
	if err != nil {
		return "", "", fmt.Errorf("%w: generating state: %v", azure.ErrNotConfigured, err)
	}
	verifier, err := gcpOAuthRandomToken(48)
	if err != nil {
		return "", "", fmt.Errorf("%w: generating pkce verifier: %v", azure.ErrNotConfigured, err)
	}
	if err := s.putState(ctx, state, azureOAuthState{
		WorkspaceID:  workspaceID.String(),
		CreatedBy:    actor,
		Stage:        azureStageConsent,
		CodeVerifier: verifier,
		LoginHint:    loginHint,
	}); err != nil {
		return "", "", err
	}
	return azure.AdminConsentURL(s.cfg, state, tenantHint), state, nil
}

func (s *AzureOnboardingService) putState(ctx context.Context, state string, st azureOAuthState) error {
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := s.redis.Set(ctx, azureOAuthStateKey(state), payload, azureOAuthStateTTL).Err(); err != nil {
		return fmt.Errorf("%w: storing oauth state: %v", azure.ErrNotConfigured, err)
	}
	return nil
}

/* --------------------------------- callback ---------------------------------- */

// AzureCallbackParams is what Microsoft put on the redirect URI.
type AzureCallbackParams struct {
	State            string
	Code             string
	AdminConsent     string
	Tenant           string
	Error            string
	ErrorDescription string
}

// AzureCallbackOutcome is what the unauthenticated callback does next: send
// the browser on to Microsoft for leg 2 (NextURL), or back into the AuthSec UI
// with an opaque session id (SessionID).
type AzureCallbackOutcome struct {
	NextURL   string
	SessionID string
}

// HandleCallback serves both legs on the one registered redirect URI. The
// state record, consumed exactly once, says which leg this is. It returns no
// workspace data and makes no change to any connector: everything that acts
// is authenticated and happens in Connect.
func (s *AzureOnboardingService) HandleCallback(ctx context.Context, p AzureCallbackParams) (*AzureCallbackOutcome, error) {
	if s.redis == nil || !s.cfg.Configured() {
		return nil, azure.ErrNotConfigured
	}
	if p.State == "" {
		return nil, ErrAzureOAuthStateInvalid
	}
	raw, err := s.redis.GetDel(ctx, azureOAuthStateKey(p.State)).Result()
	if err != nil {
		return nil, ErrAzureOAuthStateInvalid
	}
	var st azureOAuthState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil, ErrAzureOAuthStateInvalid
	}

	switch st.Stage {
	case azureStageConsent:
		return s.handleConsentLeg(ctx, st, p)
	case azureStageSignIn:
		return s.handleSignInLeg(ctx, st, p)
	}
	return nil, ErrAzureOAuthStateInvalid
}

func (s *AzureOnboardingService) handleConsentLeg(ctx context.Context, st azureOAuthState, p AzureCallbackParams) (*AzureCallbackOutcome, error) {
	if p.Error != "" {
		logAzureRefusal("admin consent", p.Error, p.ErrorDescription)
		return nil, azure.ErrConsentDenied
	}
	if !strings.EqualFold(p.AdminConsent, "true") || !azure.IsGUID(p.Tenant) {
		return nil, azure.ErrConsentDenied
	}

	// The tenant here came through the browser and is NOT trusted on its
	// own. It only decides which tenant's sign-in page leg 2 opens; the
	// tenant AuthSec binds is the tid in leg 2's token response, which must
	// equal it (handleSignInLeg).
	next, err := gcpOAuthRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("%w: generating state: %v", azure.ErrNotConfigured, err)
	}
	tenantID := strings.ToLower(p.Tenant)
	if err := s.putState(ctx, next, azureOAuthState{
		WorkspaceID:  st.WorkspaceID,
		CreatedBy:    st.CreatedBy,
		Stage:        azureStageSignIn,
		TenantID:     tenantID,
		CodeVerifier: st.CodeVerifier,
		LoginHint:    st.LoginHint,
	}); err != nil {
		return nil, err
	}
	return &AzureCallbackOutcome{
		NextURL: azure.SignInURL(s.cfg, tenantID, next, gcpOAuthPKCES256(st.CodeVerifier), st.LoginHint),
	}, nil
}

func (s *AzureOnboardingService) handleSignInLeg(ctx context.Context, st azureOAuthState, p AzureCallbackParams) (*AzureCallbackOutcome, error) {
	if p.Error != "" {
		logAzureRefusal("sign-in", p.Error, p.ErrorDescription)
		if strings.Contains(p.ErrorDescription, "AADSTS65001") {
			return nil, azure.ErrConsentRequired
		}
		return nil, azure.ErrSignInFailed
	}
	if p.Code == "" {
		return nil, azure.ErrSignInFailed
	}

	tok, err := s.api.ExchangeCode(ctx, s.cfg, st.TenantID, p.Code, st.CodeVerifier)
	if err != nil {
		logAzureError("sign-in code exchange", err)
		if errors.Is(err, azure.ErrConsentRequired) || errors.Is(err, azure.ErrCredentialRejected) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", azure.ErrSignInFailed, err)
	}
	if tok.TenantID != st.TenantID {
		return nil, azure.ErrTenantMismatch
	}

	ttl := azureOAuthSessionTTL
	if until := time.Until(tok.ExpiresAt) - time.Minute; until < ttl {
		ttl = until
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: microsoft issued an access token that is already expiring", azure.ErrSignInFailed)
	}

	sessionID, err := gcpOAuthRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("%w: generating session id: %v", azure.ErrNotConfigured, err)
	}
	payload, err := json.Marshal(azureOAuthSession{
		WorkspaceID:  st.WorkspaceID,
		CreatedBy:    st.CreatedBy,
		TenantID:     tok.TenantID,
		UserObjectID: tok.ObjectID,
		Username:     tok.Username,
		AccessToken:  tok.AccessToken,
		// The session's own end, not the token's: the Redis TTL below is
		// what actually bounds it, and the UI counts down to this value.
		ExpiresAt: time.Now().Add(ttl),
	})
	if err != nil {
		return nil, err
	}
	if err := s.redis.Set(ctx, azureOAuthSessionKey(sessionID), payload, ttl).Err(); err != nil {
		return nil, fmt.Errorf("%w: storing oauth session: %v", azure.ErrNotConfigured, err)
	}
	return &AzureCallbackOutcome{SessionID: sessionID}, nil
}

/* ------------------------------ session access ------------------------------- */

// loadSession reads the session WITHOUT consuming it, so a mismatched probe or
// a failed preview never burns a session a legitimate retry could use.
func (s *AzureOnboardingService) loadSession(ctx context.Context, sessionID string, workspaceID uuid.UUID, actor string) (*azureOAuthSession, error) {
	if s.redis == nil {
		return nil, azure.ErrNotConfigured
	}
	if sessionID == "" {
		return nil, ErrAzureSessionInvalid
	}
	raw, err := s.redis.Get(ctx, azureOAuthSessionKey(sessionID)).Result()
	if err != nil {
		return nil, ErrAzureSessionInvalid
	}
	var sess azureOAuthSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return nil, ErrAzureSessionInvalid
	}
	// Bound to the AuthSec user who started the flow, not only to the
	// workspace: a colleague in the same workspace must not be able to spend
	// another person's Azure administrator session.
	if sess.WorkspaceID != workspaceID.String() || sess.CreatedBy != actor {
		return nil, ErrAzureSessionMismatch
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrAzureSessionInvalid
	}
	return &sess, nil
}

/* ---------------------------------- preview ---------------------------------- */

// AzureSubscriptionPreview is one subscription as the signed-in administrator
// sees it, before anything is changed.
type AzureSubscriptionPreview struct {
	SubscriptionID string `json:"subscription_id"`
	DisplayName    string `json:"display_name"`
	State          string `json:"state"`
	// Eligible is whether the subscription's state accepts a role assignment.
	Eligible bool `json:"eligible"`
	// CanAssignReader is whether the administrator holds
	// roleAssignments/write there; nil when that could not be determined.
	CanAssignReader *bool `json:"can_assign_reader"`
}

// AzureSessionView is what the UI shows between sign-in and Connect.
type AzureSessionView struct {
	TenantID         string                     `json:"tenant_id"`
	Username         string                     `json:"username"`
	ExpiresAt        time.Time                  `json:"expires_at"`
	AlreadyConnected bool                       `json:"already_connected"`
	Subscriptions    []AzureSubscriptionPreview `json:"subscriptions"`
}

// Session previews what Connect would act on. Read-only on both sides.
func (s *AzureOnboardingService) Session(ctx context.Context, sessionID string, workspaceID uuid.UUID, actor string) (*AzureSessionView, error) {
	sess, err := s.loadSession(ctx, sessionID, workspaceID, actor)
	if err != nil {
		return nil, err
	}
	subs, err := s.tenantSubscriptions(ctx, sess)
	if err != nil {
		return nil, err
	}

	view := &AzureSessionView{
		TenantID:      sess.TenantID,
		Username:      sess.Username,
		ExpiresAt:     sess.ExpiresAt,
		Subscriptions: make([]AzureSubscriptionPreview, len(subs)),
	}
	if c, err := s.connectors.GetByScope(workspaceID, models.CloudProviderAzure, sess.TenantID); err == nil {
		view.AlreadyConnected = c.Status != models.CloudConnectorRevoked
	}

	forEachLimited(len(subs), azureAssignConcurrency, func(i int) {
		sub := subs[i]
		p := AzureSubscriptionPreview{
			SubscriptionID: sub.SubscriptionID,
			DisplayName:    sub.DisplayName,
			State:          sub.State,
			Eligible:       azureSubscriptionAssignable(sub.State),
		}
		if perms, err := s.api.CallerPermissions(ctx, sess.AccessToken, sub.SubscriptionID); err == nil {
			can := azure.AllowsAction(perms, azure.RoleAssignmentWriteAction)
			p.CanAssignReader = &can
		}
		view.Subscriptions[i] = p
	})
	return view, nil
}

// tenantSubscriptions lists the subscriptions the administrator can see in the
// signed-in tenant, sorted by id.
func (s *AzureOnboardingService) tenantSubscriptions(ctx context.Context, sess *azureOAuthSession) ([]azure.Subscription, error) {
	all, err := s.api.ListSubscriptions(ctx, sess.AccessToken)
	if err != nil {
		return nil, err
	}
	out := make([]azure.Subscription, 0, len(all))
	for _, sub := range all {
		// A subscription listed by this token but homed in another directory
		// belongs to a different tenant's onboarding.
		if sub.TenantID != "" && !strings.EqualFold(sub.TenantID, sess.TenantID) {
			continue
		}
		if !azure.IsGUID(sub.SubscriptionID) {
			continue
		}
		sub.SubscriptionID = strings.ToLower(sub.SubscriptionID)
		out = append(out, sub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SubscriptionID < out[j].SubscriptionID })
	return out, nil
}

// azureSubscriptionAssignable reports whether a subscription in this state
// accepts new role assignments. Disabled, Expired and Deleted subscriptions
// are read-only.
// Azure allows write operations only in Enabled and PastDue; Warned, Disabled
// and Expired block PUT/PATCH/POST, and a role assignment is a PUT.
func azureSubscriptionAssignable(state string) bool {
	switch strings.ToLower(state) {
	case "enabled", "pastdue":
		return true
	}
	return false
}

/* ---------------------------------- connect ---------------------------------- */

// AzureSubscriptionResult is the outcome for one subscription.
type AzureSubscriptionResult struct {
	SubscriptionID string                       `json:"subscription_id"`
	DisplayName    string                       `json:"display_name"`
	State          string                       `json:"state"`
	ConnectorID    *uuid.UUID                   `json:"connector_id,omitempty"`
	Status         string                       `json:"status"`
	Reader         models.AzureReaderAssignment `json:"reader"`
	Error          string                       `json:"error,omitempty"`
}

// AzureConnectResult is the outcome of Connect.
type AzureConnectResult struct {
	Tenant           *models.CloudConnector        `json:"tenant"`
	TenantCreated    bool                          `json:"tenant_created"`
	GraphPermissions []models.AzureGraphPermission `json:"graph_permissions"`
	Subscriptions    []AzureSubscriptionResult     `json:"subscriptions"`
	// Status is "active" when every selected subscription is readable by
	// AuthSec, "partial" otherwise. A tenant with no subscriptions is
	// active: its Graph connection is the whole connection.
	Status string `json:"status"`
	// Discovery is whether the background identity and resource discovery
	// started ("started") or one was already running ("already_running").
	// Its progress is each connector's coverage.
	Discovery string `json:"discovery"`
	// Warnings are facts the connection was made despite: an app that holds
	// more than AuthSec needs, subscriptions it cannot read, a tenant that
	// switched between the AuthSec app and the customer's own app.
	Warnings []string `json:"warnings,omitempty"`
}

// Connect performs the onboarding for the session's tenant. subscriptionIDs
// narrows it to a subset of the administrator's visible subscriptions; empty
// means all of them.
func (s *AzureOnboardingService) Connect(parent context.Context, sessionID string, workspaceID uuid.UUID, actor string, subscriptionIDs []string) (*AzureConnectResult, error) {
	ctx, cancel := context.WithTimeout(parent, azureConnectBudget)
	defer cancel()

	sess, err := s.loadSession(ctx, sessionID, workspaceID, actor)
	if err != nil {
		return nil, err
	}
	wanted, err := normalizeSubscriptionIDs(subscriptionIDs)
	if err != nil {
		return nil, err
	}
	tid := sess.TenantID

	// 1. AuthSec's own Graph access in the tenant. Fails with
	//    ErrAppNotInTenant when admin consent never happened there.
	graphToken, err := s.api.AppToken(ctx, s.cfg, tid, azure.ScopeGraphApp)
	if err != nil {
		logAzureError("graph app token", err)
		return nil, err
	}

	// 2. The AuthSec service principal in the customer tenant.
	sp, err := s.findAuthSecServicePrincipal(ctx, graphToken)
	if err != nil {
		return nil, err
	}

	// 3. Graph permissions: granted, then usable.
	perms, missing, _, err := s.verifyGraphPermissions(ctx, graphToken, sp.ID)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", azure.ErrGraphPermissionsMissing, strings.Join(missing, ", "))
	}

	// 4. May this person attach this tenant to this workspace?
	existingTenant, _ := s.connectors.GetByScope(workspaceID, models.CloudProviderAzure, tid)
	boundHere := existingTenant != nil && existingTenant.Status != models.CloudConnectorRevoked
	if err := s.authorizeBinding(ctx, graphToken, sess.UserObjectID, boundHere); err != nil {
		return nil, err
	}

	// 5. Subscriptions, as the administrator sees them.
	subs, err := s.tenantSubscriptions(ctx, sess)
	if err != nil {
		logAzureError("list subscriptions", err)
		return nil, err
	}
	selected, err := selectSubscriptions(subs, wanted)
	if err != nil {
		return nil, err
	}

	// 6. The tenant connector -- the Graph half of the connection.
	now := time.Now()
	tenantConn := &models.CloudConnector{
		WorkspaceID: workspaceID,
		Provider:    models.CloudProviderAzure,
		ScopeKind:   models.CloudScopeTenant,
		ScopeID:     tid,
		AuthRef:     s.cfg.AuthRef(),
		Status:      models.CloudConnectorActive,
		VerifiedAt:  &now,
		CreatedBy:   actor,
	}
	if err := tenantConn.SetAzureTenantAttrs(models.AzureTenantAttrs{
		TenantID:                 tid,
		AppID:                    s.cfg.ClientID,
		ServicePrincipalObjectID: sp.ID,
		ServicePrincipalName:     sp.DisplayName,
		GraphPermissions:         perms,
		GraphVerifiedAt:          &now,
		SubscriptionsVisible:     len(subs),
		ProvisionedVia:           models.AzureProvisionedViaAdminConsent,
		ProvisionedBy:            actor,
	}); err != nil {
		return nil, err
	}
	storedTenant, tenantCreated, err := s.connectors.Upsert(tenantConn)
	if err != nil {
		return nil, fmt.Errorf("record tenant connector: %w", err)
	}

	// 7. Reader on each subscription, as the administrator.
	results := make([]AzureSubscriptionResult, len(selected))
	forEachLimited(len(selected), azureAssignConcurrency, func(i int) {
		sub := selected[i]
		results[i] = AzureSubscriptionResult{
			SubscriptionID: sub.SubscriptionID,
			DisplayName:    sub.DisplayName,
			State:          sub.State,
			Reader:         s.ensureReader(ctx, sess.AccessToken, sub, sp.ID),
		}
	})

	// 8. Prove each assignment with AuthSec's OWN token, waiting a bounded
	//    time for Azure to apply new ones.
	s.verifyReaderAccess(ctx, tid, results)

	// 9. Record each subscription connector.
	keep := map[string]bool{}
	for i := range results {
		keep[results[i].SubscriptionID] = true
		conn, err := s.recordSubscription(workspaceID, tid, sp.ID, actor, &results[i])
		if err != nil {
			results[i].Error = "could not record the subscription: " + err.Error()
			continue
		}
		results[i].ConnectorID = &conn.ID
		results[i].Status = conn.Status
	}
	// A tenant that read with the customer's own app now reads with
	// AuthSec's: its other subscriptions move off the old credentials, and
	// the customer's secret is no longer kept.
	var warnings []string
	if boundHere && usesCustomApp(existingTenant) {
		warnings = append(warnings, "this tenant was connected with your own app; it now reads with the AuthSec app, "+
			"and the client secret AuthSec stored for your app has been removed")
		s.destroyCustomAppSecret(workspaceID, tid)
	}
	if n := s.retargetTenantSubscriptions(workspaceID, tid, s.cfg.AuthRef(), "the AuthSec app", keep); n > 0 {
		warnings = append(warnings, fmt.Sprintf("%d subscription(s) connected earlier were not selected now and cannot be "+
			"read by the AuthSec app; connect the tenant again and select them", n))
	}

	// 10. Discover identities, grants and resources in the background: the
	//     directory, then every subscription AuthSec can now read. A large
	//     tenant takes longer than one request may.
	var targets []azureScanTarget
	for _, r := range results {
		if r.ConnectorID != nil && r.Reader.Verified {
			targets = append(targets, azureScanTarget{ConnectorID: *r.ConnectorID, SubscriptionID: r.SubscriptionID})
		}
	}
	discovery := s.startDiscovery(workspaceID, tid, &storedTenant.ID, targets, models.AzureTriggerConnect)

	// The administrator's token has done its job. Best-effort: the TTL
	// removes the key regardless.
	if err := s.redis.Del(context.WithoutCancel(ctx), azureOAuthSessionKey(sessionID)).Err(); err != nil {
		log.Printf("[azure] could not consume the sign-in session after connect (it will expire on its own): %v", err)
	}

	status := models.CloudConnectorActive
	for _, r := range results {
		if !r.Reader.Verified {
			status = "partial"
		}
	}
	return &AzureConnectResult{
		Tenant:           storedTenant,
		TenantCreated:    tenantCreated,
		GraphPermissions: perms,
		Subscriptions:    results,
		Status:           status,
		Discovery:        discovery,
		Warnings:         warnings,
	}, nil
}

func normalizeSubscriptionIDs(ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, id := range ids {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if !azure.IsGUID(id) {
			return nil, fmt.Errorf("%w: %q is not a subscription id", azure.ErrInvalidInput, id)
		}
		out[id] = true
	}
	return out, nil
}

func selectSubscriptions(visible []azure.Subscription, wanted map[string]bool) ([]azure.Subscription, error) {
	if len(wanted) == 0 {
		return visible, nil
	}
	out := make([]azure.Subscription, 0, len(wanted))
	found := map[string]bool{}
	for _, sub := range visible {
		if wanted[sub.SubscriptionID] {
			out = append(out, sub)
			found[sub.SubscriptionID] = true
		}
	}
	for id := range wanted {
		if !found[id] {
			return nil, fmt.Errorf("%w: subscription %s is not visible to the signed-in account in this tenant", azure.ErrInvalidInput, id)
		}
	}
	return out, nil
}

/* ------------------------------ connect-custom ------------------------------- */

// azureCustomAppVaultPath is where a workspace's customer-provided Azure app
// credentials live, keyed by tenant id.
func azureCustomAppVaultPath(workspaceID uuid.UUID, tenantID string) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/cloud-discovery/azure/%s",
		workspaceID.String(), tenantID)
}

// ConnectCustom onboards a tenant using the customer's own Entra app
// registration: client_credentials with their client_id/client_secret/tenant_id.
// No browser OAuth flow is involved, and AuthSec assigns nothing: the customer
// gives their app Reader on each subscription it should read.
//
// Order matters for the secret: it is stored only once every read it enables
// has been proven, so a failed connect leaves no secret behind and a reconnect
// never replaces a working secret with one that does not work.
func (s *AzureOnboardingService) ConnectCustom(parent context.Context, workspaceID uuid.UUID, actor string, customCfg azure.AppConfig, tenantID string) (*AzureConnectResult, error) {
	ctx, cancel := context.WithTimeout(parent, azureConnectBudget)
	defer cancel()

	if s.vault == nil {
		return nil, ErrAzureVaultNotConfigured
	}

	// 1. A Graph token with the customer's credentials: proves the tenant id,
	//    the client id and the secret together.
	graphToken, err := s.api.AppToken(ctx, customCfg, tenantID, azure.ScopeGraphApp)
	if err != nil {
		logAzureError("custom app: graph app token", err)
		return nil, customAppError(err)
	}

	// 2. The app's service principal in the tenant.
	sp, err := s.api.FindServicePrincipal(ctx, graphToken, customCfg.ClientID, false)
	if err != nil {
		logAzureError("custom app: find service principal", err)
		return nil, customAppError(err)
	}
	if sp.AccountEnabled != nil && !*sp.AccountEnabled {
		return nil, fmt.Errorf("%w: its service principal is disabled", ErrAzureCustomAppNotInTenant)
	}

	// 3. Its Microsoft Graph application permissions.
	perms, missing, granted, err := s.verifyGraphPermissions(ctx, graphToken, sp.ID)
	if err != nil {
		return nil, customAppError(err)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrAzureCustomPermissionsMissing, strings.Join(missing, ", "))
	}
	var warnings []string
	if w := writeCapableGraphRoles(granted); len(w) > 0 {
		warnings = append(warnings, "your app holds Microsoft Graph application permissions that can change data: "+
			strings.Join(w, ", ")+". AuthSec only reads; consider removing them from the app")
	}

	// 4. The subscriptions the app can read. An app-only token lists only the
	//    subscriptions where the app holds a role, so one it cannot read is
	//    simply absent.
	armToken, err := s.api.AppToken(ctx, customCfg, tenantID, azure.ScopeARMApp)
	if err != nil {
		logAzureError("custom app: arm app token", err)
		return nil, customAppError(err)
	}
	allSubs, err := s.api.ListSubscriptions(ctx, armToken)
	if err != nil {
		logAzureError("custom app: list subscriptions", err)
		return nil, customAppError(err)
	}
	var subs []azure.Subscription
	for _, sub := range allSubs {
		if sub.TenantID != "" && !strings.EqualFold(sub.TenantID, tenantID) {
			continue
		}
		if !azure.IsGUID(sub.SubscriptionID) {
			continue
		}
		sub.SubscriptionID = strings.ToLower(sub.SubscriptionID)
		subs = append(subs, sub)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].SubscriptionID < subs[j].SubscriptionID })
	if len(subs) == 0 {
		warnings = append(warnings, "your app cannot read any Azure subscription in this tenant: assign it the Reader role "+
			"on each subscription AuthSec should read, then verify the connection. Microsoft Entra ID is read meanwhile")
	}

	// 5. Prove each one is readable. Nothing is assigned here, so a disabled
	//    subscription that is still readable is read like any other.
	results := make([]AzureSubscriptionResult, len(subs))
	var privileged []string
	for i, sub := range subs {
		results[i] = AzureSubscriptionResult{SubscriptionID: sub.SubscriptionID, DisplayName: sub.DisplayName, State: sub.State}
		_, readErr := s.api.GetSubscription(ctx, armToken, sub.SubscriptionID)
		checkedAt := time.Now()
		if readErr != nil {
			results[i].Reader = models.AzureReaderAssignment{Status: models.AzureReaderDenied, CheckedAt: &checkedAt, Error: readErr.Error()}
			continue
		}
		results[i].Reader = models.AzureReaderAssignment{
			Status: models.AzureReaderExisting, CheckedAt: &checkedAt, Verified: true, VerifiedAt: &checkedAt,
		}
		// Reader is all AuthSec needs; say so when the app holds more.
		if as, err := s.api.ListRoleAssignmentsForPrincipal(ctx, armToken, sub.SubscriptionID, sp.ID); err == nil {
			if roles := privilegedAzureRoles(as); len(roles) > 0 {
				privileged = append(privileged, firstNonEmpty(sub.DisplayName, sub.SubscriptionID)+" ("+strings.Join(roles, ", ")+")")
			}
		}
	}
	if len(privileged) > 0 {
		warnings = append(warnings, "your app holds Azure roles that can change resources or grant access, beyond the Reader "+
			"AuthSec needs: "+strings.Join(privileged, "; ")+". Consider giving it Reader only")
	}

	// 6. Everything the secret is for has been proven: store it. The secret
	//    never touches Postgres; auth_ref is the non-secret handle.
	existing, _ := s.connectors.GetByScope(workspaceID, models.CloudProviderAzure, tenantID)
	vaultPath := azureCustomAppVaultPath(workspaceID, tenantID)
	if err := s.vault.WriteSecret(vaultPath, map[string]interface{}{
		"client_id":     customCfg.ClientID,
		"client_secret": customCfg.ClientSecret,
		"tenant_id":     tenantID,
	}); err != nil {
		log.Printf("[azure] custom app: could not store the credentials of tenant %s: %v", tenantID, err)
		return nil, ErrAzureCustomCredentialsStore
	}

	// 7. The tenant connector.
	authRef := azure.AppConfig{ClientID: customCfg.ClientID}.AuthRef()
	now := time.Now()
	tenantConn := &models.CloudConnector{
		WorkspaceID: workspaceID,
		Provider:    models.CloudProviderAzure,
		ScopeKind:   models.CloudScopeTenant,
		ScopeID:     tenantID,
		AuthRef:     authRef,
		Status:      models.CloudConnectorActive,
		VerifiedAt:  &now,
		CreatedBy:   actor,
	}
	if err := tenantConn.SetAzureTenantAttrs(models.AzureTenantAttrs{
		TenantID:                 tenantID,
		AppID:                    customCfg.ClientID,
		ServicePrincipalObjectID: sp.ID,
		ServicePrincipalName:     sp.DisplayName,
		GraphPermissions:         perms,
		GraphVerifiedAt:          &now,
		SubscriptionsVisible:     len(subs),
		ProvisionedVia:           models.AzureProvisionedViaClientCredentials,
		ProvisionedBy:            actor,
	}); err != nil {
		return nil, err
	}
	storedTenant, tenantCreated, err := s.connectors.Upsert(tenantConn)
	if err != nil {
		// A tenant connected for the first time leaves nothing behind.
		if existing == nil {
			s.destroyCustomAppSecret(workspaceID, tenantID)
		}
		return nil, fmt.Errorf("record tenant connector: %w", err)
	}
	if existing != nil && existing.Status != models.CloudConnectorRevoked && !usesCustomApp(existing) {
		warnings = append(warnings, "this tenant was connected with the AuthSec app; it now reads with your app")
	}

	// 8. Each subscription connector, and the tenant's other subscriptions
	//    moved off the credentials they read with before.
	keep := map[string]bool{}
	for i := range results {
		keep[results[i].SubscriptionID] = true
		conn, err := s.recordSubscriptionWith(workspaceID, tenantID, sp.ID, actor, authRef, models.AzureProvisionedViaClientCredentials, &results[i])
		if err != nil {
			results[i].Error = "could not record the subscription: " + err.Error()
			continue
		}
		results[i].ConnectorID = &conn.ID
		results[i].Status = conn.Status
	}
	if n := s.retargetTenantSubscriptions(workspaceID, tenantID, authRef, "your app", keep); n > 0 {
		warnings = append(warnings, fmt.Sprintf("%d subscription(s) connected earlier cannot be read by your app; "+
			"assign it Reader there and verify them", n))
	}

	// 9. Discovery.
	var targets []azureScanTarget
	for _, r := range results {
		if r.ConnectorID != nil && r.Reader.Verified {
			targets = append(targets, azureScanTarget{ConnectorID: *r.ConnectorID, SubscriptionID: r.SubscriptionID})
		}
	}
	discovery := s.startDiscovery(workspaceID, tenantID, &storedTenant.ID, targets, models.AzureTriggerConnect)

	status := models.CloudConnectorActive
	for _, r := range results {
		if !r.Reader.Verified {
			status = "partial"
		}
	}
	return &AzureConnectResult{
		Tenant:           storedTenant,
		TenantCreated:    tenantCreated,
		GraphPermissions: perms,
		Subscriptions:    results,
		Status:           status,
		Discovery:        discovery,
		Warnings:         warnings,
	}, nil
}

/* --------------------------- graph: service principal ------------------------- */

func (s *AzureOnboardingService) findAuthSecServicePrincipal(ctx context.Context, graphToken string) (*azure.ServicePrincipal, error) {
	sp, err := s.api.FindServicePrincipal(ctx, graphToken, s.cfg.ClientID, false)
	if err != nil {
		logAzureError("find authsec service principal", err)
		return nil, err
	}
	// Optional. appId is globally unique, so this cannot catch an impostor; it
	// catches a deployment whose AZURE_AUTHSEC_TENANT_ID, when set, does not
	// match the app it names.
	if s.cfg.HomeTenantID != "" && !strings.EqualFold(sp.AppOwnerOrganizationID, s.cfg.HomeTenantID) {
		return nil, fmt.Errorf("%w: the application's owning tenant does not match AZURE_AUTHSEC_TENANT_ID", azure.ErrCredentialRejected)
	}
	if sp.AccountEnabled != nil && !*sp.AccountEnabled {
		return nil, fmt.Errorf("%w: the AuthSec enterprise application is disabled in this tenant", azure.ErrAppNotInTenant)
	}
	return sp, nil
}

// findServicePrincipal locates the service principal for any AppConfig's
// client id. Unlike findAuthSecServicePrincipal it skips the HomeTenantID
// check, which applies only to the managed app.
func (s *AzureOnboardingService) findServicePrincipal(ctx context.Context, graphToken string, cfg azure.AppConfig) (*azure.ServicePrincipal, error) {
	sp, err := s.api.FindServicePrincipal(ctx, graphToken, cfg.ClientID, false)
	if err != nil {
		logAzureError("find service principal", err)
		return nil, err
	}
	if cfg.HomeTenantID != "" && !strings.EqualFold(sp.AppOwnerOrganizationID, cfg.HomeTenantID) {
		return nil, fmt.Errorf("%w: the application's owning tenant does not match the configured tenant", azure.ErrCredentialRejected)
	}
	if sp.AccountEnabled != nil && !*sp.AccountEnabled {
		return nil, fmt.Errorf("%w: the enterprise application is disabled in this tenant", azure.ErrAppNotInTenant)
	}
	return sp, nil
}

// verifyGraphPermissions reports every required Graph application permission
// as granted (an app role assignment exists) and usable (a minimal read it
// allows succeeded). missing lists the ones not granted at all -- the only case
// that fails onboarding; a granted-but-unusable permission is recorded, not
// fatal, because the usual cause (a licence, a just-issued token) is not fixed
// by consenting again.
//
// granted is every Microsoft Graph application permission the principal holds
// (by value), required or not.
func (s *AzureOnboardingService) verifyGraphPermissions(ctx context.Context, graphToken, spID string) (perms []models.AzureGraphPermission, missing []string, granted map[string]bool, err error) {
	graphSP, err := s.api.FindServicePrincipal(ctx, graphToken, azure.GraphAppID, true)
	if err != nil {
		logAzureError("find microsoft graph service principal", err)
		return nil, nil, nil, err
	}
	roleValue := map[string]string{}
	for _, r := range graphSP.AppRoles {
		roleValue[strings.ToLower(r.ID)] = r.Value
	}
	assignments, err := s.api.ListAppRoleAssignments(ctx, graphToken, spID)
	if err != nil {
		logAzureError("list app role assignments", err)
		return nil, nil, nil, err
	}
	granted = map[string]bool{}
	for _, a := range assignments {
		if strings.EqualFold(a.ResourceID, graphSP.ID) {
			if v := roleValue[strings.ToLower(a.AppRoleID)]; v != "" {
				granted[v] = true
			}
		}
	}

	perms = make([]models.AzureGraphPermission, 0, len(azure.RequiredGraphAppRoles)+len(azure.OptionalGraphAppRoles))
	check := func(name string, optional bool) {
		p := models.AzureGraphPermission{Name: name, Granted: granted[name], Optional: optional}
		if !p.Granted {
			p.State = models.AzureGraphPermissionNotGranted
			if !optional {
				missing = append(missing, name)
			}
			perms = append(perms, p)
			return
		}
		p.State, p.Detail = s.probeGraph(ctx, graphToken, name)
		perms = append(perms, p)
	}
	for _, name := range azure.RequiredGraphAppRoles {
		check(name, false)
	}
	// An optional permission not granted is recorded, never fatal: the tenant
	// consented before AuthSec asked for it, and consenting again adds it.
	for _, name := range azure.OptionalGraphAppRoles {
		check(name, true)
	}
	return perms, missing, granted, nil
}

func (s *AzureOnboardingService) probeGraph(ctx context.Context, graphToken, permission string) (string, string) {
	path, ok := azure.GraphProbePaths[permission]
	if !ok {
		return models.AzureGraphPermissionUnknown, ""
	}
	err := s.api.ProbeGraph(ctx, graphToken, path)
	if err == nil {
		return models.AzureGraphPermissionUsable, ""
	}
	var ae *azure.APIError
	if errors.As(err, &ae) && ae.Status == 403 {
		if strings.Contains(strings.ToLower(ae.Code+" "+ae.Message), "premium") {
			return models.AzureGraphPermissionLicense, ae.Error()
		}
		// Granted (only granted permissions are probed) yet refused: for an
		// API that also needs a licence, the licence is what is missing.
		if lic, ok := azure.LicensedGraphPermissions[permission]; ok {
			return models.AzureGraphPermissionLicense, "needs a " + lic + " licence in this tenant: " + ae.Error()
		}
		return models.AzureGraphPermissionDenied, ae.Error()
	}
	return models.AzureGraphPermissionUnknown, err.Error()
}

// authorizeBinding decides whether the signed-in person may attach this tenant
// to an AuthSec workspace.
//
// The consent redirect's tenant= parameter passes through the browser, and a
// tenant that already consented AuthSec for one customer workspace would
// otherwise be bindable to ANY workspace by anyone who could reach the
// callback with that tenant's id. The tenant is therefore taken from the
// signed-in token, and the person must be a member of it -- never a guest --
// holding a directory role that can grant tenant-wide consent to Graph
// application permissions. Once the tenant is connected to this workspace, a
// member without such a role (typically a subscription Owner adding Reader to
// more subscriptions) may re-run the flow.
func (s *AzureOnboardingService) authorizeBinding(ctx context.Context, graphToken, userObjectID string, boundHere bool) error {
	user, err := s.api.GetUser(ctx, graphToken, userObjectID)
	if err != nil {
		logAzureError("read signed-in user", err)
		return fmt.Errorf("%w: the signed-in account could not be read from the directory", azure.ErrNotAuthorizedToBind)
	}
	if !strings.EqualFold(user.UserType, "Member") {
		return fmt.Errorf("%w: guest accounts cannot connect a tenant; sign in with an account that belongs to it", azure.ErrNotAuthorizedToBind)
	}
	if user.AccountEnabled != nil && !*user.AccountEnabled {
		return fmt.Errorf("%w: the signed-in account is disabled", azure.ErrNotAuthorizedToBind)
	}
	if boundHere {
		return nil
	}
	roles, err := s.api.UserDirectoryRoleTemplateIDs(ctx, graphToken, userObjectID)
	if err != nil {
		logAzureError("read signed-in user's directory roles", err)
		return fmt.Errorf("%w: the signed-in account's Microsoft Entra roles could not be read", azure.ErrNotAuthorizedToBind)
	}
	for _, r := range roles {
		if _, ok := azure.BindingDirectoryRoleTemplateIDs[r]; ok {
			return nil
		}
	}
	return fmt.Errorf("%w: connecting a tenant for the first time requires an active Global Administrator or Privileged Role Administrator role", azure.ErrNotAuthorizedToBind)
}

/* ------------------------------ rbac: reader ---------------------------------- */

// ensureReader makes sure the AuthSec service principal holds Reader on the
// subscription, creating the assignment with the administrator's token when it
// is absent. Idempotent: an existing assignment -- direct, inherited, or one
// the deterministic name collides with -- is success, never a second write.
func (s *AzureOnboardingService) ensureReader(ctx context.Context, adminToken string, sub azure.Subscription, principalID string) models.AzureReaderAssignment {
	now := time.Now()
	scope := azure.SubscriptionScope(sub.SubscriptionID)
	out := models.AzureReaderAssignment{CheckedAt: &now, Scope: scope}

	if !azureSubscriptionAssignable(sub.State) {
		out.Status = models.AzureReaderSkipped
		out.Error = fmt.Sprintf("the subscription is %s and does not accept role assignments", sub.State)
		return out
	}

	// An existing Reader for the principal at, or above, the subscription.
	// A failure to list is not fatal: the PUT below decides.
	if existing, err := s.api.ListRoleAssignmentsForPrincipal(ctx, adminToken, sub.SubscriptionID, principalID); err == nil {
		for _, ra := range existing {
			if !azure.IsReader(ra) || !strings.EqualFold(ra.Properties.PrincipalID, principalID) {
				continue
			}
			raScope := strings.ToLower(ra.Properties.Scope)
			switch {
			case raScope == "":
				continue
			case raScope == scope:
				out.Status, out.AssignmentID = models.AzureReaderExisting, ra.ID
				return out
			case !strings.HasPrefix(raScope, scope+"/"):
				// Not below the subscription, so above it: a management group
				// or the tenant root. Inherited Reader covers the subscription.
				out.Status, out.AssignmentID, out.Scope = models.AzureReaderInherited, ra.ID, ra.Properties.Scope
				return out
			}
		}
	}

	name := azure.RoleAssignmentName(scope, principalID, azure.ReaderRoleDefinitionID)
	roleDef := azure.ReaderRoleDefinitionResourceID(scope)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		id, err := s.api.CreateRoleAssignment(ctx, adminToken, scope, name, roleDef, principalID)
		if err == nil {
			out.Status, out.AssignmentID = models.AzureReaderCreated, id
			return out
		}
		lastErr = err
		if azure.IsAPICode(err, "RoleAssignmentExists") {
			out.Status = models.AzureReaderExisting
			return out
		}
		if errors.Is(err, azure.ErrARMForbidden) {
			out.Status = models.AzureReaderDenied
			out.Error = "the signed-in account may not create role assignments on this subscription " +
				"(it needs Owner, User Access Administrator or Role Based Access Control Administrator)"
			return out
		}
		// Only PrincipalNotFound is worth repeating: a service principal created
		// seconds ago by admin consent may not have replicated to ARM yet,
		// despite principalType. Every other refusal is final.
		if !azure.IsAPICode(err, "PrincipalNotFound") || attempt == 3 {
			break
		}
		if sleepCtx(ctx, time.Duration(attempt)*5*time.Second) != nil {
			break
		}
	}
	logAzureError("create reader assignment", lastErr)
	out.Status = models.AzureReaderFailed
	out.Error = lastErr.Error()
	return out
}

func readerInPlace(status string) bool {
	switch status {
	case models.AzureReaderCreated, models.AzureReaderExisting, models.AzureReaderInherited:
		return true
	}
	return false
}

// verifyReaderAccess proves, with AuthSec's own app-only ARM token, that the
// service principal can read each subscription whose Reader is in place. Azure
// applies a new assignment within minutes, not instantly, so this polls within
// a bounded budget and leaves the rest marked unverified; Verify finishes them
// later without needing the administrator again.
func (s *AzureOnboardingService) verifyReaderAccess(ctx context.Context, tenantID string, results []AzureSubscriptionResult) {
	pending := map[int]bool{}
	for i := range results {
		if readerInPlace(results[i].Reader.Status) {
			pending[i] = true
		}
	}
	if len(pending) == 0 {
		return
	}

	armToken, err := s.api.AppToken(ctx, s.cfg, tenantID, azure.ScopeARMApp)
	if err != nil {
		logAzureError("arm app token", err)
		for i := range pending {
			results[i].Reader.Error = "AuthSec could not obtain its own Azure Resource Manager token: " + err.Error()
		}
		return
	}

	budget := azureVerifyBudget
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl) - azureInventoryReserve; left < budget {
			budget = left
		}
	}
	deadline := time.Now().Add(budget)

	for attempt := 1; len(pending) > 0; attempt++ {
		var mu sync.Mutex
		idx := make([]int, 0, len(pending))
		for i := range pending {
			idx = append(idx, i)
		}
		forEachLimited(len(idx), azureAssignConcurrency, func(k int) {
			i := idx[k]
			_, err := s.api.GetSubscription(ctx, armToken, results[i].SubscriptionID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				now := time.Now()
				results[i].Reader.Verified = true
				results[i].Reader.VerifiedAt = &now
				results[i].Reader.Error = ""
				delete(pending, i)
				return
			}
			if errors.Is(err, azure.ErrARMForbidden) || azure.APIStatus(err) == 404 {
				results[i].Reader.Error = azure.ErrRBACPending.Error()
				return
			}
			results[i].Reader.Error = err.Error()
		})
		if len(pending) == 0 {
			return
		}
		wait := retryBackoff(3*time.Second, attempt)
		if time.Now().Add(wait).After(deadline) {
			return
		}
		if sleepCtx(ctx, wait) != nil {
			return
		}
	}
}

// recordSubscription upserts the subscription's connector row from its result.
func (s *AzureOnboardingService) recordSubscription(workspaceID uuid.UUID, tenantID, principalID, actor string, r *AzureSubscriptionResult) (*models.CloudConnector, error) {
	return s.recordSubscriptionWith(workspaceID, tenantID, principalID, actor, s.cfg.AuthRef(), models.AzureProvisionedViaAdminConsent, r)
}

func (s *AzureOnboardingService) recordSubscriptionWith(workspaceID uuid.UUID, tenantID, principalID, actor, authRef, provisionedVia string, r *AzureSubscriptionResult) (*models.CloudConnector, error) {
	parent := tenantID
	conn := &models.CloudConnector{
		WorkspaceID:   workspaceID,
		Provider:      models.CloudProviderAzure,
		ScopeKind:     models.CloudScopeSubscription,
		ScopeID:       r.SubscriptionID,
		ParentScopeID: &parent,
		AuthRef:       authRef,
		CreatedBy:     actor,
	}
	if err := conn.SetAzureSubscriptionAttrs(models.AzureSubscriptionAttrs{
		TenantID:                 tenantID,
		DisplayName:              r.DisplayName,
		State:                    r.State,
		ServicePrincipalObjectID: principalID,
		Reader:                   r.Reader,
		ProvisionedVia:           provisionedVia,
		ProvisionedBy:            actor,
	}); err != nil {
		return nil, err
	}

	if r.Reader.Verified {
		conn.Status = models.CloudConnectorActive
		conn.VerifiedAt = r.Reader.VerifiedAt
	} else {
		conn.Status = models.CloudConnectorError
		conn.LastError, conn.LastErrorCode = azureReaderFailure(r.Reader)
		// Keep the last proof of access: a subscription that worked yesterday
		// and is unreadable now is "broken since", not "never worked".
		if prev, err := s.connectors.GetByScope(workspaceID, models.CloudProviderAzure, r.SubscriptionID); err == nil {
			conn.VerifiedAt = prev.VerifiedAt
		}
	}
	stored, _, err := s.connectors.Upsert(conn)
	return stored, err
}

// azureReaderFailure is the (last_error, last_error_code) of a subscription
// AuthSec cannot read yet.
func azureReaderFailure(r models.AzureReaderAssignment) (string, string) {
	switch r.Status {
	case models.AzureReaderDenied:
		return "Reader could not be assigned: " + r.Error, ConnErrAuthRefused
	case models.AzureReaderSkipped:
		return "Reader was not assigned: " + r.Error, ConnErrScopeInvalid
	case models.AzureReaderFailed:
		return "Reader could not be assigned: " + r.Error, ""
	}
	if r.Error == "" || r.Error == azure.ErrRBACPending.Error() {
		return "Reader is assigned but Azure has not applied it yet; verify this subscription again in a few minutes",
			ConnErrAzureRBACPending
	}
	return "Reader is assigned but AuthSec could not read the subscription: " + r.Error, ""
}

/* ---------------------------------- verify ----------------------------------- */

// AzureVerifyResult is the outcome of Verify.
type AzureVerifyResult struct {
	Connector *models.CloudConnector `json:"connector"`
	// Discovery is set when the connection was proven and a background
	// discovery pass was started (or was already running).
	Discovery string `json:"discovery,omitempty"`
}

// Verify re-proves a connector with AuthSec's own credentials alone -- no
// customer sign-in -- and, when it holds, starts a fresh discovery pass. A
// tenant connector re-checks the service principal and its Graph permissions,
// then rediscovers the directory and every subscription it can read; a
// subscription connector re-checks Reader access, then rediscovers that
// subscription. It cannot CREATE a missing Reader assignment: that needs an
// administrator, which means running the onboarding flow again.
func (s *AzureOnboardingService) Verify(parent context.Context, workspaceID, connectorID uuid.UUID) (*AzureVerifyResult, error) {
	return s.verify(parent, workspaceID, connectorID, models.AzureTriggerVerify)
}

// resolveAppConfig returns the AppConfig for the given connector. For the
// managed app (AuthRef matches s.cfg), it returns s.cfg. For a custom app, it
// reads the customer's credentials from Vault.
func (s *AzureOnboardingService) resolveAppConfig(c *models.CloudConnector) (azure.AppConfig, error) {
	if s.cfg.Configured() && c.AuthRef == s.cfg.AuthRef() {
		return s.cfg, nil
	}
	if s.vault == nil {
		return azure.AppConfig{}, ErrAzureVaultNotConfigured
	}
	tenantID := c.ScopeID
	if c.ScopeKind == models.CloudScopeSubscription && c.ParentScopeID != nil {
		tenantID = *c.ParentScopeID
	}
	vaultPath := azureCustomAppVaultPath(c.WorkspaceID, tenantID)
	secret, err := s.vault.ReadSecret(vaultPath)
	if err != nil {
		return azure.AppConfig{}, fmt.Errorf("read custom app credentials: %w", err)
	}
	clientID, _ := secret["client_id"].(string)
	clientSecret, _ := secret["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		return azure.AppConfig{}, fmt.Errorf("%w: custom app credentials in vault are incomplete", azure.ErrNotConfigured)
	}
	return azure.AppConfig{ClientID: clientID, ClientSecret: clientSecret}, nil
}

// verify is Verify with the trigger the passes it starts are recorded under.
func (s *AzureOnboardingService) verify(parent context.Context, workspaceID, connectorID uuid.UUID, trigger string) (*AzureVerifyResult, error) {
	ctx, cancel := context.WithTimeout(parent, azureConnectBudget)
	defer cancel()

	c, err := s.azureConnector(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}

	// Revoked first: a revoked connector has no credentials left to resolve.
	if c.Status == models.CloudConnectorRevoked {
		return nil, ErrAzureConnectorRevoked
	}
	cfg, err := s.resolveAppConfig(c)
	if err != nil {
		return nil, err
	}

	if c.ScopeKind == models.CloudScopeTenant {
		return s.verifyTenant(ctx, c, cfg, trigger)
	}
	return s.verifySubscription(ctx, c, cfg, trigger)
}

func (s *AzureOnboardingService) verifyTenant(ctx context.Context, c *models.CloudConnector, cfg azure.AppConfig, trigger string) (*AzureVerifyResult, error) {
	fail := func(err error) (*AzureVerifyResult, error) {
		// A tenant read with the customer's own app: its failures are theirs.
		if usesCustomApp(c) {
			err = customAppError(err)
		}
		// A passing failure (throttling, Microsoft's 5xx, a timeout) proves
		// nothing about the connection: it stays as it is, so scheduled
		// discovery keeps trying, and the caller is told.
		if azureTransient(err) {
			return nil, err
		}
		stored, merr := s.connectors.MarkError(c.WorkspaceID, c.ID, err.Error(), ClassifyConnectorError(err))
		if merr != nil {
			return nil, merr
		}
		return &AzureVerifyResult{Connector: stored}, nil
	}

	graphToken, err := s.api.AppToken(ctx, cfg, c.ScopeID, azure.ScopeGraphApp)
	if err != nil {
		logAzureError("graph app token", err)
		return fail(err)
	}
	sp, err := s.findServicePrincipal(ctx, graphToken, cfg)
	if err != nil {
		return fail(err)
	}
	perms, missing, _, err := s.verifyGraphPermissions(ctx, graphToken, sp.ID)
	if err != nil {
		return fail(err)
	}

	attrs := c.AzureTenantAttrs()
	attrs.ServicePrincipalObjectID = sp.ID
	attrs.ServicePrincipalName = sp.DisplayName
	attrs.GraphPermissions = perms
	if len(missing) > 0 {
		if err := c.SetAzureTenantAttrs(attrs); err == nil {
			// Without cancel: the verify budget may be spent, and the write is
			// best effort either way.
			_ = tenancy.InWorkspace(context.WithoutCancel(ctx), s.db, c.WorkspaceID, func(tx *gorm.DB) error {
				return tx.Model(&models.CloudConnector{}).
					Where("workspace_id = ? AND id = ?", c.WorkspaceID, c.ID).
					Update("attrs", c.Attrs).Error
			})
		}
		return fail(fmt.Errorf("%w: %s", azure.ErrGraphPermissionsMissing, strings.Join(missing, ", ")))
	}
	now := time.Now()
	attrs.GraphVerifiedAt = &now
	if err := c.SetAzureTenantAttrs(attrs); err != nil {
		return nil, err
	}
	stored, err := s.connectors.MarkVerified(c.WorkspaceID, c.ID, c.Attrs)
	if err != nil {
		return nil, err
	}
	discovery := s.startDiscovery(c.WorkspaceID, c.ScopeID, &c.ID, s.readableSubscriptions(c.WorkspaceID, c.ScopeID), trigger)
	return &AzureVerifyResult{Connector: stored, Discovery: discovery}, nil
}

// readableSubscriptions lists the tenant's subscription connectors whose
// Reader access was last proven.
func (s *AzureOnboardingService) readableSubscriptions(workspaceID uuid.UUID, tenantID string) []azureScanTarget {
	all, err := s.connectors.List(workspaceID, models.CloudProviderAzure)
	if err != nil {
		return nil
	}
	var out []azureScanTarget
	for _, c := range all {
		if c.ScopeKind == models.CloudScopeSubscription && c.Status == models.CloudConnectorActive &&
			c.ParentScopeID != nil && strings.EqualFold(*c.ParentScopeID, tenantID) {
			out = append(out, azureScanTarget{ConnectorID: c.ID, SubscriptionID: c.ScopeID})
		}
	}
	return out
}

func (s *AzureOnboardingService) verifySubscription(ctx context.Context, c *models.CloudConnector, cfg azure.AppConfig, trigger string) (*AzureVerifyResult, error) {
	tenantID := ""
	if c.ParentScopeID != nil {
		tenantID = *c.ParentScopeID
	}
	if !azure.IsGUID(tenantID) {
		return nil, fmt.Errorf("%w: the subscription connector has no tenant", azure.ErrInvalidInput)
	}
	attrs := c.AzureSubscriptionAttrs()
	now := time.Now()
	attrs.Reader.CheckedAt = &now

	armToken, err := s.api.AppToken(ctx, cfg, tenantID, azure.ScopeARMApp)
	if err == nil {
		_, err = s.api.GetSubscription(ctx, armToken, c.ScopeID)
	}
	if err != nil {
		logAzureError("verify subscription", err)
		attrs.Reader.Verified = false
		reason, code := err.Error(), ClassifyConnectorError(err)
		if errors.Is(err, azure.ErrARMForbidden) || azure.APIStatus(err) == 404 {
			attrs.Reader.Error = azure.ErrRBACPending.Error()
			reason = "AuthSec's service principal cannot read this subscription: the Reader assignment is missing " +
				"or has not taken effect yet. If it was removed, connect the tenant again to restore it."
			code = ConnErrAzureRBACPending
		} else {
			attrs.Reader.Error = err.Error()
		}
		if serr := c.SetAzureSubscriptionAttrs(attrs); serr == nil {
			// Without cancel: the failure being recorded may be the verify
			// budget running out.
			_ = tenancy.InWorkspace(context.WithoutCancel(ctx), s.db, c.WorkspaceID, func(tx *gorm.DB) error {
				return tx.Model(&models.CloudConnector{}).
					Where("workspace_id = ? AND id = ?", c.WorkspaceID, c.ID).
					Update("attrs", c.Attrs).Error
			})
		}
		stored, merr := s.connectors.MarkError(c.WorkspaceID, c.ID, reason, code)
		if merr != nil {
			return nil, merr
		}
		return &AzureVerifyResult{Connector: stored}, nil
	}

	attrs.Reader.Verified = true
	attrs.Reader.VerifiedAt = &now
	attrs.Reader.Error = ""
	if err := c.SetAzureSubscriptionAttrs(attrs); err != nil {
		return nil, err
	}
	if _, err := s.connectors.MarkVerified(c.WorkspaceID, c.ID, c.Attrs); err != nil {
		return nil, err
	}
	discovery := s.startDiscovery(c.WorkspaceID, tenantID, nil,
		[]azureScanTarget{{ConnectorID: c.ID, SubscriptionID: c.ScopeID}}, trigger)
	stored, err := s.connectors.Get(c.WorkspaceID, c.ID)
	if err != nil {
		return nil, err
	}
	return &AzureVerifyResult{Connector: stored, Discovery: discovery}, nil
}

/* ---------------------------------- revoke ----------------------------------- */

// Revoke disconnects a connector. Revoking a tenant also revokes its
// subscriptions, since they share its service principal. Nothing AuthSec found
// is deleted, matching CloudConnectorRepository.Revoke.
//
// This does NOT remove anything in the customer's tenant: AuthSec holds no
// right to delete its own Reader assignments or service principal. The
// customer removes access by deleting the AuthSec enterprise application,
// which also removes its role assignments.
func (s *AzureOnboardingService) Revoke(workspaceID, connectorID uuid.UUID) ([]models.CloudConnector, error) {
	c, err := s.azureConnector(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	targets := []uuid.UUID{c.ID}
	if c.ScopeKind == models.CloudScopeTenant {
		all, err := s.connectors.List(workspaceID, models.CloudProviderAzure)
		if err != nil {
			return nil, err
		}
		for _, sub := range all {
			if sub.ScopeKind == models.CloudScopeSubscription && sub.ParentScopeID != nil &&
				strings.EqualFold(*sub.ParentScopeID, c.ScopeID) && sub.Status != models.CloudConnectorRevoked {
				targets = append(targets, sub.ID)
			}
		}
	}
	out := make([]models.CloudConnector, 0, len(targets))
	for _, id := range targets {
		if _, err := s.connectors.Revoke(workspaceID, id); err != nil {
			return nil, err
		}
		stored, err := s.connectors.Get(workspaceID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, *stored)
	}
	// A tenant that read with the customer's own app: its client secret is
	// no longer AuthSec's to hold.
	if c.ScopeKind == models.CloudScopeTenant && usesCustomApp(c) {
		s.destroyCustomAppSecret(workspaceID, c.ScopeID)
	}
	return out, nil
}

/* ---------------------------------- reads ------------------------------------ */

// ListConnectors returns the workspace's Azure connectors.
func (s *AzureOnboardingService) ListConnectors(workspaceID uuid.UUID) ([]models.CloudConnector, error) {
	return s.connectors.List(workspaceID, models.CloudProviderAzure)
}

// GetConnector returns one Azure connector.
func (s *AzureOnboardingService) GetConnector(workspaceID, connectorID uuid.UUID) (*models.CloudConnector, error) {
	return s.azureConnector(workspaceID, connectorID)
}

// ListResources returns the workspace's Azure resource inventory.
func (s *AzureOnboardingService) ListResources(workspaceID uuid.UUID, f repositories.AzureListFilter) ([]models.CloudResource, int64, error) {
	return s.inventory.ListResources(workspaceID, f)
}

// ListIdentities returns the workspace's Entra directory objects.
func (s *AzureOnboardingService) ListIdentities(workspaceID uuid.UUID, f repositories.AzureIdentityFilter) ([]models.CloudIdentity, int64, error) {
	return s.inventory.ListIdentities(workspaceID, f)
}

// ListGrants returns who holds which Azure role or directory role, and where.
func (s *AzureOnboardingService) ListGrants(workspaceID uuid.UUID, f repositories.AzureGrantFilter) ([]repositories.AzureGrant, int64, error) {
	return s.inventory.ListGrants(workspaceID, f)
}

// ListSecrets returns credential metadata of app registrations and service
// principals, soonest expiry first.
func (s *AzureOnboardingService) ListSecrets(workspaceID uuid.UUID, f repositories.AzureListFilter) ([]repositories.AzureSecret, int64, error) {
	return s.inventory.ListSecrets(workspaceID, f)
}

// ListFederation returns who may become each identity: the federated
// credentials of app registrations and user-assigned managed identities.
func (s *AzureOnboardingService) ListFederation(workspaceID uuid.UUID, f repositories.AzureListFilter) ([]repositories.AzureFederationEdge, int64, error) {
	return s.inventory.ListFederation(workspaceID, f)
}

// ListWorkloads returns the resources that run as a managed identity.
func (s *AzureOnboardingService) ListWorkloads(workspaceID uuid.UUID, f repositories.AzureListFilter) ([]repositories.AzureWorkload, int64, error) {
	return s.inventory.ListWorkloads(workspaceID, f)
}

// ListFoundry returns the workspace's Foundry accounts and projects and who
// each one's managed identity can become.
func (s *AzureOnboardingService) ListFoundry(workspaceID uuid.UUID, connectorID *uuid.UUID) ([]repositories.AzureWorkload, []repositories.AzureFoundryTrust, error) {
	return s.inventory.ListFoundry(workspaceID, connectorID)
}

// ScanRuns lists one Azure connector's discovery passes, newest first.
func (s *AzureOnboardingService) ScanRuns(workspaceID, connectorID uuid.UUID, limit int) ([]models.CloudScanRun, error) {
	if _, err := s.azureConnector(workspaceID, connectorID); err != nil {
		return nil, err
	}
	return s.inventory.ScanRuns(workspaceID, connectorID, limit)
}

// Neighbourhood is one access graph node and everything one hop from it.
func (s *AzureOnboardingService) Neighbourhood(workspaceID uuid.UUID, ref string) (out *repositories.AzureGraphNeighbourhood, err error) {
	err = tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) (err error) {
		out, err = repositories.AzureNeighbourhoodOf(tx, workspaceID, ref)
		return err
	})
	return out, err
}

// Evidence is the receipts behind one Entra object and its grants.
func (s *AzureOnboardingService) Evidence(workspaceID uuid.UUID, objectID string, limit int) (out []repositories.AzureEvidence, err error) {
	err = tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) (err error) {
		out, err = repositories.AzureEvidenceFor(tx, workspaceID, objectID, limit)
		return err
	})
	return out, err
}

// GraphSummary counts the workspace's Azure rows in the shared IGA graph.
func (s *AzureOnboardingService) GraphSummary(workspaceID uuid.UUID) (out []repositories.AzureGraphCount, err error) {
	err = tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) (err error) {
		out, err = repositories.AzureGraphSummary(tx, workspaceID)
		return err
	})
	return out, err
}

// BlastRadius is everything one Entra object can reach in the graph, directly,
// through its groups, and through the identities it can become.
func (s *AzureOnboardingService) BlastRadius(workspaceID uuid.UUID, objectID string) (out *repositories.AzureBlastRadius, err error) {
	err = tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) (err error) {
		out, err = repositories.AzureBlastRadiusOf(tx, workspaceID, objectID)
		return err
	})
	return out, err
}

// ListUsage returns sign-in evidence: which identity obtained tokens for which
// resource, most recent first.
func (s *AzureOnboardingService) ListUsage(workspaceID uuid.UUID, f repositories.AzureUsageFilter) ([]repositories.AzureUsage, int64, error) {
	return s.inventory.ListUsage(workspaceID, f)
}

func (s *AzureOnboardingService) azureConnector(workspaceID, connectorID uuid.UUID) (*models.CloudConnector, error) {
	c, err := s.connectors.Get(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	if c.Provider != models.CloudProviderAzure {
		return nil, repositories.ErrCloudConnectorNotFound
	}
	return c, nil
}

/* ---------------------------------- helpers ---------------------------------- */

// forEachLimited runs fn(0..n-1) with at most limit in flight.
func forEachLimited(n, limit int, fn func(i int)) {
	if n == 0 {
		return
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// logAzureError records a Microsoft refusal for an operator. The error carries
// Microsoft's code and prose only -- never a token, which is never in an error.
func logAzureError(step string, err error) {
	if err != nil {
		log.Printf("[azure] %s failed: %v", step, err)
	}
}

// logAzureRefusal records an error= redirect from Microsoft. Only the first
// line of the description is kept: the rest is trace and correlation ids.
func logAzureRefusal(leg, code, description string) {
	if i := strings.IndexAny(description, "\r\n"); i > 0 {
		description = description[:i]
	}
	if len(description) > 300 {
		description = description[:300]
	}
	log.Printf("[azure] %s refused by microsoft: error=%s description=%q", leg, code, description)
}
