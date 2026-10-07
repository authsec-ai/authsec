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
//     create the Reader assignment on each one AS THE ADMINISTRATOR, and
//     prove each with AuthSec's OWN app-only token.
//
// Graph consent and Azure RBAC are separate grants. Admin consent gives the
// service principal directory read access and nothing in any subscription;
// the service principal holds no roleAssignments/write and so can never grant
// itself Reader. Every assignment is made with the delegated token of a human
// who holds that permission, through the same ARM API the portal uses.
//
// No credential is persisted. AuthSec's client secret stays in the deployment
// environment (cloud_connector.auth_ref is the non-secret "azure-app:<id>"),
// no refresh token is ever requested, and the administrator's access token
// lives only in Redis until Connect consumes it or the TTL expires it -- the
// same one-shot discipline as GCPOAuthProvisionService.
type AzureOnboardingService struct {
	db         *gorm.DB
	redis      *redis.Client
	cfg        azure.AppConfig
	api        *azure.Client
	connectors repositories.CloudConnectorRepository
}

// NewAzureOnboardingService constructs the service. redisClient may be nil, in
// which case Available reports false and every flow method fails with
// azure.ErrNotConfigured.
func NewAzureOnboardingService(db *gorm.DB, redisClient *redis.Client, cfg azure.AppConfig) *AzureOnboardingService {
	return &AzureOnboardingService{
		db:         db,
		redis:      redisClient,
		cfg:        cfg,
		api:        azure.NewClient(nil),
		connectors: repositories.NewCloudConnectorRepository(db),
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
func azureSubscriptionAssignable(state string) bool {
	switch strings.ToLower(state) {
	case "enabled", "warned", "pastdue":
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
	perms, missing, err := s.verifyGraphPermissions(ctx, graphToken, sp.ID)
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
	for i := range results {
		conn, err := s.recordSubscription(workspaceID, tid, sp.ID, actor, &results[i])
		if err != nil {
			results[i].Error = "could not record the subscription: " + err.Error()
			continue
		}
		results[i].ConnectorID = &conn.ID
		results[i].Status = conn.Status
	}

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

// verifyGraphPermissions reports every required Graph application permission
// as granted (an app role assignment exists) and usable (a minimal read it
// allows succeeded). missing lists the ones not granted at all -- the only case
// that fails onboarding; a granted-but-unusable permission is recorded, not
// fatal, because the usual cause (a licence, a just-issued token) is not fixed
// by consenting again.
func (s *AzureOnboardingService) verifyGraphPermissions(ctx context.Context, graphToken, spID string) ([]models.AzureGraphPermission, []string, error) {
	graphSP, err := s.api.FindServicePrincipal(ctx, graphToken, azure.GraphAppID, true)
	if err != nil {
		logAzureError("find microsoft graph service principal", err)
		return nil, nil, err
	}
	roleValue := map[string]string{}
	for _, r := range graphSP.AppRoles {
		roleValue[strings.ToLower(r.ID)] = r.Value
	}
	assignments, err := s.api.ListAppRoleAssignments(ctx, graphToken, spID)
	if err != nil {
		logAzureError("list app role assignments", err)
		return nil, nil, err
	}
	granted := map[string]bool{}
	for _, a := range assignments {
		if strings.EqualFold(a.ResourceID, graphSP.ID) {
			if v := roleValue[strings.ToLower(a.AppRoleID)]; v != "" {
				granted[v] = true
			}
		}
	}

	perms := make([]models.AzureGraphPermission, 0, len(azure.RequiredGraphAppRoles)+len(azure.OptionalGraphAppRoles))
	var missing []string
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
	return perms, missing, nil
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
		return fmt.Errorf("%w: the signed-in account's directory roles could not be read", azure.ErrNotAuthorizedToBind)
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
		if left := time.Until(dl); left < budget {
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
	parent := tenantID
	conn := &models.CloudConnector{
		WorkspaceID:   workspaceID,
		Provider:      models.CloudProviderAzure,
		ScopeKind:     models.CloudScopeSubscription,
		ScopeID:       r.SubscriptionID,
		ParentScopeID: &parent,
		AuthRef:       s.cfg.AuthRef(),
		CreatedBy:     actor,
	}
	if err := conn.SetAzureSubscriptionAttrs(models.AzureSubscriptionAttrs{
		TenantID:                 tenantID,
		DisplayName:              r.DisplayName,
		State:                    r.State,
		ServicePrincipalObjectID: principalID,
		Reader:                   r.Reader,
		ProvisionedVia:           models.AzureProvisionedViaAdminConsent,
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
}

// Verify re-proves a connector with AuthSec's own credentials alone -- no
// customer sign-in. A tenant connector re-checks the service principal and its
// Graph permissions; a subscription connector re-checks Reader access. It
// cannot CREATE a missing Reader assignment: that needs an administrator,
// which means running the onboarding flow again.
func (s *AzureOnboardingService) Verify(parent context.Context, workspaceID, connectorID uuid.UUID) (*AzureVerifyResult, error) {
	ctx, cancel := context.WithTimeout(parent, azureConnectBudget)
	defer cancel()

	if !s.cfg.Configured() {
		return nil, azure.ErrNotConfigured
	}
	c, err := s.azureConnector(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	if c.Status == models.CloudConnectorRevoked {
		return nil, ErrAzureConnectorRevoked
	}

	if c.ScopeKind == models.CloudScopeTenant {
		return s.verifyTenant(ctx, c)
	}
	return s.verifySubscription(ctx, c)
}

func (s *AzureOnboardingService) verifyTenant(ctx context.Context, c *models.CloudConnector) (*AzureVerifyResult, error) {
	fail := func(err error) (*AzureVerifyResult, error) {
		stored, merr := s.connectors.MarkError(c.WorkspaceID, c.ID, err.Error(), ClassifyConnectorError(err))
		if merr != nil {
			return nil, merr
		}
		return &AzureVerifyResult{Connector: stored}, nil
	}

	graphToken, err := s.api.AppToken(ctx, s.cfg, c.ScopeID, azure.ScopeGraphApp)
	if err != nil {
		logAzureError("graph app token", err)
		return fail(err)
	}
	sp, err := s.findAuthSecServicePrincipal(ctx, graphToken)
	if err != nil {
		return fail(err)
	}
	perms, missing, err := s.verifyGraphPermissions(ctx, graphToken, sp.ID)
	if err != nil {
		return fail(err)
	}

	attrs := c.AzureTenantAttrs()
	attrs.ServicePrincipalObjectID = sp.ID
	attrs.ServicePrincipalName = sp.DisplayName
	attrs.GraphPermissions = perms
	if len(missing) > 0 {
		if err := c.SetAzureTenantAttrs(attrs); err == nil {
			_ = s.db.Model(&models.CloudConnector{}).
				Where("workspace_id = ? AND id = ?", c.WorkspaceID, c.ID).
				Update("attrs", c.Attrs).Error
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
	return &AzureVerifyResult{Connector: stored}, nil
}

func (s *AzureOnboardingService) verifySubscription(ctx context.Context, c *models.CloudConnector) (*AzureVerifyResult, error) {
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

	armToken, err := s.api.AppToken(ctx, s.cfg, tenantID, azure.ScopeARMApp)
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
			_ = s.db.Model(&models.CloudConnector{}).
				Where("workspace_id = ? AND id = ?", c.WorkspaceID, c.ID).
				Update("attrs", c.Attrs).Error
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
	stored, err := s.connectors.MarkVerified(c.WorkspaceID, c.ID, c.Attrs)
	if err != nil {
		return nil, err
	}
	return &AzureVerifyResult{Connector: stored}, nil
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
