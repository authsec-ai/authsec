package platform

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/azure"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudAzureController onboards Microsoft Entra tenants and Azure
// subscriptions through AuthSec's one multi-tenant app registration. See
// services.AzureOnboardingService for the flow and docs/flows/azure-onboarding.md
// for the customer journey.
type CloudAzureController struct {
	db *gorm.DB
}

// NewCloudAzureController constructs the controller.
func NewCloudAzureController(db *gorm.DB) *CloudAzureController {
	return &CloudAzureController{db: db}
}

// service builds the Azure service. The app registration, secret included, is
// read from the environment per request and never stored anywhere else.
func (ctl *CloudAzureController) service() *services.AzureOnboardingService {
	return services.NewAzureOnboardingService(ctl.db, config.GetRedisClient(), azure.AppConfigFromEnv())
}

/* ----------------------------------- status ---------------------------------- */

// OAuthStatus handles GET /authsec/discovery/azure/oauth/status. Lets the UI
// hide the Azure option when the deployment is not configured for it.
func (ctl *CloudAzureController) OAuthStatus(c *gin.Context) {
	cfg := azure.AppConfigFromEnv()
	c.JSON(http.StatusOK, gin.H{
		"available":    ctl.service().Available(c.Request.Context()),
		"client_id":    cfg.ClientID,
		"redirect_uri": cfg.RedirectURI,
	})
}

/* ----------------------------------- start ----------------------------------- */

type startAzureOAuthRequest struct {
	// Tenant optionally pins the consent screen to one directory (tenant id
	// or verified domain). Empty lets the administrator's account decide.
	Tenant    string `json:"tenant"`
	LoginHint string `json:"login_hint"`
}

// StartOAuth handles POST /authsec/discovery/azure/oauth/start and returns the
// Microsoft admin-consent URL the browser should open.
func (ctl *CloudAzureController) StartOAuth(c *gin.Context) {
	workspaceID, actor, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req startAzureOAuthRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
			return
		}
	}
	authorizeURL, state, err := ctl.service().Start(c.Request.Context(), workspaceID, actor, req.Tenant, req.LoginHint)
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{"authorize_url": authorizeURL, "state": state})
}

/* ---------------------------------- callback --------------------------------- */

// OAuthCallback handles GET /api/v1/auth/azure/callback -- the one redirect
// URI registered on the AuthSec app, serving both legs.
//
// UNAUTHENTICATED by necessity, like the GCP and connector-broker callbacks:
// Microsoft redirects the bare browser here. It only validates and consumes
// state, then either sends the browser on to Microsoft for the sign-in leg or
// redeems the code and sends the browser back into the authenticated UI with
// an opaque session id (never a token). Every step that acts is authenticated
// and re-checks that the session belongs to the caller.
//
// Registered on the ROOT engine so its path matches AZURE_REDIRECT_URI exactly.
func (ctl *CloudAzureController) OAuthCallback(c *gin.Context) {
	redirectTo := func(query url.Values) string {
		if config.AppConfig != nil {
			if u := config.AppConfig.BuildUIRouteURL("/discovery/cloud/azure/oauth/callback", query); u != "" {
				return u
			}
		}
		return "/discovery/cloud/azure/oauth/callback?" + query.Encode()
	}

	outcome, err := ctl.service().HandleCallback(c.Request.Context(), services.AzureCallbackParams{
		State:            c.Query("state"),
		Code:             c.Query("code"),
		AdminConsent:     c.Query("admin_consent"),
		Tenant:           c.Query("tenant"),
		Error:            c.Query("error"),
		ErrorDescription: c.Query("error_description"),
	})
	if err != nil {
		c.Redirect(http.StatusFound, redirectTo(url.Values{"error": {azureCallbackErrorCode(err)}}))
		return
	}
	if outcome.NextURL != "" {
		c.Redirect(http.StatusFound, outcome.NextURL)
		return
	}
	c.Redirect(http.StatusFound, redirectTo(url.Values{"session_id": {outcome.SessionID}}))
}

// azureCallbackErrorCode is the stable code the UI shows for a failed
// callback. Codes only: the query string is the wrong place for prose.
func azureCallbackErrorCode(err error) string {
	switch {
	case errors.Is(err, azure.ErrNotConfigured):
		return "not_configured"
	case errors.Is(err, services.ErrAzureOAuthStateInvalid):
		return "state_invalid"
	case errors.Is(err, azure.ErrConsentDenied):
		return "consent_denied"
	case errors.Is(err, azure.ErrConsentRequired):
		return "consent_required"
	case errors.Is(err, azure.ErrTenantMismatch):
		return "tenant_mismatch"
	case errors.Is(err, azure.ErrCredentialRejected):
		return "authsec_credential_rejected"
	}
	return "sign_in_failed"
}

/* ---------------------------------- session ---------------------------------- */

// GetSession handles GET /authsec/discovery/azure/oauth/session?session_id=.
// Previews the tenant and subscriptions Connect would act on; changes nothing.
func (ctl *CloudAzureController) GetSession(c *gin.Context) {
	workspaceID, actor, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sessionID := strings.TrimSpace(c.Query("session_id"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}
	view, err := ctl.service().Session(c.Request.Context(), sessionID, workspaceID, actor)
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": view, "meta": gin.H{"as_of": time.Now().UTC()}})
}

/* ---------------------------------- connect ---------------------------------- */

type connectAzureRequest struct {
	SessionID string `json:"session_id"`
	// SubscriptionIDs narrows Reader assignment to these subscriptions.
	// Empty means every subscription the administrator can see.
	SubscriptionIDs []string `json:"subscription_ids"`
}

// Connect handles POST /authsec/discovery/azure/oauth/connect: verify the
// service principal and Graph permissions, assign Reader per subscription as
// the signed-in administrator, and prove it.
func (ctl *CloudAzureController) Connect(c *gin.Context) {
	workspaceID, actor, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req connectAzureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}

	result, err := ctl.service().Connect(c.Request.Context(), sessionID, workspaceID, actor, req.SubscriptionIDs)
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		auditAdminMutation(c, workspaceID.String(), "onboard", "cloud_connector", "", status, nil, body)
		c.JSON(status, body)
		return
	}

	status := http.StatusOK
	if result.TenantCreated {
		status = http.StatusCreated
	}
	auditAdminMutation(c, workspaceID.String(), "onboard", "cloud_connector",
		result.Tenant.ID.String(), status, nil, result)

	c.JSON(status, gin.H{
		"success": true,
		"message": azureConnectMessage(result),
		"data":    result,
		"meta":    gin.H{"as_of": time.Now().UTC()},
	})
}

func azureConnectMessage(r *services.AzureConnectResult) string {
	verified := 0
	for _, s := range r.Subscriptions {
		if s.Reader.Verified {
			verified++
		}
	}
	switch {
	case len(r.Subscriptions) == 0:
		return "Entra tenant connected; no Azure subscriptions are visible to the signed-in account"
	case verified == len(r.Subscriptions):
		return "Entra tenant and all selected Azure subscriptions connected"
	}
	return "Entra tenant connected; some subscriptions are not readable yet -- see each subscription's reader status"
}

/* --------------------------------- connectors -------------------------------- */

// ListConnectors handles GET /authsec/discovery/azure/connectors.
func (ctl *CloudAzureController) ListConnectors(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	rows, err := ctl.service().ListConnectors(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "count": len(rows)},
	})
}

// GetConnector handles GET /authsec/discovery/azure/connectors/:id.
func (ctl *CloudAzureController) GetConnector(c *gin.Context) {
	workspaceID, connectorID, ok := azureConnectorParams(c)
	if !ok {
		return
	}
	conn, err := ctl.service().GetConnector(workspaceID, connectorID)
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": conn})
}

// VerifyConnector handles POST /authsec/discovery/azure/connectors/:id/verify.
// Re-proves the connector with AuthSec's own credentials.
func (ctl *CloudAzureController) VerifyConnector(c *gin.Context) {
	workspaceID, connectorID, ok := azureConnectorParams(c)
	if !ok {
		return
	}
	result, err := ctl.service().Verify(c.Request.Context(), workspaceID, connectorID)
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		c.JSON(status, body)
		return
	}
	auditAdminMutation(c, workspaceID.String(), "verify", "cloud_connector",
		connectorID.String(), http.StatusOK, nil, result.Connector)
	c.JSON(http.StatusOK, gin.H{
		"data": result,
		"meta": gin.H{"as_of": time.Now().UTC(), "verified": result.Connector.VerifiedAt},
	})
}

// RevokeConnector handles DELETE /authsec/discovery/azure/connectors/:id.
func (ctl *CloudAzureController) RevokeConnector(c *gin.Context) {
	workspaceID, connectorID, ok := azureConnectorParams(c)
	if !ok {
		return
	}
	revoked, err := ctl.service().Revoke(workspaceID, connectorID)
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		c.JSON(status, body)
		return
	}
	auditAdminMutation(c, workspaceID.String(), "revoke", "cloud_connector",
		connectorID.String(), http.StatusOK, nil, revoked)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    revoked,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "AuthSec stopped using this connection. Access in Azure is unchanged until the customer " +
				"deletes the AuthSec enterprise application, which also removes its Reader assignments.",
		},
	})
}

func azureConnectorParams(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return uuid.Nil, uuid.Nil, false
	}
	connectorID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return uuid.Nil, uuid.Nil, false
	}
	return workspaceID, connectorID, true
}

/* ------------------------------- error mapping ------------------------------- */

// mapAzureOnboardingError maps the service's sentinels to the {error, hint,
// fault} shape the AWS and GCP onboarding surfaces use. fault says whose move
// it is: authsec (deployment), customer_account (the customer's tenant or
// sign-in), azure (Microsoft).
func mapAzureOnboardingError(err error) (int, gin.H) {
	h := func(status int, hint, fault string) (int, gin.H) {
		return status, gin.H{
			"error":      err.Error(),
			"error_code": services.ClassifyConnectorError(err),
			"hint":       hint,
			"fault":      fault,
		}
	}
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		return http.StatusNotFound, gin.H{"error": "azure connector not found"}
	case errors.Is(err, azure.ErrNotConfigured):
		return h(http.StatusServiceUnavailable,
			"set AZURE_AUTHSEC_CLIENT_ID, AZURE_AUTHSEC_CLIENT_SECRET and AZURE_REDIRECT_URI, and make sure Redis is reachable", "authsec")
	case errors.Is(err, azure.ErrInvalidInput):
		return h(http.StatusBadRequest, "check the tenant, login hint or subscription ids sent", "customer_account")
	case errors.Is(err, services.ErrAzureSessionInvalid), errors.Is(err, services.ErrAzureOAuthStateInvalid):
		return h(http.StatusBadRequest, "start the Azure connection again and complete the Microsoft sign-in", "customer_account")
	case errors.Is(err, services.ErrAzureSessionMismatch):
		return h(http.StatusForbidden, "start the Azure connection again from your own AuthSec account", "customer_account")
	case errors.Is(err, services.ErrAzureConnectorRevoked):
		return h(http.StatusConflict, "connect the tenant again to restore this connection", "customer_account")
	case errors.Is(err, azure.ErrCredentialRejected):
		return h(http.StatusBadGateway,
			"AuthSec's Entra application credential was rejected; check AZURE_AUTHSEC_CLIENT_SECRET (expired or rotated?) and, if set, AZURE_AUTHSEC_TENANT_ID", "authsec")
	case errors.Is(err, azure.ErrAppNotInTenant):
		return h(http.StatusBadRequest,
			"a Global Administrator must grant admin consent to the AuthSec application in this tenant, then connect again", "customer_account")
	case errors.Is(err, azure.ErrGraphPermissionsMissing):
		return h(http.StatusBadRequest,
			"grant admin consent again so the AuthSec application holds Application.Read.All, Directory.Read.All and AuditLog.Read.All", "customer_account")
	case errors.Is(err, azure.ErrNotAuthorizedToBind):
		return h(http.StatusForbidden,
			"sign in with a member account holding Global Administrator or Privileged Role Administrator", "customer_account")
	case errors.Is(err, azure.ErrConsentRequired):
		return h(http.StatusBadRequest,
			"the AuthSec app registration must declare Azure Service Management user_impersonation so admin consent grants it", "authsec")
	case errors.Is(err, azure.ErrTenantMismatch), errors.Is(err, azure.ErrSignInFailed), errors.Is(err, azure.ErrConsentDenied):
		return h(http.StatusBadRequest, "start the Azure connection again and sign in to the tenant you consented", "customer_account")
	case errors.Is(err, azure.ErrARMForbidden):
		return h(http.StatusForbidden, "the signed-in account could not read Azure subscriptions in this tenant", "customer_account")
	case errors.Is(err, azure.ErrThrottled):
		return h(http.StatusTooManyRequests, "Microsoft is throttling requests; try again in a minute", "azure")
	}
	var ae *azure.APIError
	if errors.As(err, &ae) {
		return h(http.StatusBadGateway, "Microsoft returned an unexpected error; see error for its code", "azure")
	}
	return http.StatusInternalServerError, gin.H{"error": err.Error()}
}
