package platform

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"os"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
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
	return services.NewAzureOnboardingService(ctl.db, config.GetRedisClient(), azure.AppConfigFromEnv(), ctl.vaultClient())
}

func (ctl *CloudAzureController) vaultClient() vault.VaultClient {
	addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil
	}
	vc, err := vault.NewClient(addr, token)
	if err != nil {
		return nil
	}
	return vc
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
// the signed-in administrator, prove it, and inventory the resources.
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

/* ------------------------------- connect-custom ------------------------------ */

type connectAzureCustomRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TenantID     string `json:"tenant_id"`
}

// ConnectCustom handles POST /authsec/discovery/azure/connect-custom: onboard
// a tenant using the customer's own Entra app registration and client
// credentials, rather than the AuthSec managed app.
func (ctl *CloudAzureController) ConnectCustom(c *gin.Context) {
	workspaceID, actor, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req connectAzureCustomRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if !azure.IsGUID(strings.TrimSpace(req.ClientID)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id must be a valid GUID"})
		return
	}
	if !azure.IsGUID(strings.TrimSpace(req.TenantID)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id must be a valid GUID"})
		return
	}
	if strings.TrimSpace(req.ClientSecret) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_secret is required"})
		return
	}

	result, err := ctl.service().ConnectCustom(c.Request.Context(), workspaceID, actor, azure.AppConfig{
		ClientID:     strings.ToLower(strings.TrimSpace(req.ClientID)),
		ClientSecret: strings.TrimSpace(req.ClientSecret),
	}, strings.ToLower(strings.TrimSpace(req.TenantID)))
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
	case len(r.Subscriptions) == 0 && r.Tenant != nil && r.Tenant.AzureTenantAttrs().ProvisionedVia == models.AzureProvisionedViaClientCredentials:
		return "Microsoft Entra ID tenant connected; your app cannot read any Azure subscription yet -- assign it the Reader role on the subscriptions AuthSec should read"
	case len(r.Subscriptions) == 0:
		return "Microsoft Entra ID tenant connected; no Azure subscriptions are visible to the signed-in account"
	case verified == len(r.Subscriptions):
		return "Microsoft Entra ID tenant and all selected Azure subscriptions connected"
	}
	return "Microsoft Entra ID tenant connected; some subscriptions are not readable yet -- see each subscription's Reader status"
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
// Re-proves the connector with AuthSec's own credentials; for a subscription
// that is readable, also refreshes its inventory.
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

// ListResources handles GET /authsec/discovery/azure/resources.
func (ctl *CloudAzureController) ListResources(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	f, ok := azureListFilterFrom(c)
	if !ok {
		return
	}
	rows, total, err := ctl.service().ListResources(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset,
			"note": "every resource Azure Resource Graph returned for the connected subscriptions " +
				"under AuthSec's Reader assignment; each connector's coverage says whether its last pass was complete",
		},
	})
}

// ListIdentities handles GET /authsec/discovery/azure/identities.
// Filters: connector_id, kind (entra_user, entra_group, entra_application,
// entra_service_principal, entra_managed_identity), q (name, id or UPN).
func (ctl *CloudAzureController) ListIdentities(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	f := repositories.AzureIdentityFilter{
		ConnectorID: connectorID,
		Kind:        strings.TrimSpace(c.Query("kind")),
		AgentType:   strings.TrimSpace(c.Query("agent_type")),
		Search:      strings.TrimSpace(c.Query("q")),
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := ctl.service().ListIdentities(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset},
	})
}

// azureGrantSources are the values ListGrants accepts for source.
var azureGrantSources = map[string]bool{
	repositories.AzureGrantSourceDirectoryRole: true,
	repositories.AzureGrantSourceApplication:   true,
	repositories.AzureGrantSourceDelegated:     true,
	repositories.AzureGrantSourceRBAC:          true,
	repositories.AzureGrantSourceKeyVault:      true,
}

// ListGrants handles GET /authsec/discovery/azure/grants: who holds which
// role or permission, and where. plane=api is the Entra side (directory roles,
// application and delegated API permissions); plane=cloud is Azure (RBAC role
// assignments, Key Vault access policies). Filters: connector_id,
// identity_id, plane, source.
func (ctl *CloudAzureController) ListGrants(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	plane := strings.TrimSpace(c.Query("plane"))
	if plane != "" && plane != "api" && plane != "cloud" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plane must be api or cloud"})
		return
	}
	resourceID, err := parseOptionalUUID(c.Query("resource_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource_id"})
		return
	}
	source := strings.TrimSpace(c.Query("source"))
	if source != "" && !azureGrantSources[source] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source must be directory_role, application_permission, " +
			"delegated_permission, rbac_role_assignment or key_vault_access_policy"})
		return
	}
	f := repositories.AzureGrantFilter{
		ConnectorID: connectorID,
		IdentityID:  identityID,
		Plane:       plane,
		Source:      source,
		ResourceID:  resourceID,
		Limit:       atoiDefault(c.Query("limit"), 100),
		Offset:      atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := ctl.service().ListGrants(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset,
			"note": "plane=api: Microsoft Entra roles (active assignments) and API permissions -- application " +
				"permissions apply on their own, delegated ones only on behalf of a signed-in user (constraint bounded). " +
				"plane=cloud: Azure RBAC role assignments and Key Vault access policies. " +
				"Grants are as assigned, not effective: a role held through a group is listed on the group.",
		},
	})
}

// ListFederation handles GET /authsec/discovery/azure/federation: who outside
// Entra may obtain an identity's tokens with no secret -- federated
// credentials on app registrations and user-assigned managed identities
// (GitHub Actions, AKS service accounts, other OIDC issuers).
func (ctl *CloudAzureController) ListFederation(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	f, ok := azureListFilterFrom(c)
	if !ok {
		return
	}
	rows, total, err := ctl.service().ListFederation(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset},
	})
}

// ListWorkloads handles GET /authsec/discovery/azure/workloads: resources that
// run as a managed identity, one row per (resource, identity), and AKS
// clusters with their OIDC issuer.
func (ctl *CloudAzureController) ListWorkloads(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	f, ok := azureListFilterFrom(c)
	if !ok {
		return
	}
	rows, total, err := ctl.service().ListWorkloads(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset},
	})
}

// ListFoundry handles GET /authsec/discovery/azure/foundry: every Foundry and
// Cognitive Services account and Foundry project (with its models and
// connections), and, under "trusts", who each one's managed identity can
// become -- for a Foundry agent, its blueprint and agent identities.
func (ctl *CloudAzureController) ListFoundry(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	f, ok := azureListFilterFrom(c)
	if !ok {
		return
	}
	rows, trusts, err := ctl.service().ListFoundry(workspaceID, f.ConnectorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "trusts": trusts, "meta": gin.H{"as_of": time.Now().UTC(), "total": len(rows)}})
}

// Neighbourhood handles GET /authsec/discovery/azure/graph/neighbourhood?ref=:
// one access graph node and everything one hop from it, for a canvas that
// starts on one object and expands on request. ref is "<type>:<id>" --
// object:<Entra object id>, identity|resource|workload|external:<graph id>,
// or scope:<scope path>.
func (ctl *CloudAzureController) Neighbourhood(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	ref := strings.TrimSpace(c.Query("ref"))
	out, err := ctl.service().Neighbourhood(workspaceID, ref)
	switch {
	case errors.Is(err, repositories.ErrGraphNodeNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "that node is not in the graph: discovery has not projected it, " +
			"it has no live connections, or IGA_GRAPH_PROJECTION is off"})
		return
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": gin.H{"as_of": time.Now().UTC()}})
}

// Evidence handles GET /authsec/discovery/azure/evidence?object_id=: how
// AuthSec knows what it says about one Entra object -- for the object and each
// grant it holds, the Microsoft API that returned it, the coverage state of
// that read, the scan run, and how many runs have confirmed it since.
func (ctl *CloudAzureController) Evidence(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	objectID := strings.TrimSpace(c.Query("object_id"))
	if !azure.IsGUID(objectID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "object_id must be a Microsoft Entra object ID"})
		return
	}
	limit := atoiDefault(c.Query("limit"), 100)
	rows, err := ctl.service().Evidence(workspaceID, objectID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "total": len(rows), "limit": limit},
	})
}

// GraphSummary handles GET /authsec/discovery/azure/graph/summary: the Azure
// rows of the shared IGA graph, by kind and state. Empty unless
// IGA_GRAPH_PROJECTION is on.
func (ctl *CloudAzureController) GraphSummary(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	rows, err := ctl.service().GraphSummary(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	gate := services.GraphProjection()
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "projection_enabled": gate != nil && gate.Enabled()},
	})
}

// BlastRadius handles GET /authsec/discovery/azure/graph/blast-radius?object_id=:
// every live grant an Entra object can reach -- its own, its groups'
// (transitively), and those of identities it can become through federation --
// most sensitive first.
func (ctl *CloudAzureController) BlastRadius(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	objectID := strings.TrimSpace(c.Query("object_id"))
	if !azure.IsGUID(objectID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "object_id must be a Microsoft Entra object ID"})
		return
	}
	out, err := ctl.service().BlastRadius(workspaceID, objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if out.Identity == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "that object is not in the graph: discovery has not projected it, or IGA_GRAPH_PROJECTION is off"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": out,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "grants are as assigned: Azure RBAC deny assignments and ABAC conditions are not evaluated, " +
				"so those grants carry effective_conclusion unknown; delegated permissions apply only on behalf of a signed-in user",
		},
	})
}

// ListUsage handles GET /authsec/discovery/azure/usage: which service
// principal or managed identity obtained tokens for which resource, from the
// Entra sign-in log (Entra ID P1/P2). Filters: identity_id, ai=true (Azure AI
// services only).
func (ctl *CloudAzureController) ListUsage(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	f := repositories.AzureUsageFilter{
		IdentityID: identityID,
		AIOnly:     c.Query("ai") == "true",
		Limit:      atoiDefault(c.Query("limit"), 100),
		Offset:     atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := ctl.service().ListUsage(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset,
			"note": "aggregated from service principal and managed identity sign-ins, one row per identity per resource; " +
				"last_used_at is the most recent successful sign-in AuthSec has seen. Empty when the tenant has no " +
				"Microsoft Entra ID P1 or P2 licence -- the tenant connector's coverage says which.",
		},
	})
}

// ListSecrets handles GET /authsec/discovery/azure/secrets: client secret and
// certificate METADATA (never values) of app registrations and service
// principals, soonest expiry first.
func (ctl *CloudAzureController) ListSecrets(c *gin.Context) {
	workspaceID, _, err := workspaceAndActorFrom(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	f, ok := azureListFilterFrom(c)
	if !ok {
		return
	}
	rows, total, err := ctl.service().ListSecrets(workspaceID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{"as_of": time.Now().UTC(), "total": total, "limit": f.Limit, "offset": f.Offset},
	})
}

// azureListFilterFrom reads the inventory list filters: connector_id,
// identity_id, kind, q, limit, offset. Writes the 400 itself.
func azureListFilterFrom(c *gin.Context) (repositories.AzureListFilter, bool) {
	f := repositories.AzureListFilter{
		Kind:   strings.TrimSpace(c.Query("kind")),
		Search: strings.TrimSpace(c.Query("q")),
		Limit:  atoiDefault(c.Query("limit"), 100),
		Offset: atoiDefault(c.Query("offset"), 0),
	}
	var err error
	if f.ConnectorID, err = parseOptionalUUID(c.Query("connector_id")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return f, false
	}
	if f.IdentityID, err = parseOptionalUUID(c.Query("identity_id")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return f, false
	}
	return f, true
}

// ScanRuns handles GET /authsec/discovery/azure/connectors/:id/scan-runs: the
// connector's discovery passes, newest first -- what started each one, how it
// ended, and the coverage it published.
func (ctl *CloudAzureController) ScanRuns(c *gin.Context) {
	workspaceID, connectorID, ok := azureConnectorParams(c)
	if !ok {
		return
	}
	rows, err := ctl.service().ScanRuns(workspaceID, connectorID, atoiDefault(c.Query("limit"), 20))
	if err != nil {
		status, body := mapAzureOnboardingError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"as_of": time.Now().UTC(), "total": len(rows)}})
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

	// The customer's own app ("your own app"): theirs to fix, never
	// AuthSec's deployment. Checked before the managed-app cases below.
	case errors.Is(err, services.ErrAzureCustomCredentialRejected):
		return h(http.StatusBadRequest,
			"check the client id and client secret of your app registration: the secret may be mistyped, expired or deleted. "+
				"Create a new client secret in Microsoft Entra ID if needed", "customer_account")
	case errors.Is(err, services.ErrAzureCustomTenantNotFound):
		return h(http.StatusBadRequest,
			"check the tenant id: it is the Directory (tenant) ID on your app registration's Overview page", "customer_account")
	case errors.Is(err, services.ErrAzureCustomAppNotInTenant):
		return h(http.StatusBadRequest,
			"check the client id, and that your app registration lives in, or was consented in, this tenant and is enabled", "customer_account")
	case errors.Is(err, services.ErrAzureCustomPermissionsMissing):
		return h(http.StatusBadRequest,
			"add the listed Microsoft Graph application permissions to your app registration and grant admin consent, then connect again", "customer_account")
	case errors.Is(err, services.ErrAzureCustomCredentialsStore):
		return h(http.StatusInternalServerError,
			"AuthSec could not store your app's credentials securely; try again, and contact support if it keeps failing", "authsec")
	case errors.Is(err, azure.ErrTenantNotFound):
		return h(http.StatusBadRequest, "check the tenant id", "customer_account")
	case errors.Is(err, services.ErrAzureVaultNotConfigured):
		return h(http.StatusServiceUnavailable,
			"set VAULT_ADDR and VAULT_TOKEN so custom app credentials can be stored securely", "authsec")
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
			"AuthSec's Microsoft Entra application credential was rejected; check AZURE_AUTHSEC_CLIENT_SECRET (expired or rotated?) and, if set, AZURE_AUTHSEC_TENANT_ID", "authsec")
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
	// Anything else is AuthSec's own failure: its text can name internals
	// (a Vault path, a database error), so it is logged, not returned.
	log.Printf("[azure] onboarding failed: %v", err)
	return http.StatusInternalServerError, gin.H{"error": "AuthSec could not complete the request; try again, and contact support if it keeps failing"}
}
