package platform

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/internal/vault"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AzureOnboardController is Azure onboarding: sign an operator in, list the
// Entra tenants their account can see, admin-consent the chosen ones, and check
// whether ARM Reader was actually assigned.
//
// It lives under /api/azure/* rather than /authsec/discovery/azure/* for one
// reason that is not negotiable: /api/azure/callback is fixed by the redirect
// URI registered on the Entra application, and Microsoft will refuse to redirect
// anywhere else. The other four routes are grouped with it so the flow reads as
// one thing.
//
// The two browser-facing routes are unauthenticated because a top-level redirect
// from Microsoft cannot carry a bearer token. They are protected by the one-shot
// state row instead. The four console-facing routes are authenticated and RBAC
// checked exactly like the AWS routes: they are ordinary fetch calls.
type AzureOnboardController struct {
	db *gorm.DB
}

// NewAzureOnboardController constructs the controller.
func NewAzureOnboardController(db *gorm.DB) *AzureOnboardController {
	return &AzureOnboardController{db: db}
}

// The operator's session id travels in a cookie because the browser is the only
// thing present on the callback. Path-scoped so it is never attached to an
// unrelated request; HttpOnly so page scripts cannot read it; Lax so it still
// arrives on the top-level redirect back from Microsoft, which is the one
// navigation that must carry it.
const azureSessionCookie = "authsec_azure_session"

const azureSessionSecretEnv = "SESSION_SECRET"

// service builds the onboarding service, or explains why it cannot.
func (ctl *AzureOnboardController) service() (*services.AzureOnboardService, error) {
	addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		// The operator's delegated ARM token has to go somewhere safe. Refuse
		// plainly here rather than fail later with a confusing 500.
		return nil, errors.New("VAULT_ADDR/VAULT_TOKEN not configured; the azure sign-in token cannot be stored")
	}
	vc, err := vault.NewClient(addr, token)
	if err != nil {
		return nil, err
	}
	return services.NewAzureOnboardService(ctl.db, vc)
}

// ConfigStatus handles GET /api/azure/config.
//
// Reports what this deployment is configured with, so a setup screen can show a
// live checklist instead of an operator guessing from a 500. Deliberately does
// NOT go through ctl.service(): that constructor fails when configuration is
// incomplete, which is exactly the state this endpoint exists to describe.
//
// Secret VALUES are never returned -- only whether each one is set. The client
// id, redirect uri and endpoints are public by design (they appear in every
// authorize URL), so reporting them lets a setup screen catch the single most
// common misconfiguration: a redirect uri that does not match the one
// registered on the Entra application.
func (ctl *AzureOnboardController) ConfigStatus(c *gin.Context) {
	if _, _, err := ctl.workspaceAndActor(c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	redirectURI := strings.TrimSpace(os.Getenv("AZURE_REDIRECT_URI"))
	secretSet := strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET")) != ""
	sessionSet := len(strings.TrimSpace(os.Getenv(azureSessionSecretEnv))) >= 32
	vaultSet := os.Getenv("VAULT_ADDR") != "" && os.Getenv("VAULT_TOKEN") != ""

	missing := []string{}
	if clientID == "" {
		missing = append(missing, "AZURE_CLIENT_ID")
	}
	if !secretSet {
		missing = append(missing, "AZURE_CLIENT_SECRET")
	}
	if redirectURI == "" {
		missing = append(missing, "AZURE_REDIRECT_URI")
	}
	if !sessionSet {
		missing = append(missing, "SESSION_SECRET (32+ chars)")
	}
	if !vaultSet {
		missing = append(missing, "VAULT_ADDR/VAULT_TOKEN")
	}

	c.JSON(http.StatusOK, gin.H{
		"ready": len(missing) == 0,
		"data": gin.H{
			// Public values, echoed so a setup screen can compare them against
			// the Entra application.
			"client_id":      clientID,
			"redirect_uri":   redirectURI,
			"signin_tenant":  azureonboard.SignInTenant,
			"authority_host": azureonboard.AuthorityBase,
			"arm_endpoint":   azureonboard.ARMBase,

			// Presence only. The values are never serialised.
			"client_secret_set":  secretSet,
			"session_secret_set": sessionSet,
			"vault_configured":   vaultSet,

			"missing": missing,
		},
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "secret values are never returned; only whether they are set. " +
				"redirect_uri must match a uri registered on the entra application exactly",
			"required_graph_permissions": azureonboard.RequiredGraphRoles(),
		},
	})
}

/* ---------------------------------- login --------------------------------- */

// Login handles GET /api/azure/login.
//
// Redirects the operator to Microsoft to sign in with their own Azure work
// account. Nothing is stored until they come back.
func (ctl *AzureOnboardController) Login(c *gin.Context) {
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	workspaceID, err := svc.ResolveLoginWorkspace(c.Query("workspace_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// admin_consent=true merges tenant-wide consent into this sign-in. Opt-in per
	// request rather than per deployment: it requires a Global Administrator, so
	// forcing it on would lock out every other operator on the same instance.
	adminConsent := strings.EqualFold(strings.TrimSpace(c.Query("admin_consent")), "true")

	authorizeURL, err := svc.StartLogin(workspaceID, "browser", adminConsent)
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	c.Redirect(http.StatusFound, authorizeURL)
}

/* -------------------------------- callback -------------------------------- */

// Callback handles GET /api/azure/callback, for both redirects.
//
// Unauthenticated by necessity. The one-shot state row is what authorises it,
// and it is the only place the workspace and consented tenant are read from.
func (ctl *AzureOnboardController) Callback(c *gin.Context) {
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	res, err := svc.HandleCallback(c.Request.Context(), services.AzureCallbackInput{
		Code:             c.Query("code"),
		State:            c.Query("state"),
		Tenant:           c.Query("tenant"),
		AdminConsent:     c.Query("admin_consent"),
		Error:            c.Query("error"),
		ErrorDescription: c.Query("error_description"),
	})
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	if res.Step == "logged_in" {
		secret := []byte(os.Getenv(azureSessionSecretEnv))
		if len(secret) == 0 {
			// The token is already stored; without a way to hand the operator a
			// tamper-evident handle it cannot be used, so say so rather than
			// issuing an unprotected cookie.
			svc.EndSession(res.WorkspaceID, res.SessionID)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "SESSION_SECRET is not configured on this deployment",
			})
			return
		}
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			azureSessionCookie,
			signAzureSession(res.SessionID, secret),
			int(8*time.Hour/time.Second),
			"/api/azure",
			"",
			requestIsHTTPS(c),
			true,
		)
		c.JSON(http.StatusOK, gin.H{"ok": true, "step": "logged_in"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":     true,
		"step":   "consented",
		"tenant": res.Connector.TenantID,
		"data":   res.Connector,
		"meta": gin.H{
			"created": res.Created,
			"next": "POST /api/azure/validate-arm with this tenantId, after assigning Reader to " +
				"the AuthSec application in the tenant's subscriptions",
			"note": "consent is not access: the application can be fully consented here and still " +
				"read nothing until a Reader role assignment exists",
		},
	})
}

/* --------------------------------- tenants -------------------------------- */

// ListTenants handles GET /api/azure/tenants.
//
// Returns only the tenants the signed-in operator can see -- ARM's own tenant
// list, the same one the portal shows under "Manage tenants".
func (ctl *AzureOnboardController) ListTenants(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	sessionID, ok := ctl.sessionFromCookie(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": azureonboard.ErrNoSession.Error(),
			"hint":  "open /api/azure/login in a browser and complete the Microsoft sign-in first",
		})
		return
	}

	tenants, err := svc.ListTenants(c.Request.Context(), workspaceID, sessionID)
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, tenants)
}

/* --------------------------------- consent -------------------------------- */

// StartConsent handles POST /api/azure/consent.
//
// Redirects to Microsoft's admin-consent page for one tenant. AuthSec cannot
// grant consent; only an administrator of that directory can.
func (ctl *AzureOnboardController) StartConsent(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var body struct {
		TenantID string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"tenantId\": \"<guid>\"}"})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	consentURL, err := svc.StartConsent(workspaceID, actor, strings.TrimSpace(body.TenantID))
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}
	// A browser console cannot use the redirect.
	//
	// This endpoint needs a bearer token, so it cannot be reached by a plain
	// navigation; and fetch() follows a 302 automatically, which would send the
	// XHR to login.microsoftonline.com, where the absence of CORS headers fails
	// the request before the operator ever sees the consent page. Reading the
	// Location header instead does not work either: a followed redirect is
	// already consumed, and redirect:"manual" yields an opaque response whose
	// headers are unreadable.
	//
	// So a client that asks for JSON gets the URL and navigates the top-level
	// window to it itself. The 302 stays the default for form posts and for
	// anything already relying on it.
	if strings.Contains(c.GetHeader("Accept"), "application/json") {
		c.JSON(http.StatusOK, gin.H{
			"ok":          true,
			"consent_url": consentURL,
			"meta": gin.H{
				"next": "navigate the top-level window to consent_url; an administrator of " +
					"that tenant must accept the page",
				"expires_in_seconds": 900,
			},
		})
		return
	}
	c.Redirect(http.StatusFound, consentURL)
}

/* ------------------------------- validate arm ------------------------------ */

// ValidateARM handles POST /api/azure/validate-arm.
//
// Asks, app-only, whether the consented application can read Azure Resource
// Manager in this tenant. Deliberately not asked with the operator's own token:
// that would answer a different question and pass whenever the operator is
// privileged.
func (ctl *AzureOnboardController) ValidateARM(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var body struct {
		TenantID string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"tenantId\": \"<guid>\"}"})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	res, err := svc.ValidateARM(c.Request.Context(), workspaceID, strings.TrimSpace(body.TenantID))
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	// A refusal is a recorded verdict, not a transport failure: the caller asked
	// whether Reader works and got a truthful answer.
	c.JSON(http.StatusOK, gin.H{
		"ok":   res.ARMReaderOK,
		"data": res,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"hint": "assign the built-in Reader role to the AuthSec application at the " +
				"subscription or management-group scope, then re-run this check",
		},
	})
}

// ReaderSetup handles POST /api/azure/reader-setup.
//
// Returns the exact role assignment a human has to make, in the three forms
// people use: an az CLI command, a PowerShell command, and an ARM template.
// Same assignment either way, with the principal, role and scope already filled
// in, because "open IAM and find the app" is where onboarding stalls.
//
// This cannot be done for them. Entra consent and Azure RBAC are separate
// systems, and Azure offers no API by which an application grants itself a role.
func (ctl *AzureOnboardController) ReaderSetup(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var body struct {
		TenantID string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"tenantId\": \"<guid>\"}"})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	setup, err := svc.ReaderSetup(c.Request.Context(), workspaceID, strings.TrimSpace(body.TenantID))
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":   true,
		"data": setup,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "assigning this role needs Owner or User Access Administrator on the scope; " +
				"no application can grant itself an azure role",
			"next": "run one of these, then POST /api/azure/validate-arm",
		},
	})
}

// AssignReader handles POST /api/azure/assign-reader.
//
// Grants ARM Reader without the customer running a command or opening the
// portal. AuthSec makes the request on behalf of the signed-in operator, using
// their delegated token -- so it succeeds exactly when that person could have
// done it by hand, and cleanly refuses when they could not.
//
// Needs BOTH credentials: the bearer token says which workspace is asking, the
// session cookie carries the Azure sign-in the assignment is made as.
func (ctl *AzureOnboardController) AssignReader(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var body struct {
		TenantID string `json:"tenantId"`
		Scope    string `json:"scope"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"tenantId\": \"<guid>\"}"})
		return
	}
	sessionID, ok := ctl.sessionFromCookie(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": azureonboard.ErrNoSession.Error(),
			"hint":  "the assignment is made as the signed-in operator; sign in at /api/azure/login first",
		})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	tenantID := strings.TrimSpace(body.TenantID)
	res, err := svc.AssignReader(c.Request.Context(), workspaceID, sessionID,
		tenantID, strings.TrimSpace(body.Scope))
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		// A refusal is the interesting case: it records that someone attempted
		// to grant AuthSec access to a customer tenant and Azure said no.
		auditAdminMutation(c, workspaceID.String(), "azure.reader.assign.failed",
			"azure_connector", tenantID, status,
			nil, gin.H{"tenant_id": tenantID, "error": err.Error()})
		c.JSON(status, errBody)
		return
	}

	// This is the only state-changing action this feature performs inside
	// another organisation's Azure tenant. Without a record there is no answer
	// to "who granted AuthSec access to this subscription, and when".
	auditAdminMutation(c, workspaceID.String(), "azure.reader.assign",
		"azure_connector", tenantID, http.StatusOK,
		nil, gin.H{
			"tenant_id": tenantID,
			"principal": res.Assigned,
			"all_ok":    res.AllOK,
		})
	c.JSON(http.StatusOK, gin.H{
		"ok":   res.AllOK,
		"data": res,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"next":  "POST /api/azure/validate-arm to confirm the application can now read",
			"note": "granted as the signed-in operator, which requires them to hold Owner or " +
				"User Access Administrator on the scope; no application can grant itself an azure role",
		},
	})
}

// ValidateGraph handles POST /api/azure/validate-graph.
//
// The Entra counterpart to validate-arm. Consent completing is not the same as
// consent granting anything: an application that declares no permissions is
// consented successfully and holds none. This asks the token itself which
// permissions actually landed.
func (ctl *AzureOnboardController) ValidateGraph(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var body struct {
		TenantID string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"tenantId\": \"<guid>\"}"})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	res, err := svc.ValidateGraph(c.Request.Context(), workspaceID, strings.TrimSpace(body.TenantID))
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":   res.GraphOK,
		"data": res,
		"meta": gin.H{
			"as_of":    time.Now().UTC(),
			"required": azureonboard.RequiredGraphRoles(),
			"note": "permissions must be declared on the app registration as Application, not " +
				"Delegated; a delegated grant never appears in an app-only token",
		},
	})
}

// ListSubscriptions handles GET /api/azure/subscriptions?tenantId=...
//
// Per-subscription Reader coverage, which is what makes partial coverage
// visible. A tenant is only fully onboarded when every subscription reads true.
func (ctl *AzureOnboardController) ListSubscriptions(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	rows, err := svc.Subscriptions(workspaceID, strings.TrimSpace(c.Query("tenantId")))
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	readable := 0
	for _, r := range rows {
		if r.ReaderOK {
			readable++
		}
	}
	coverage := "none"
	switch {
	case len(rows) > 0 && readable == len(rows):
		coverage = "complete"
	case readable > 0:
		coverage = "partial"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rows,
		"meta": gin.H{
			"count":    len(rows),
			"readable": readable,
			"coverage": coverage,
			"as_of":    time.Now().UTC(),
			"note":     "coverage 'partial' is not an all-clear: reader is assigned per scope",
		},
	})
}

/* ------------------------------- connectors ------------------------------- */

// ListConnectors handles GET /api/azure/connectors.
func (ctl *AzureOnboardController) ListConnectors(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	rows, err := svc.Connectors(workspaceID)
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rows,
		"meta": gin.H{
			"count": len(rows),
			"as_of": time.Now().UTC(),
			"note": "onboarding is complete for a tenant when the row exists AND arm_reader_ok " +
				"is true; arm_checked_at null means the reader check has never been run",
		},
	})
}

/* --------------------------------- helpers -------------------------------- */

// requestIsHTTPS reports whether the browser reached us over TLS.
//
// Request.TLS alone is wrong behind a terminating proxy, which is the normal
// deployment: nginx or an ALB speaks TLS to the browser and plain HTTP to us,
// so the cookie carrying a live Azure sign-in would ship without Secure. Same
// test middlewares/security.go already uses to decide on HSTS.
func requestIsHTTPS(c *gin.Context) bool {
	return c.Request.TLS != nil ||
		c.GetHeader("X-Forwarded-Proto") == "https" ||
		os.Getenv("FORCE_HSTS") == "true" ||
		os.Getenv("ENVIRONMENT") == "production"
}

func (ctl *AzureOnboardController) workspaceAndActor(c *gin.Context) (uuid.UUID, string, error) {
	return workspaceAndActorFrom(c)
}

// sessionFromCookie recovers the session id the callback issued.
func (ctl *AzureOnboardController) sessionFromCookie(c *gin.Context) (string, bool) {
	raw, err := c.Cookie(azureSessionCookie)
	if err != nil || raw == "" {
		return "", false
	}
	secret := []byte(os.Getenv(azureSessionSecretEnv))
	if len(secret) == 0 {
		return "", false
	}
	return verifyAzureSession(raw, secret)
}

// signAzureSession binds a session id to this deployment.
//
// The id is already unguessable, so this is not what keeps it secret -- it is
// what stops a forged or truncated cookie value reaching the secrets-store path
// lookup at all.
func signAzureSession(sessionID string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sessionID))
	return sessionID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyAzureSession(raw string, secret []byte) (string, bool) {
	sessionID, sig, ok := strings.Cut(raw, ".")
	if !ok || sessionID == "" || sig == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sessionID))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return "", false
	}
	return sessionID, true
}

// mapAzureOnboardError turns a service error into a status and a body that says
// whose problem it is. Distinct from the cloud discovery connector's mapper:
// these are different failure modes with different operator actions.
func mapAzureOnboardError(err error) (int, gin.H) {
	switch {
	case errors.Is(err, azureonboard.ErrNotConfigured):
		return http.StatusInternalServerError, gin.H{
			"error": err.Error(),
			"hint": "set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_REDIRECT_URI on the backend; " +
				"the redirect uri must match one registered on the Entra application exactly",
			"fault": "authsec",
		}

	case errors.Is(err, azureonboard.ErrNoSession):
		return http.StatusUnauthorized, gin.H{
			"error": err.Error(),
			"hint":  "the azure sign-in has expired or was never completed; start again at /api/azure/login",
			"fault": "operator",
		}

	case errors.Is(err, repositories.ErrAzureStateInvalid):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "each redirect is single use and expires; start the step again rather than " +
				"replaying a callback url",
			"fault": "operator",
		}

	case errors.Is(err, azureonboard.ErrTenantMismatch):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "consent was requested for a different tenant than the one that answered; nothing was recorded",
			"fault": "operator",
		}

	case errors.Is(err, azureonboard.ErrConsentDenied):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint": "an administrator of that tenant must accept the consent page; " +
				"a user without the privilege cannot grant it",
			"fault": "customer_tenant",
		}

	case errors.Is(err, azureonboard.ErrAppNotInTenant):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "run POST /api/azure/consent for this tenant and complete the admin consent page first",
			"fault": "customer_tenant",
		}

	case errors.Is(err, azureonboard.ErrARMForbidden):
		return http.StatusOK, gin.H{
			"ok":    false,
			"error": err.Error(),
			"hint":  "assign the built-in Reader role to the AuthSec application in this tenant",
			"fault": "customer_tenant",
		}

	case errors.Is(err, repositories.ErrAzureConnectorNotFound):
		return http.StatusNotFound, gin.H{
			"error": "this tenant has not been consented in this workspace",
			"hint":  "POST /api/azure/consent first",
		}

	case errors.Is(err, services.ErrAzureWorkspaceAmbiguous):
		return http.StatusBadRequest, gin.H{"error": err.Error()}
	}

	var apiErr *azureonboard.APIError
	if errors.As(err, &apiErr) {
		status := http.StatusBadGateway
		if apiErr.Status == http.StatusTooManyRequests {
			status = http.StatusTooManyRequests
		}
		return status, gin.H{
			"error": apiErr.Error(),
			"fault": "azure",
		}
	}

	return http.StatusBadRequest, gin.H{"error": err.Error()}
}
