package platform

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
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

// SESSION_SECRET is an OPTIONAL override. Left unset -- which is the normal
// case -- the cookie key is derived from JWT_SECRET, which every deployment
// already has.
const azureSessionSecretEnv = "SESSION_SECRET"

// azureSessionKeyPurpose separates this key from every other use of
// JWT_SECRET. Two keys derived with different labels cannot be substituted for
// one another, so a signature valid for one is meaningless to the other -- the
// cookie key cannot mint a JWT, and the JWT key cannot forge a cookie.
const azureSessionKeyPurpose = "authsec/azure-session-cookie/v1"

// azureSessionKey is the key the Azure sign-in cookie is signed with.
//
// It used to be SESSION_SECRET alone, a variable this feature introduced and
// nothing else in the codebase reads. That made a new deployment secret to
// generate, distribute and rotate for one cookie in one feature -- and an
// operator who had done every part of the Azure setup correctly still stopped
// at the end on a variable they had never been asked for.
//
// So it is derived from JWT_SECRET instead, which is already required and
// already the deployment's signing secret. HMAC with a purpose label gives a
// key that is independent of the JWT key rather than the same bytes used
// twice. SESSION_SECRET still wins when set, for deployments that already
// configured one and for anyone who wants the two blast radii separate.
func azureSessionKey() []byte {
	if s := strings.TrimSpace(os.Getenv(azureSessionSecretEnv)); len(s) >= 32 {
		return []byte(s)
	}
	root := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if root == "" {
		// Nothing to derive from. Returning a key built from an empty secret
		// would sign cookies anyone could forge, so return none and let the
		// caller refuse to issue one.
		return nil
	}
	mac := hmac.New(sha256.New, []byte(root))
	mac.Write([]byte(azureSessionKeyPurpose))
	return mac.Sum(nil)
}

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

// serviceFor builds the onboarding service bound to one workspace's Entra
// application: the row it submitted through POST /api/azure/config if there is
// one, else the deployment-wide AZURE_* variables.
//
// Readiness is checked HERE rather than in the constructor. A deployment with no
// AZURE_* variables at all is perfectly usable by a workspace that supplied its
// own application, so "is this configured" is only answerable once the workspace
// is known.
func (ctl *AzureOnboardController) serviceFor(workspaceID uuid.UUID) (*services.AzureOnboardService, error) {
	svc, err := ctl.service()
	if err != nil {
		return nil, err
	}
	bound := svc.ForWorkspace(workspaceID)
	if err := bound.Ready(); err != nil {
		return nil, err
	}
	return bound, nil
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
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	redirectURI := strings.TrimSpace(os.Getenv("AZURE_REDIRECT_URI"))
	secretSet := strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET")) != ""
	// No environment fallback for the home tenant: it belongs to a specific
	// application, so it lives beside the client id it describes, in the stored
	// row, where the two cannot drift apart.
	homeTenant := ""
	source := "environment"

	// A workspace that submitted its own application overrides all of the above,
	// and the checklist must describe what will ACTUALLY be used -- otherwise a
	// correctly configured workspace reads as broken because the deployment has
	// no env vars.
	var stored *models.AzureAppConfig
	problem, certPEM, certThumb := "", "", ""
	// Set when the row itself could not be read. Distinct from "there is no
	// row": this used to discard the error and answer with the environment
	// checklist, telling an operator to set AZURE_* variables because Postgres
	// was unreachable.
	readError := ""
	if svc, sErr := ctl.service(); sErr == nil {
		cfg, cErr := svc.GetAppConfig(workspaceID)
		if cErr != nil {
			readError = cErr.Error()
		}
		if cErr == nil && cfg != nil {
			stored = cfg
			clientID, redirectURI, homeTenant = cfg.ClientID, cfg.RedirectURI, cfg.HomeTenant
			source = "workspace"

			// Whether the secret is READABLE, not whether a row exists.
			//
			// This used to assume the two were the same -- "the row cannot exist
			// without a secret written first" -- which is true when the row is
			// written and false ever after. A secrets store restored from an
			// older backup than the database, or a development store that keeps
			// nothing across a restart, leaves the row pointing at a path that
			// holds nothing. Reporting "configured, secret set" then sends an
			// operator looking at everything except the one thing that is wrong.
			if rErr := svc.ForWorkspace(workspaceID).Ready(); rErr != nil {
				problem = rErr.Error()
			} else {
				secretSet = true
			}
			// The PUBLIC certificate, so the console can always offer it.
			// Offering it only once left an operator who closed the page with
			// no way back except generating again -- which replaces the key and
			// orphans whatever they had already uploaded.
			certPEM, certThumb = svc.CurrentCertificatePEM(workspaceID)
		}
	}
	sessionSet := len(azureSessionKey()) > 0
	vaultSet := os.Getenv("VAULT_ADDR") != "" && os.Getenv("VAULT_TOKEN") != ""

	missing := []string{}
	if clientID == "" {
		missing = append(missing, "client id")
	}
	if !secretSet {
		missing = append(missing, "client secret")
	}
	if redirectURI == "" {
		missing = append(missing, "redirect uri")
	}
	if !sessionSet {
		missing = append(missing, "JWT_SECRET (or SESSION_SECRET, 32+ chars)")
	}
	if !vaultSet {
		missing = append(missing, "VAULT_ADDR/VAULT_TOKEN")
	}

	c.JSON(http.StatusOK, gin.H{
		// A row that could not be read is not a ready workspace, whatever the
		// environment happens to hold.
		"ready": len(missing) == 0 && readError == "",
		"data": gin.H{
			// Public values, echoed so a setup screen can compare them against
			// the Entra application.
			"client_id":    clientID,
			"redirect_uri": redirectURI,
			"home_tenant":  homeTenant,

			// Which of the two sources these values came from, so a setup
			// screen can say "this workspace has its own app" rather than
			// leaving an operator to guess why editing .env changed nothing.
			"source":     source,
			"configured": stored != nil,
			"checked_at": func() interface{} {
				if stored != nil && stored.CheckedAt != nil {
					return stored.CheckedAt
				}
				return nil
			}(),
			"signin_tenant":  azureonboard.SignInTenant,
			"authority_host": azureonboard.AuthorityBase,
			"arm_endpoint":   azureonboard.ARMBase,

			// Presence only. The values are never serialised.
			"client_secret_set":  secretSet,
			"session_secret_set": sessionSet,
			"vault_configured":   vaultSet,

			"missing": missing,

			// Set only when a STORED application exists and cannot be used, so
			// a setup screen can say what is actually wrong instead of listing
			// environment variables this workspace was never meant to set.
			//
			// Named credential_problem, not problem: an error body's "problem"
			// is a Diagnosis object, and one key holding two shapes is how a
			// client ends up rendering "[object Object]".
			"credential_problem": problem,

			// Set only when the stored application could not be READ. Without
			// it an unreachable database is indistinguishable from a workspace
			// that never configured anything.
			"config_read_error": readError,

			// The certificate in use, when there is one. Public: it verifies a
			// signature and cannot make one. Empty for a client secret, and
			// there is no equivalent for one -- a secret cannot be handed back.
			"certificate_pem": certPEM,

			// Uppercase hex, the form the portal shows and AADSTS700027 quotes.
			// With both on screen the mismatch that error describes is one
			// glance to confirm.
			"certificate_thumbprint": certThumb,
		},
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "secret values are never returned; only whether they are set. " +
				"redirect_uri must match a uri registered on the entra application exactly",
			"required_graph_permissions": azureonboard.RequiredGraphRoles(),
		},
	})
}

// SetAppConfig handles POST /api/azure/config.
//
// The first step of onboarding: someone creates an App Registration in the Azure
// portal and hands AuthSec its details. This stores them and, in the same call,
// asks Microsoft whether that application actually has what onboarding needs --
// answering the only question that matters before anything else is attempted.
//
// It answers 200 even when the registration is wrong, and that is deliberate.
// "Stored, and here is exactly what is missing and how to grant it" is a
// different outcome from "rejected", and an operator fixing four permissions in
// the portal needs the list, not an error. `ok` says whether the application is
// usable; `check.findings` says what to do about it.
//
// The secret is written to Vault and never returned, never logged, and never
// stored in Postgres -- the row keeps only the path.
func (ctl *AzureOnboardController) SetAppConfig(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var in services.AzureAppConfigInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "body must be {\"clientId\", \"homeTenant\", \"redirectUri\"} plus EITHER " +
				"\"generateCertificate\": true OR \"clientSecret\"",
			"hint": "clientId and homeTenant are the Application (client) ID and Directory " +
				"(tenant) ID from the app registration Overview page. generateCertificate is " +
				"preferred: AuthSec makes the key pair, keeps the private key, and returns the " +
				"certificate for you to upload -- so the key is never sent anywhere",
		})
		return
	}

	// Unbound: this endpoint SUPPLIES the configuration, so it cannot require it.
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	res, err := svc.SetAppConfig(c.Request.Context(), workspaceID, actor, in)
	if err != nil {
		auditAdminMutation(c, workspaceID.String(), "azure.app.config.failed",
			"azure_app_config", workspaceID.String(), http.StatusBadRequest,
			nil, gin.H{"error": err.Error()})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Recorded because it changes which Entra application this workspace acts
	// as. The secret is not in the payload and never will be -- only the fact.
	auditAdminMutation(c, workspaceID.String(), "azure.app.config",
		"azure_app_config", workspaceID.String(), http.StatusOK,
		nil, gin.H{"client_id": res.Stored.ClientID, "home_tenant": res.Stored.HomeTenant})

	ok := res.Check != nil && res.Check.OK
	c.JSON(http.StatusOK, gin.H{
		"ok":   ok,
		"data": res,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "the credential -- secret or private key -- is stored in vault and is never " +
				"returned by any endpoint. certificate_pem, when present, is the PUBLIC " +
				"certificate to upload to Microsoft. stored=true with ok=false means the " +
				"application was saved but is not usable yet",
			"next": nextForAppConfig(res),
		},
	})
}

// nextForAppConfig turns the verdict into the one thing to do next.
func nextForAppConfig(res *services.AzureAppConfigResult) string {
	switch {
	case res.CheckError != "":
		// The diagnosis when there is one -- "check the client id and the
		// secret" is actively wrong for a 403, where both are correct and the
		// missing thing is admin consent.
		if res.CheckProblem != nil {
			return res.CheckProblem.Fix
		}
		return "the application could not be read at all: check the client id, the credential, " +
			"and that homeTenant is the directory the registration was created in"
	case res.CertificatePEM != "":
		// The key pair exists and Microsoft has not seen the public half yet, so
		// every check below would fail for that one reason. Say the one thing
		// that unblocks it.
		return "download certificate_pem and upload it: portal -> your app -> " +
			"Certificates & secrets -> Certificates -> Upload certificate. Then " +
			"GET /api/azure/app/check. Until then the application cannot authenticate, " +
			"because Microsoft has no public key to verify its signature against"
	case res.Check == nil:
		return "stored, but not verified"
	case len(res.Check.MissingPermissions) > 0:
		return "grant these as APPLICATION permissions (not delegated) in portal -> API permissions " +
			"-> Microsoft Graph -> Application permissions, then Grant admin consent: " +
			strings.Join(res.Check.MissingPermissions, ", ")
	case len(res.Check.MissingARMScopes) > 0:
		// A different API and a different permission type, so a different path.
		// Sending someone to Microsoft Graph for these is what the merged field
		// used to do, and user_impersonation is not there to be found.
		return "declare these as DELEGATED permissions in portal -> API permissions -> " +
			"Add a permission -> APIs my organization uses -> Azure Service Management -> " +
			"Delegated permissions, then Grant admin consent: " +
			strings.Join(res.Check.MissingARMScopes, ", ")
	case !res.Check.OK:
		return "fix the errors in check.findings, then POST this again or GET /api/azure/app/check"
	default:
		return "GET /api/azure/login to sign in and start onboarding tenants"
	}
}

// CheckAppRegistration handles GET /api/azure/app/check.
//
// Asserts that the App Registration matches what this code requires. Read-only:
// it reports and never repairs, so it cannot itself become a way to repoint the
// product at a different application.
//
// Serves BOTH setup paths. Whether the registration was created by hand in the
// portal or by an automated bootstrap, this is the single assertion that says
// the end state is right -- and it checks by machine every field the runbook
// currently asks a human to verify by eye.
func (ctl *AzureOnboardController) CheckAppRegistration(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	svc, err := ctl.serviceFor(workspaceID)
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	res, err := svc.CheckAppRegistration(c.Request.Context())
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":   res.OK,
		"data": res,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "needs only Application.Read.All, which discovery already requires; " +
				"no write access is used or requested",
			"severity": "an 'error' finding blocks onboarding; a 'warning' does not",
		},
	})
}

// ResolveSignInName handles POST /api/azure/signin-name.
//
// Turns "my email is X" into "type Y at the sign-in page", which for an
// externally backed account are different strings. Read-only, and it returns a
// username -- not a credential, not a token, nothing that grants anything.
//
// It exists because the alternative is a dead end. Microsoft rejects the real
// address at a directory sign-in, says only "use your work or school account",
// and there is no way for the person to discover the rewritten name it would
// have accepted. It is not shown at sign-up, not in any mail, and not anywhere
// they would look.
func (ctl *AzureOnboardController) ResolveSignInName(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var body struct {
		TenantID string `json:"tenantId"`
		Email    string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "body must be {\"tenantId\": \"<guid>\", \"email\": \"you@example.com\"}"})
		return
	}
	svc, err := ctl.serviceFor(workspaceID)
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	res, err := svc.ResolveSignInName(c.Request.Context(),
		strings.TrimSpace(body.TenantID), strings.TrimSpace(body.Email))
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":   true,
		"data": res,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "sign in at /api/azure/login?tenant=<tenantId>&login_hint=<user_principal_name>. " +
				"mangled=true means the address differs from the directory name, which is why " +
				"typing the address itself fails",
			"limit": "needs the application to be consented in this tenant already, because the " +
				"lookup uses an app-only Graph token",
		},
	})
}

/* ---------------------------------- login --------------------------------- */

// Login handles GET /api/azure/login.
//
// Redirects the operator to Microsoft to sign in with their own Azure work
// account. Nothing is stored until they come back.
func (ctl *AzureOnboardController) Login(c *gin.Context) {
	// Unbound on purpose: resolving which workspace this sign-in belongs to
	// needs only the database, and the workspace is not known until it returns.
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardErrorPublic(c, err)
		c.JSON(status, body)
		return
	}

	workspaceID, err := svc.ResolveLoginWorkspace(c.Query("workspace_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Rebind: the authorize URL must carry THIS workspace's client id and
	// redirect uri, and the code that comes back is redeemable only by the
	// application that issued it.
	if svc, err = ctl.serviceFor(workspaceID); err != nil {
		status, body := mapAzureOnboardErrorPublic(c, err)
		c.JSON(status, body)
		return
	}

	// There is no admin_consent parameter, and there never usefully was one.
	//
	// It used to set prompt=admin_consent on the authorize URL, and Microsoft
	// rejects that value on the v2.0 endpoint outright -- AADSTS901001, before a
	// password is typed. Admin consent is a separate Microsoft screen; POST
	// /api/azure/auto-setup chains the two for the operator, and POST
	// /api/azure/consent does one tenant on its own.
	//
	// login_hint decides which identity Entra resolves before anyone types.
	// pick_account forces the picker -- opt-in, because forcing it replaces
	// working single sign-on with a blank username box, and for an externally
	// backed account the name that box needs is one nobody knows.
	//
	// The autoSetup argument is hard-coded false and there is no query parameter
	// for it. This route is a browser navigation with no bearer token, and the
	// auto-setup path WRITES an azure_connectors row -- so a query parameter
	// here would let anyone who can reach this deployment sign in with a tenant
	// of their choosing and file it into a workspace they have no rights to.
	// POST /api/azure/auto-setup mints that state instead, behind
	// discovery:admin.
	authorizeURL, err := svc.StartLogin(workspaceID, "browser", false, false,
		strings.TrimSpace(c.Query("tenant")),
		strings.TrimSpace(c.Query("login_hint")),
		strings.EqualFold(strings.TrimSpace(c.Query("pick_account")), "true"))
	if err != nil {
		status, body := mapAzureOnboardErrorPublic(c, err)
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
		status, body := mapAzureOnboardErrorPublic(c, err)
		c.JSON(status, body)
		return
	}

	// Bind to the workspace this redirect was started for, BEFORE redeeming the
	// state. Microsoft will only exchange the code for the application that
	// issued it, so a callback authenticating with a different workspace's
	// application fails with an opaque invalid_client. Peeking grants nothing:
	// the state is still redeemed exactly once, atomically, inside
	// HandleCallback.
	//
	// FAILING TO BIND IS FATAL HERE, and must not fall through to the unbound
	// service. That fallback crashed the process: with no AZURE_* variables --
	// now a supported deployment, because the application arrives through
	// POST /api/azure/config -- the unbound service holds a nil Microsoft client,
	// and the code exchange dereferenced it. This route is unauthenticated by
	// necessity, so a nil dereference here is a remote unauthenticated crash.
	ws, wErr := svc.PeekCallbackWorkspace(c.Query("state"))
	if wErr != nil {
		status, body := mapAzureOnboardErrorPublic(c, wErr)
		c.JSON(status, body)
		return
	}
	bound, bErr := ctl.serviceFor(ws)
	if bErr != nil {
		status, body := mapAzureOnboardErrorPublic(c, bErr)
		c.JSON(status, body)
		return
	}
	svc = bound

	res, err := svc.HandleCallback(c.Request.Context(), services.AzureCallbackInput{
		Code:             c.Query("code"),
		State:            c.Query("state"),
		Tenant:           c.Query("tenant"),
		AdminConsent:     c.Query("admin_consent"),
		Error:            c.Query("error"),
		ErrorDescription: c.Query("error_description"),
	})
	if err != nil {
		status, body := mapAzureOnboardErrorPublic(c, err)
		c.JSON(status, body)
		return
	}

	if res.Step == "logged_in" {
		secret := azureSessionKey()
		if len(secret) == 0 {
			// The token is already stored; without a way to hand the operator a
			// tamper-evident handle it cannot be used, so say so rather than
			// issuing an unprotected cookie.
			svc.EndSession(res.WorkspaceID, res.SessionID)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "neither JWT_SECRET nor SESSION_SECRET is configured on this " +
					"deployment, so the sign-in cookie cannot be signed",
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
		// First leg of an automatic setup: send the browser straight on to the
		// consent screen. The cookie is already set above, which matters -- the
		// second callback needs it to find the session the chain will run with.
		//
		// A redirect rather than an answer because there is nothing useful to
		// answer yet: the operator asked for the whole thing, and stopping here
		// to make them click again in the console would be the manual flow with
		// extra steps.
		if res.ConsentRedirect != "" {
			c.Redirect(http.StatusFound, res.ConsentRedirect)
			return
		}

		out := gin.H{"ok": true, "step": "logged_in"}
		if res.AutoSetupSkipped != "" {
			// The sign-in asked for the whole chain and did not get it. Saying
			// why here is the difference between a console that explains itself
			// and one that appears to have done nothing.
			out["setup"] = "skipped"
			out["reason"] = res.AutoSetupSkipped
			out["meta"] = gin.H{
				"next": "continue manually: GET /api/azure/tenants, then POST /api/azure/consent",
			}
		}
		c.JSON(http.StatusOK, out)
		return
	}

	out := gin.H{
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
	}

	// Second leg of an automatic setup. Started here rather than in the service
	// because the chain needs the sign-in session id, and the cookie carrying it
	// is only readable from a request.
	if res.AutoSetupWanted {
		switch sessionID, ok := ctl.sessionFromCookie(c); {
		case !ok:
			out["setup"] = "skipped"
			out["reason"] = "the sign-in session cookie did not come back with this redirect"
		case svc.StartAutoSetup(res.WorkspaceID, sessionID, res.Connector.TenantID, res.AutoSetupWide):
			out["setup"] = "running"
			meta := gin.H{
				"next": "poll GET /api/azure/setup-status until state is done or failed",
			}
			if res.AutoSetupWide {
				meta["reader_scope"] = "the tenant root management group, which covers " +
					"subscriptions created later"
				meta["note"] = "reaching that scope can briefly raise your own account to root " +
					"User Access Administrator. It is given back in the same run; the setup " +
					"status reports whether that succeeded, because it does not expire on its own"
			}
			out["meta"] = meta
		default:
			out["setup"] = "skipped"
			out["reason"] = "a setup run is already in progress for this session"
		}
	}
	c.JSON(http.StatusOK, out)
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
	svc, err := ctl.serviceFor(workspaceID)
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
	svc, err := ctl.serviceFor(workspaceID)
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
	svc, err := ctl.serviceFor(workspaceID)
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
	svc, err := ctl.serviceFor(workspaceID)
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

		// TenantWide asks for one grant at the root management group instead of
		// one per subscription, so subscriptions created later are covered too.
		//
		// Opt-in, and it must stay opt-in: reaching that scope can require
		// briefly raising the operator's own privilege to root User Access
		// Administrator. Nobody should discover that happened by reading the
		// response.
		TenantWide bool `json:"tenantWide"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"tenantId\": \"<guid>\"}"})
		return
	}
	if body.TenantWide && strings.TrimSpace(body.Scope) != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "tenantWide and scope are mutually exclusive",
			"hint": "tenantWide targets the tenant root management group; " +
				"pass scope only to target one subscription or management group",
		})
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
	svc, err := ctl.serviceFor(workspaceID)
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	tenantID := strings.TrimSpace(body.TenantID)
	res, err := svc.AssignReader(c.Request.Context(), workspaceID, sessionID,
		tenantID, strings.TrimSpace(body.Scope), body.TenantWide)
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
	// Elevation is recorded separately and unconditionally. A temporary raise to
	// root User Access Administrator is the single most privileged thing this
	// feature can do inside a customer tenant, and "was it given back" is the
	// question an auditor will ask first.
	auditAdminMutation(c, workspaceID.String(), "azure.reader.assign",
		"azure_connector", tenantID, http.StatusOK,
		nil, gin.H{
			"tenant_id":   tenantID,
			"principal":   res.Assigned,
			"all_ok":      res.AllOK,
			"tenant_wide": res.TenantWide,
			"elevation":   res.Elevation,
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
	svc, err := ctl.serviceFor(workspaceID)
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

// AvailableSubscriptions handles GET /api/azure/available-subscriptions.
//
// The subscriptions the signed-in OPERATOR can see, so a console can offer the
// choice of which to grant Reader on. Needs the session cookie: this is the
// operator's view of ARM, not the application's.
//
// It exists because the only subscription list the product held was the one in
// azure_subscriptions -- which is populated by validate-arm, which needs Reader,
// which is the very thing the choice is meant to scope. The choice could not be
// offered before the grant it applies to.
//
// read, not admin. It grants nothing and writes nothing; it reports what the
// person can already see in their own portal.
func (ctl *AzureOnboardController) AvailableSubscriptions(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sessionID, ok := ctl.sessionFromCookie(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": azureonboard.ErrNoSession.Error(),
			"hint":  "this is the operator's own view of ARM; sign in at /api/azure/login first",
		})
		return
	}
	svc, err := ctl.serviceFor(workspaceID)
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}

	subs, err := svc.AvailableSubscriptions(c.Request.Context(), workspaceID, sessionID,
		strings.TrimSpace(c.Query("tenantId")))
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":   true,
		"data": subs,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "what the SIGNED-IN OPERATOR can see, live from ARM. Pass one as " +
				"scope=/subscriptions/<id> to POST /api/azure/assign-reader to grant Reader " +
				"on just that one",
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
	svc, err := ctl.serviceFor(workspaceID)
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
	svc, err := ctl.serviceFor(workspaceID)
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
	secret := azureSessionKey()
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
// mapAzureOnboardErrorPublic is mapAzureOnboardError for the two routes that
// have no bearer token: /api/azure/login and /api/azure/callback.
//
// The configuration errors are deliberately detailed -- they name the vault
// path and carry the secrets-store error verbatim, because that is what makes
// a broken workspace debuggable from the console. None of it belongs in a
// response anyone on the network can ask for. The detail goes to the log; the
// caller gets the fact.
func mapAzureOnboardErrorPublic(c *gin.Context, err error) (int, gin.H) {
	status, body := mapAzureOnboardError(err)
	if errors.Is(err, azureonboard.ErrNotConfigured) {
		log.Printf("azure: unauthenticated request to %s could not be served: %v",
			c.Request.URL.Path, err)
		return status, gin.H{
			"error": "azure onboarding is not configured for this workspace",
			"hint": "an administrator can see what is wrong at GET /api/azure/config, " +
				"which requires a bearer token",
			"fault": "authsec",
		}
	}
	return status, body
}

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
			"ok":      false,
			"error":   err.Error(),
			"hint":    "assign the built-in Reader role to the AuthSec application in this tenant",
			"fault":   "customer_tenant",
			"problem": azureonboard.DiagnoseARMForbidden(),
		}

	case errors.Is(err, repositories.ErrAzureConnectorNotFound):
		return http.StatusNotFound, gin.H{
			"error": "this tenant has not been consented in this workspace",
			"hint":  "POST /api/azure/consent first",
		}

	case errors.Is(err, services.ErrAzureWorkspaceAmbiguous):
		return http.StatusBadRequest, gin.H{"error": err.Error()}
	}

	// Named where it can be. A 401 and a 403 from Microsoft read almost alike
	// and are fixed in different blades of the portal, so handing back the raw
	// string alone is how an operator ends up regenerating a credential that
	// was working.
	diag := azureonboard.Diagnose(err)

	var apiErr *azureonboard.APIError
	if errors.As(err, &apiErr) {
		status := http.StatusBadGateway
		if apiErr.Status == http.StatusTooManyRequests {
			status = http.StatusTooManyRequests
		}
		body := gin.H{
			"error": apiErr.Error(),
			"fault": "azure",
		}
		if diag != nil {
			body["problem"] = diag
			body["hint"] = diag.Fix
			// Whose problem it is, when the diagnosis knows better than
			// "azure" -- a missing consent is not Microsoft misbehaving.
			body["fault"] = diag.Fault
		}
		return status, body
	}

	body := gin.H{"error": err.Error()}
	if diag != nil {
		body["problem"] = diag
		body["hint"] = diag.Fix
		body["fault"] = diag.Fault
		return http.StatusBadRequest, body
	}

	// An unclassified error is not automatically the caller's fault, and
	// answering every one of them 400 said it was. A Postgres outage, a Vault
	// that will not answer, a certificate that no longer parses -- all reported
	// as "bad request", which sends whoever is on call to look at the client.
	// Nothing here is retryable by changing the request.
	if isInfrastructureFailure(err) {
		body["fault"] = "authsec"
		body["hint"] = "this is a failure inside the deployment, not in the request; " +
			"check the database and the secrets store"
		return http.StatusInternalServerError, body
	}
	return http.StatusBadRequest, body
}

// isInfrastructureFailure reports whether an error is the deployment's own.
//
// Matched on the sentinel where there is one and on the driver's text where
// there is not -- gorm and the vault client do not export errors for most of
// what goes wrong, and a wrong status code is worse than an imperfect match.
func isInfrastructureFailure(err error) bool {
	if errors.Is(err, gorm.ErrInvalidDB) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"connection refused", "connection reset", "no such host", "i/o timeout",
		"broken pipe", "server closed the connection", "driver: bad connection",
		"vault", "secrets store", "sql:", "pq:", "dial tcp",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

/* ------------------------------- auto setup ------------------------------- */

// StartAutoSetup handles POST /api/azure/auto-setup.
//
// Returns the one sign-in URL that does everything: the administrator signs in,
// grants admin consent on the same Microsoft screen, and the callback then reads
// the tenant, assigns Reader across its subscriptions and verifies both planes
// in the background.
//
// It exists as an authenticated endpoint rather than a flag on /login because
// completing it writes an azure_connectors row. Every other write in this
// controller is behind discovery:admin, and this one is no different -- see the
// note in Login.
//
// It is not a replacement for the step-by-step routes. This path assumes ONE
// person holds both privileges the flow needs -- Global Administrator to
// consent, Owner or User Access Administrator to assign Reader -- in the tenant
// they are signing in to. That is the on-prem case. When those are different
// people, or the operator is onboarding a tenant they do not administer, the
// separate endpoints are the only thing that works.
func (ctl *AzureOnboardController) StartAutoSetup(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	// All optional. tenant pins the sign-in authority, which is what an
	// externally backed account needs; login_hint decides which identity Entra
	// resolves before anyone types.
	var body struct {
		Tenant      string `json:"tenant"`
		LoginHint   string `json:"login_hint"`
		PickAccount bool   `json:"pick_account"`

		// TenantWide asks for ONE Reader grant at the tenant root management
		// group instead of one per subscription, so subscriptions created later
		// are covered without anyone coming back.
		//
		// Opt-in, and it must stay opt-in: reaching that scope can require
		// briefly raising the operator's own privilege to root User Access
		// Administrator. That is a reasonable thing to do when a person asks for
		// it and an indefensible thing to infer. The raise is reported in the
		// setup status whether or not it happened.
		TenantWide bool `json:"tenant_wide"`
	}
	_ = c.ShouldBindJSON(&body)

	svc, err := ctl.serviceFor(workspaceID)
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}

	loginURL, err := svc.StartLogin(workspaceID, actor, true, body.TenantWide,
		strings.TrimSpace(body.Tenant), strings.TrimSpace(body.LoginHint), body.PickAccount)
	if err != nil {
		status, errBody := mapAzureOnboardError(err)
		c.JSON(status, errBody)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":        true,
		"login_url": loginURL,
		"meta": gin.H{
			"next": "navigate the top-level window to login_url, then poll " +
				"GET /api/azure/setup-status",
			"requires": "the signer must be a Global Administrator of the tenant " +
				"(to consent) and Owner or User Access Administrator (to assign Reader)",
			"expires_in_seconds": 900,
		},
	})
}

// SetupStatus handles GET /api/azure/setup-status.
//
// Progress of the background chain for the caller's own sign-in session.
//
// 404 means this process has no run for that session: it finished long enough
// ago to be swept, the sign-in never asked for one, or -- behind more than one
// replica -- the poll landed on an instance that did not run it. In all three
// cases GET /api/azure/connectors is the durable answer, and the response says
// so rather than leaving a console to guess.
func (ctl *AzureOnboardController) SetupStatus(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	svc, err := ctl.serviceFor(workspaceID)
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	sessionID, ok := ctl.sessionFromCookie(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": azureonboard.ErrNoSession.Error(),
			"hint":  "complete the Microsoft sign-in first",
		})
		return
	}

	status, found := svc.SetupStatus(sessionID)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "no setup run is recorded for this session",
			"hint":  "read GET /api/azure/connectors for the stored result",
		})
		return
	}
	c.JSON(http.StatusOK, status)
}

// DeleteAppConfig handles DELETE /api/azure/config.
//
// Removes the workspace's stored Entra application and the client secret it
// points at. Without this there is no way to take an application back out: POST
// replaces one, so a workspace that submitted the wrong registration -- or is
// being offboarded -- is stuck with it.
//
// The secret goes first, in the service, because a row without its secret is
// recoverable (re-submit) and a secret without its row is an orphan nobody will
// ever clean up.
//
// It does NOT touch azure_connectors. Those record that customer tenants granted
// consent, which remains true whichever application this workspace uses next,
// and deleting them here would quietly discard the record of a grant that still
// exists in Microsoft.
func (ctl *AzureOnboardController) DeleteAppConfig(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	// ctl.service(), not serviceFor(): serviceFor checks Ready(), and a
	// configuration broken enough to fail that check is exactly the one an
	// operator most needs to be able to delete.
	svc, err := ctl.service()
	if err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	if err := svc.DeleteAppConfig(workspaceID); err != nil {
		status, body := mapAzureOnboardError(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"meta": gin.H{
			"note": "the stored application and its credential are gone. This workspace now falls " +
				"back to the deployment-wide AZURE_* variables, if any are set",
			"next": "POST /api/azure/config to submit a different application",
		},
	})
}
