package platform

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudGCPOAuthController is the Google Authentication onboarding option:
// a human's one-time Google sign-in, used ONLY to auto-provision the same
// Workload Identity Federation resources CloudGCPController's manual
// Cloud-Shell script flow creates, then handed off to the existing,
// unmodified onboarding path (services.GCPOnboardingService.Onboard).
//
// Deliberately a SEPARATE file and controller from cloud_gcp_controller.go
// (not edits to it) -- the existing WIF and JSON-key onboarding surface is
// untouched by this feature. WIF stays available as its own, independent
// option; this controller is purely additive.
type CloudGCPOAuthController struct {
	db *gorm.DB
}

// NewCloudGCPOAuthController constructs the controller.
func NewCloudGCPOAuthController(db *gorm.DB) *CloudGCPOAuthController {
	return &CloudGCPOAuthController{db: db}
}

// service builds the OAuth provisioning service. Mirrors
// CloudGCPController.service()'s Vault/issuer construction exactly (same
// env vars, same issuer resolution), so a connector this option provisions
// resolves to the identical WIF issuer the manual flow would use, and adds
// the Redis client and the GCP_OAUTH_* client credentials this option alone
// needs. A deployment missing Redis or the OAuth client env vars still has
// a fully working WIF/JSON-key onboarding surface -- see
// services.GCPOAuthProvisionService.Available.
func (ctl *CloudGCPOAuthController) service() *services.GCPOAuthProvisionService {
	var vc vault.VaultClient
	if addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"); addr != "" && token != "" {
		if c, err := vault.NewClient(addr, token); err == nil {
			vc = c
		}
	}
	appIssuerURL := ""
	if config.AppConfig != nil {
		appIssuerURL = config.AppConfig.OAuthBaseURL()
	}
	issuerURL := gcp.ResolveWIFIssuerURL(appIssuerURL)
	issuer := tokens.NewNativeIssuer(ctl.db, tokens.NativeKeys(), issuerURL)
	onboardSvc := services.NewGCPOnboardingService(ctl.db, vc, issuer)

	redisClient := config.GetRedisClient()
	clientID := strings.TrimSpace(os.Getenv("GCP_OAUTH_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GCP_OAUTH_CLIENT_SECRET"))
	redirectURI := strings.TrimSpace(os.Getenv("GCP_OAUTH_REDIRECT_URI"))

	return services.NewGCPOAuthProvisionService(ctl.db, redisClient, onboardSvc, clientID, clientSecret, redirectURI, issuerURL)
}

func (ctl *CloudGCPOAuthController) workspaceAndActor(c *gin.Context) (uuid.UUID, string, error) {
	return workspaceAndActorFrom(c)
}

/* ----------------------------------- status ------------------------------- */

// GoogleOAuthStatus handles GET /authsec/discovery/gcp/google-oauth/status.
// Lets the frontend hide/disable the "Google Authentication" card cleanly
// when Redis or the OAuth client isn't configured, instead of starting a
// flow that would fail at the callback.
func (ctl *CloudGCPOAuthController) GoogleOAuthStatus(c *gin.Context) {
	available := ctl.service().Available(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"available": available})
}

/* ----------------------------------- start -------------------------------- */

// StartGoogleOAuth handles POST /authsec/discovery/gcp/google-oauth/start.
//
// Takes no request body: per the approved UX, the human signs in with
// Google BEFORE picking a project (ListGoogleProjects, after this
// completes), so no scope is known yet at this point.
func (ctl *CloudGCPOAuthController) StartGoogleOAuth(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	authorizeURL, state, err := ctl.service().Start(c.Request.Context(), workspaceID, actor)
	if err != nil {
		status, body := mapGoogleOAuthError(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authorize_url": authorizeURL,
		"state":         state,
	})
}

/* ---------------------------------- callback ------------------------------- */

// GoogleOAuthCallback handles GET /discovery/gcp/google-oauth/callback.
//
// UNAUTHENTICATED by necessity: Google redirects the bare browser here,
// carrying no AuthSec session. This handler does ONLY what an unauthenticated,
// provider-redirected endpoint should: validate state, exchange the code,
// mint a short-lived opaque session id, and send the browser back into the
// authenticated SPA with that id (never the access token) in the query
// string. It performs NO provisioning and returns no workspace data --
// every later step (ListGoogleProjects/PreflightGoogleOAuth/
// ProvisionGoogleOAuth) is authenticated and re-checks that the session
// belongs to the caller's own workspace before doing anything.
//
// Registered directly on the ROOT engine in routes.go (r.GET(...)), NOT on
// the `authsec` group and NOT inside the authenticated `discovery` group --
// two distinct reasons, not one: (1) a route here must not sit behind
// AuthMiddleware, the same reason AuthSec's existing connector-broker OAuth
// callback (authsec.GET("/connector-oauth/callback", ...)) is placed outside
// its own authenticated group; and (2) unlike that sibling callback, this
// one must ALSO sit outside the "/authsec" path prefix entirely, because
// GCP_OAUTH_REDIRECT_URI -- the exact URI registered with Google and read
// from this deployment's .env -- is configured as the bare
// "/discovery/gcp/google-oauth/callback", with no "/authsec" segment. Google
// redirects back to exactly that path after consent, so the handler must be
// reachable there or the browser 404s on return (live-confirmed: it did,
// until this was corrected). Also does not collide with a `:id`-shaped
// sibling in Gin's routing tree (/gcp/connectors/:id).
func (ctl *CloudGCPOAuthController) GoogleOAuthCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	oauthErr := c.Query("error")

	redirectTo := func(query url.Values) string {
		if config.AppConfig != nil {
			if u := config.AppConfig.BuildUIRouteURL("/discovery/cloud/gcp/google-oauth/callback", query); u != "" {
				return u
			}
		}
		return "/discovery/cloud/gcp/google-oauth/callback?" + query.Encode()
	}

	if oauthErr != "" {
		q := url.Values{"error": {"google_denied"}}
		c.Redirect(http.StatusFound, redirectTo(q))
		return
	}
	if code == "" || state == "" {
		q := url.Values{"error": {"missing_code_or_state"}}
		c.Redirect(http.StatusFound, redirectTo(q))
		return
	}

	sessionID, err := ctl.service().HandleCallback(c.Request.Context(), code, state)
	if err != nil {
		q := url.Values{"error": {"exchange_failed"}}
		c.Redirect(http.StatusFound, redirectTo(q))
		return
	}

	q := url.Values{"session_id": {sessionID}}
	c.Redirect(http.StatusFound, redirectTo(q))
}

/* ---------------------------------- projects -------------------------------- */

// ListGoogleProjects handles GET /authsec/discovery/gcp/google-oauth/projects.
func (ctl *CloudGCPOAuthController) ListGoogleProjects(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sessionID := strings.TrimSpace(c.Query("session_id"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}

	projects, err := ctl.service().ListProjects(c.Request.Context(), sessionID, workspaceID)
	if err != nil {
		status, body := mapGoogleOAuthError(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": projects,
		"meta": gin.H{"as_of": time.Now().UTC(), "count": len(projects)},
	})
}

/* --------------------------------- preflight -------------------------------- */

type preflightGoogleOAuthRequest struct {
	SessionID       string `json:"session_id"`
	ScopeKind       string `json:"scope_kind"`
	ScopeID         string `json:"scope_id"`
	ReaderProjectID string `json:"reader_project_id"`
}

// PreflightGoogleOAuth handles POST /authsec/discovery/gcp/google-oauth/preflight.
//
// Runs testIamPermissions for the just-picked project and returns which
// permissions (if any) are missing, WITHOUT provisioning anything -- lets
// the frontend show a clean "automatic setup isn't available, use the
// existing WIF flow instead" state before the user ever clicks a final
// "Connect" button.
func (ctl *CloudGCPOAuthController) PreflightGoogleOAuth(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req preflightGoogleOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	missing, err := ctl.service().Preflight(c.Request.Context(), strings.TrimSpace(req.SessionID), workspaceID, services.GoogleScope{
		ScopeKind:       req.ScopeKind,
		ScopeID:         req.ScopeID,
		ReaderProjectID: req.ReaderProjectID,
	})
	if err != nil {
		status, body := mapGoogleOAuthError(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sufficient":          len(missing) == 0,
		"missing_permissions": missing,
	})
}

/* --------------------------------- provision -------------------------------- */

type provisionGoogleOAuthRequest struct {
	SessionID       string `json:"session_id"`
	ScopeKind       string `json:"scope_kind"`
	ScopeID         string `json:"scope_id"`
	ReaderProjectID string `json:"reader_project_id"`
	DisplayName     string `json:"display_name"`
	// Hints is optional customer-declared context no GCP API reports.
	Hints *models.GCPOnboardingHints `json:"hints,omitempty"`
}

// ProvisionGoogleOAuth handles POST /authsec/discovery/gcp/google-oauth/connectors.
//
// The terminal call: re-runs preflight, and only on success spends the
// session's access token to configure GCP, then hands off to the existing
// onboarding path. See services.GCPOAuthProvisionService.Provision's own
// doc comment for the full ordering and idempotency guarantees. The
// response envelope matches CreateConnector's exactly, and this handler
// audits identically -- both so a connector created via Google
// Authentication is indistinguishable, end to end, from one created by
// hand.
func (ctl *CloudGCPOAuthController) ProvisionGoogleOAuth(c *gin.Context) {
	workspaceID, actor, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req provisionGoogleOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}

	connector, created, perr := ctl.service().Provision(c.Request.Context(), sessionID, workspaceID, services.GoogleScope{
		ScopeKind:       req.ScopeKind,
		ScopeID:         req.ScopeID,
		ReaderProjectID: req.ReaderProjectID,
	}, req.DisplayName, req.Hints, actor)
	if perr != nil {
		status, body := mapGoogleOAuthError(perr)
		c.JSON(status, body)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	auditAdminMutation(c, workspaceID.String(), "onboard", "cloud_connector",
		connector.ID.String(), status, nil, connector)

	c.JSON(status, gin.H{
		"success": true,
		"message": gcpOnboardMessage(created),
		"data":    connector,
		"meta": gin.H{
			"as_of":    time.Now().UTC(),
			"verified": connector.VerifiedAt,
			"note": "provisioned automatically via Google Authentication; the connection is proven but " +
				"nothing has been discovered yet -- identity discovery runs as a separate step",
		},
	})
}

/* ------------------------------ error mapping ------------------------------- */

// mapGoogleOAuthError maps this option's own sentinels first, then falls
// back to mapGCPOnboardingError for anything the final Onboard() hand-off
// call returns -- so a customer sees the exact same {error, hint, fault}
// shape whether their connection failed under WIF's manual flow or under
// Google Authentication's automated one.
func mapGoogleOAuthError(err error) (int, gin.H) {
	switch {
	case errors.Is(err, services.ErrGoogleOAuthUnavailable):
		return http.StatusServiceUnavailable, gin.H{
			"error": err.Error(),
			"hint":  "use the Workload Identity Federation option instead",
			"fault": "authsec",
		}
	case errors.Is(err, services.ErrGoogleOAuthStateInvalid):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "start over by clicking \"Continue with Google\" again",
			"fault": "customer_account",
		}
	case errors.Is(err, services.ErrGoogleOAuthSessionInvalid):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "sign in with Google again to start a new session",
			"fault": "customer_account",
		}
	case errors.Is(err, services.ErrGoogleOAuthWorkspaceMismatch):
		return http.StatusForbidden, gin.H{
			"error": err.Error(),
			"hint":  "sign in with Google again from this workspace",
			"fault": "customer_account",
		}
	case errors.Is(err, services.ErrGoogleOAuthPermissionsMissing):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "the signed-in Google account needs IAM/Service Usage admin rights on the reader project (and the scope being connected) for automatic setup, or use the Workload Identity Federation option instead",
			"fault": "customer_account",
		}
	case errors.Is(err, services.ErrInvalidScopeID):
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "check scope_kind (must be org, folder or project), scope_id and reader_project_id",
			"fault": "customer_account",
		}
	case errors.Is(err, gcp.ErrWIFPoolMissing):
		// OAuth-specific override, BEFORE the mapGCPOnboardingError fallback
		// below: the shared fallback's hint names setup-reader.sh and a
		// pasted-back provider resource, neither of which exists in this
		// flow (nothing was pasted; the trust relationship was configured
		// automatically seconds ago). Same status and fault as the manual
		// flow, only the hint is reworded for this option.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "automatic setup could not verify the connection yet -- Google Cloud can take a minute to apply the new trust relationship, so try connecting again; if it keeps failing, use the Workload Identity Federation option instead",
			"fault": "customer_account",
		}
	case errors.Is(err, gcp.ErrInvalidGrant):
		// Same reason as above: the shared hint says to re-run
		// setup-reader.sh, which this flow never used.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "Google Cloud rejected the credential exchange for the automatically configured access -- try connecting again, or use the Workload Identity Federation option instead",
			"fault": "gcp",
		}
	case errors.Is(err, gcp.ErrPermissionDenied):
		// Same reason as above: the shared hint points at roles
		// setup-reader.sh requested, which this flow granted itself.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "Google Cloud denied the read request for the automatically configured reader identity -- try connecting again, or use the Workload Identity Federation option instead",
			"fault": "customer_account",
		}
	case errors.Is(err, services.ErrScopeNotReadable):
		// Same reason as above: the shared hint references the setup
		// command, which this flow never showed.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "the automatically configured reader identity could not read the selected project yet -- try connecting again, or use the Workload Identity Federation option instead",
			"fault": "customer_account",
		}
	case errors.Is(err, gcp.ErrWIFIssuerUnreachable):
		// Same reason as above: the shared hint suggests the JSON key
		// method, which this wizard no longer offers for new connections.
		return http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"hint":  "Google Cloud could not reach this deployment's sign-in service to finish verifying the connection -- if this deployment uses a local development tunnel, confirm it is still running, or use the Workload Identity Federation option instead",
			"fault": "authsec",
		}
	}
	// Anything else came from the final Onboard() hand-off -- reuse the
	// existing, unmodified WIF/JSON-key error mapping so the customer sees
	// identical error shapes regardless of onboarding path.
	return mapGCPOnboardingError(err)
}
