package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// machineAccessTokenTTL mirrors the native M2M access-token lifetime minted by
// tokenClientCredentialsGrant (oauth_as_controller.go: TTL = time.Hour). The
// dry-run reports the same value so the wizard doesn't promise a TTL the real
// mint won't honor. If the grant's TTL changes, change it here too.
var machineAccessTokenTTL = time.Hour

// ── POST /authsec/applications/:id/machine-access/api-credential ──────────────

// apiCredentialRequest creates (or reuses) a service account, provisions a
// confidential M2M credential, grants it an RS-scoped role, and registers the
// client as approved for this MCP server — the whole "machine identity with an
// API credential" in one call (plan §4.2 / §7). It is a thin wrapper over
// shipped primitives: ServiceAccountService (create + credential),
// EnsureClientRegistration (approved), and an RS-scoped role binding.
type apiCredentialRequest struct {
	// One of: ServiceAccountID (reuse an un-credentialed SA) or
	// ServiceAccountName (create a new one).
	ServiceAccountID   string `json:"service_account_id,omitempty"`
	ServiceAccountName string `json:"service_account_name,omitempty"`
	Description        string `json:"description,omitempty"`

	// RoleID must be a role scoped to this MCP server (rs-{id}: prefix).
	RoleID string `json:"role_id" binding:"required"`

	// Credential type — exactly one. JWKS/JWKSUri ⇒ private_key_jwt;
	// UseClientSecret ⇒ client_secret_basic (secret shown once).
	JWKSUri         *string `json:"jwks_uri,omitempty"`
	JWKS            *string `json:"jwks,omitempty"`
	UseClientSecret bool    `json:"use_client_secret,omitempty"`
}

type apiCredentialResponse struct {
	ServiceAccountID        string  `json:"service_account_id"`
	ServiceAccountName      string  `json:"service_account_name"`
	ClientID                string  `json:"client_id"`
	TokenEndpointAuthMethod string  `json:"token_endpoint_auth_method"`
	ClientSecret            *string `json:"client_secret,omitempty"` // shown once
	RoleID                  string  `json:"role_id"`
	RoleName                string  `json:"role_name"`
	AssignmentID            string  `json:"assignment_id"`
	TokenEndpoint           string  `json:"token_endpoint"`
	Resource                string  `json:"resource"`
	Note                    string  `json:"note"`
}

// CreateAPICredentialAccess handles POST /authsec/applications/:id/machine-access/api-credential.
func (ctrl *ApplicationsController) CreateAPICredentialAccess(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req apiCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.ServiceAccountID == "" && strings.TrimSpace(req.ServiceAccountName) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide service_account_id (existing) or service_account_name (new)"})
		return
	}

	// Validate the role belongs to this workspace and is scoped to this RS.
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}
	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	rsRolePrefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if !strings.HasPrefix(role.Name, rsRolePrefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this MCP server"})
		return
	}

	saSvc := services.NewServiceAccountService(config.DB)

	// Resolve or create the service account.
	var sa *models.ServiceAccount
	if req.ServiceAccountID != "" {
		saUUID, perr := uuid.Parse(req.ServiceAccountID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service_account_id"})
			return
		}
		sa, err = saSvc.GetServiceAccount(workspaceID, saUUID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
			return
		}
	} else {
		// The acting admin is the accountable owner for an implicitly-created SA
		// (D1/F7: owner always). Falls back to a system marker if unresolved.
		ownerEmail := c.GetString("email")
		if ownerEmail == "" {
			ownerEmail = "system@authsec.local"
		}
		sa, err = saSvc.CreateServiceAccount(workspaceID, strings.TrimSpace(req.ServiceAccountName), req.Description, ownerEmail, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// Role binding + credential provisioning + client registration must all land
	// together or not at all. Previously these ran as three separate phases, so a
	// registration failure AFTER provisioning left an ACTIVE credentialed SA whose
	// one-time secret the caller never received and which could not be re-credentialed
	// (ErrServiceAccountHasCredential). Wrap all three in ONE transaction via the
	// tx-aware helper variants; any failure rolls the whole thing back, leaving the
	// (possibly just-created) SA disabled and re-usable.
	var cred *services.ProvisionedCredential
	var assignmentID string
	txErr := config.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		aID, bErr := ensureServiceAccountRSBindingTx(tx, workspaceID, sa.ID, role, rs.ID)
		if bErr != nil {
			return fmt.Errorf("failed to assign role: %w", bErr)
		}
		assignmentID = aID

		c, pErr := saSvc.ProvisionCredentialTx(tx, workspaceID, sa.ID, services.CredentialOptions{
			JWKSUri:         req.JWKSUri,
			JWKS:            req.JWKS,
			UseClientSecret: req.UseClientSecret,
		})
		if pErr != nil {
			return pErr // sentinel errors propagate unwrapped for status mapping below
		}
		cred = c

		clientUUID, uerr := uuid.Parse(c.ClientID)
		if uerr != nil {
			return fmt.Errorf("parse new client id: %w", uerr)
		}
		// Register the new client as approved for THIS MCP server so the M2M grant's
		// registration gate (oauth_as_controller.go: GetClientRegistration == approved)
		// passes. Without it the credential exists but every mint returns access_denied.
		if _, regErr := ctrl.oauthSvc.EnsureClientRegistrationTx(
			tx, rs.ID, clientUUID, workspaceID, "admin", models.ClientRegStatusApproved,
		); regErr != nil {
			return fmt.Errorf("failed to register client: %w", regErr)
		}
		return nil
	})
	if txErr != nil {
		switch {
		case errors.Is(txErr, services.ErrServiceAccountHasCredential):
			c.JSON(http.StatusBadRequest, gin.H{"error": "this service account already has a credential; create a new one or use the access-assignment path to add a role"})
		case errors.Is(txErr, services.ErrCredentialTypeMissing), errors.Is(txErr, services.ErrCredentialTypeAmbiguous):
			c.JSON(http.StatusBadRequest, gin.H{"error": txErr.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": txErr.Error()})
		}
		return
	}

	auditAdminMutation(c, workspaceID.String(), "application_api_credential_created", "service_account",
		sa.ID.String(), http.StatusCreated, nil, map[string]interface{}{
			"application_id": id, "client_id": cred.ClientID, "role_id": roleUUID.String(),
		})

	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"
	c.JSON(http.StatusCreated, apiCredentialResponse{
		ServiceAccountID:        sa.ID.String(),
		ServiceAccountName:      sa.Name,
		ClientID:                cred.ClientID,
		TokenEndpointAuthMethod: cred.AuthMethod,
		ClientSecret:            cred.Secret,
		RoleID:                  roleUUID.String(),
		RoleName:                role.Name,
		AssignmentID:            assignmentID,
		TokenEndpoint:           tokenEndpoint,
		Resource:                rs.ResourceURI,
		Note:                    "Use client_credentials at " + tokenEndpoint + " with HTTP Basic auth (client_id:client_secret) and resource=" + rs.ResourceURI + ". The client secret (if any) is shown only once.",
	})
}

// ensureServiceAccountRSBinding creates an RS-scoped role binding for a service
// account, idempotently (the uq_rb_sa_rs partial-unique index also guards this
// at the DB). Mirrors CreateRSBinding's convention for users.
func ensureServiceAccountRSBinding(workspaceID, saID uuid.UUID, role models.RBACRole, rsID uuid.UUID) (string, error) {
	return ensureServiceAccountRSBindingTx(config.DB, workspaceID, saID, role, rsID)
}

// ensureServiceAccountRSBindingTx is ensureServiceAccountRSBinding bound to a
// specific *gorm.DB (a transaction handle) so it can participate in an atomic
// machine-access creation. The no-arg wrapper above runs it on config.DB.
func ensureServiceAccountRSBindingTx(db *gorm.DB, workspaceID, saID uuid.UUID, role models.RBACRole, rsID uuid.UUID) (string, error) {
	scopeType := "resource_server"
	scopeID := rsID

	var existing models.RoleBinding
	err := db.
		Where("workspace_id = ? AND service_account_id = ? AND role_id = ?", workspaceID, saID, role.ID).
		Where("scope_type = ? AND scope_id = ?", scopeType, scopeID).
		First(&existing).Error
	if err == nil {
		return existing.ID.String(), nil
	}

	ws := workspaceID
	binding := models.RoleBinding{
		WorkspaceID:      &ws,
		ServiceAccountID: &saID,
		RoleID:           role.ID,
		RoleName:         role.Name,
		ScopeType:        &scopeType,
		ScopeID:          &scopeID,
		Conditions:       json.RawMessage([]byte("{}")),
		AssignmentSource: "manual_admin",
		CreatedAt:        time.Now().UTC(),
	}
	if err := db.Create(&binding).Error; err != nil {
		return "", err
	}
	return binding.ID.String(), nil
}

// ── POST /authsec/applications/:id/token-test/simulate ────────────────────────

type simulateRequest struct {
	ServiceAccountID string   `json:"service_account_id,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	RoleID           string   `json:"role_id,omitempty"`
	AssignmentID     string   `json:"assignment_id,omitempty"`
	RequestedScopes  []string `json:"requested_scopes,omitempty"`

	// Mode selects the debugger's depth (plan: Journey 4):
	//   "config" (default) — no SVID in hand; checks only what config can prove.
	//   "paste_svid"       — validate a real SVID's signature/iss/aud/sub (no mint).
	// ("live" — real mint + MCP introspection — is a separate, audited path and
	// is gated on an open product decision; not handled here.)
	Mode string `json:"mode,omitempty"`
	SVID string `json:"svid,omitempty"` // required when Mode == "paste_svid"
}

type simulateCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass" | "fail"
	Reason string `json:"reason,omitempty"`
}

type simulateResponse struct {
	WouldMint       bool            `json:"would_mint"`
	SubjectType     string          `json:"subject_type"`
	EffectiveScopes []string        `json:"effective_scopes"`
	ExpiresIn       int             `json:"expires_in"`
	Checks          []simulateCheck `json:"checks"`
	// FailureBundle is a paste-ready summary (Slack/Jira) of the first failing
	// check — populated only when WouldMint is false. The debugger's "copy
	// failure bundle" button surfaces this verbatim.
	FailureBundle string `json:"failure_bundle,omitempty"`
}

// SimulateToken handles POST /authsec/applications/:id/token-test/simulate.
// A DRY RUN — it never mints a token. It reports, check by check, exactly why a
// real client_credentials mint would or wouldn't succeed for a service account
// on this MCP server (plan §6/§7, acceptance T2). The real, copyable mint stays
// POST /oauth/token (the simulate path can't hold the one-time secret).
func (ctrl *ApplicationsController) SimulateToken(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req simulateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.RoleID == "" && req.AssignmentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role_id or assignment_id is required (it defines the scope set to test)"})
		return
	}

	// Resolve the service account (directly or via the linked client).
	sa, resolveErr := ctrl.resolveSimulateSA(c, workspaceID, req)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": resolveErr.Error()})
		return
	}

	// Resolve the role being tested: explicit role_id, or the role on the
	// referenced assignment (which must belong to this SA + RS).
	roleID, roleErr := ctrl.resolveSimulateRole(workspaceID, rs.ID, sa.ID, req)
	if roleErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": roleErr.Error()})
		return
	}

	checks := make([]simulateCheck, 0, 5)
	pass := func(name string) { checks = append(checks, simulateCheck{Name: name, Status: "pass"}) }
	fail := func(name, reason string) {
		checks = append(checks, simulateCheck{Name: name, Status: "fail", Reason: reason})
	}

	// 1. service_account_active
	if sa.Status == "active" {
		pass("service_account_active")
	} else {
		fail("service_account_active", "service account status is '"+sa.Status+"' — provision a credential to activate it")
	}

	// 2. client_linked
	clientLinked := sa.OAuthClientID != nil
	if clientLinked {
		pass("client_linked")
	} else {
		fail("client_linked", "no OAuth client linked — provision an API credential")
	}

	// 3. client_registration_approved (the M2M mint's registration gate)
	regApproved := false
	if clientLinked {
		if reg, regErr := ctrl.oauthSvc.GetClientRegistration(rs.ID, *sa.OAuthClientID); regErr == nil && reg.Status == models.ClientRegStatusApproved {
			regApproved = true
		}
	}
	if regApproved {
		pass("client_registration_approved")
	} else {
		fail("client_registration_approved", "the linked client is not approved for this MCP server")
	}

	// 4. role_binding_exists
	var bindingCount int64
	config.DB.Model(&models.RoleBinding{}).
		Where("workspace_id = ? AND service_account_id = ? AND role_id = ?", workspaceID, sa.ID, roleID).
		Where("scope_type = 'resource_server' AND scope_id = ?", rs.ID).
		Count(&bindingCount)
	if bindingCount > 0 {
		pass("role_binding_exists")
	} else {
		fail("role_binding_exists", "no role binding for this service account + role on this MCP server")
	}

	// Mintable = SA's RBAC-effective scopes ∩ rs.scopes_supported (what a real
	// mint could grant). requested_scopes (if any) is then tested against it.
	resolver := services.NewScopeResolver(config.DB)
	saEffective, _ := resolver.ServiceAccountEffectiveScopes(c.Request.Context(), workspaceID.String(), sa.ID.String(), rs.ID.String())
	mintable := intersectStrings(saEffective, rs.ScopesSupported)

	// 5. requested_scopes_subset
	var effectiveScopes []string
	if len(mintable) == 0 {
		fail("requested_scopes_subset", "the assigned role grants no scopes on this MCP server")
		effectiveScopes = []string{}
	} else if len(req.RequestedScopes) > 0 {
		missing := subtractStrings(req.RequestedScopes, mintable)
		if len(missing) > 0 {
			fail("requested_scopes_subset", "requested scopes not granted by the role: "+strings.Join(missing, ", "))
			effectiveScopes = intersectStrings(req.RequestedScopes, mintable)
		} else {
			pass("requested_scopes_subset")
			effectiveScopes = intersectStrings(req.RequestedScopes, mintable)
		}
	} else {
		pass("requested_scopes_subset")
		effectiveScopes = mintable
	}

	// SPIFFE/Kubernetes config checks — only meaningful for a SPIFFE-backed
	// workload. This is a CONFIG dry-run: we have no actual SVID in hand, so we
	// verify only what config can prove (issuer configured + its JWKS reachable
	// from this backend). We deliberately do NOT claim to have checked the
	// SVID's iss/aud/sub — that needs a pasted SVID or a live test.
	if sa.SpiffeID != nil {
		iss, perr := services.ProbeSpiffeOIDC()
		if iss == "" {
			fail("spiffe_issuer_configured", "SPIFFE_OIDC_ISSUER is not set — SPIFFE/Kubernetes auth is disabled on this deployment")
		} else {
			pass("spiffe_issuer_configured")
			if perr == nil {
				pass("jwks_reachable_from_backend")
			} else {
				fail("jwks_reachable_from_backend", perr.Error())
			}
		}

		// paste_svid + live both validate a REAL pasted SVID (signature/iss/aud)
		// and confirm its sub matches this workload's registered SPIFFE ID.
		// Validation alone mints nothing and writes nothing.
		if req.Mode == "paste_svid" || req.Mode == "live" {
			if strings.TrimSpace(req.SVID) == "" {
				fail("svid_provided", "paste a JWT-SVID to validate its signature, issuer, audience, and subject")
			} else {
				tokenEndpoint := ""
				if config.AppConfig != nil {
					tokenEndpoint = config.AppConfig.OAuthBaseURL() + "/oauth/token"
				}
				svidSub, verr := services.VerifySVID(req.SVID, tokenEndpoint)
				if verr != nil {
					fail("svid_verified", verr.Error())
				} else {
					pass("svid_verified")
				}
				if svidSub != "" {
					if svidSub == *sa.SpiffeID {
						pass("svid_sub_matches_registered_spiffe_id")
					} else {
						fail("svid_sub_matches_registered_spiffe_id",
							fmt.Sprintf("SVID sub %q does not match this workload's SPIFFE ID %q", svidSub, *sa.SpiffeID))
					}
				}

				// live mode: actually exchange the SVID at the real token endpoint
				// (the complete production path). This MINTS a real short-lived
				// token and is recorded in the normal token-endpoint audit. We stop
				// at the mint — no outbound call to the MCP server.
				if req.Mode == "live" {
					scopes := req.RequestedScopes
					if len(scopes) == 0 {
						scopes = effectiveScopes
					}
					if ok, reason := liveExchangeSVID(req.SVID, rs.ResourceURI, scopes); ok {
						pass("token_issued")
					} else {
						fail("token_issued", reason)
					}
				}
			}
		}
	}

	wouldMint := true
	var firstFail *simulateCheck
	for i := range checks {
		if checks[i].Status != "pass" {
			wouldMint = false
			firstFail = &checks[i]
			break
		}
	}

	resp := simulateResponse{
		WouldMint:       wouldMint,
		SubjectType:     "service_account",
		EffectiveScopes: effectiveScopes,
		ExpiresIn:       int(machineAccessTokenTTL.Seconds()),
		Checks:          checks,
	}
	if firstFail != nil {
		resp.FailureBundle = fmt.Sprintf(
			"Workload: %s   MCP server: %s\nFailure (%s): %s\nResource: %s",
			sa.Name, rs.Name, firstFail.Name, firstFail.Reason, rs.ResourceURI,
		)
	}
	c.JSON(http.StatusOK, resp)
}

// liveExchangeSVID performs the COMPLETE production token exchange for a pasted
// JWT-SVID against this deployment's own token endpoint. It is used only by the
// debugger's "live" mode — it mints a real (short-lived) token and is recorded
// in the normal token-endpoint audit. Returns (true, "") on a 200 with an
// access_token; otherwise (false, reason). It deliberately stops at the mint and
// does not call the downstream MCP server.
func liveExchangeSVID(svid, resource string, scopes []string) (bool, string) {
	if config.AppConfig == nil {
		return false, "server config unavailable"
	}
	endpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", "urn:authsec:params:oauth:client-assertion-type:spiffe-svid")
	form.Set("client_assertion", svid)
	if resource != "" {
		form.Set("resource", resource)
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	resp, err := http.PostForm(endpoint, form) //nolint:noctx
	if err != nil {
		return false, "exchange request failed: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "access_token") {
		return true, ""
	}
	snippet := string(body)
	if len(snippet) > 180 {
		snippet = snippet[:180]
	}
	return false, fmt.Sprintf("token endpoint returned %d: %s", resp.StatusCode, snippet)
}

// resolveSimulateSA loads the service account from service_account_id, or from
// the linked client when client_id is given instead.
func (ctrl *ApplicationsController) resolveSimulateSA(c *gin.Context, workspaceID uuid.UUID, req simulateRequest) (*models.ServiceAccount, error) {
	saSvc := services.NewServiceAccountService(config.DB)
	if req.ServiceAccountID != "" {
		saUUID, err := uuid.Parse(req.ServiceAccountID)
		if err != nil {
			return nil, errors.New("invalid service_account_id")
		}
		sa, err := saSvc.GetServiceAccount(workspaceID, saUUID)
		if err != nil {
			return nil, errors.New("service account not found")
		}
		return sa, nil
	}
	if req.ClientID != "" {
		var client models.MCPOAuthClient
		if err := config.DB.Where("client_id = ?", req.ClientID).First(&client).Error; err != nil {
			return nil, errors.New("client not found")
		}
		sa, err := ctrl.oauthSvc.GetServiceAccountByClientID(c.Request.Context(), client.ID)
		if err != nil || sa == nil {
			return nil, errors.New("no service account linked to this client")
		}
		if sa.WorkspaceID != workspaceID {
			return nil, errors.New("service account not in this workspace")
		}
		return sa, nil
	}
	return nil, errors.New("provide service_account_id or client_id")
}

// resolveSimulateRole returns the role UUID to test: req.RoleID, or the role on
// the referenced assignment (validated to belong to this SA + RS).
func (ctrl *ApplicationsController) resolveSimulateRole(workspaceID, rsID, saID uuid.UUID, req simulateRequest) (uuid.UUID, error) {
	if req.RoleID != "" {
		roleUUID, err := uuid.Parse(req.RoleID)
		if err != nil {
			return uuid.Nil, errors.New("invalid role_id")
		}
		return roleUUID, nil
	}
	assignUUID, err := uuid.Parse(req.AssignmentID)
	if err != nil {
		return uuid.Nil, errors.New("invalid assignment_id")
	}
	var rb models.RoleBinding
	if err := config.DB.
		Where("id = ? AND workspace_id = ? AND service_account_id = ?", assignUUID, workspaceID, saID).
		Where("scope_type = 'resource_server' AND scope_id = ?", rsID).
		First(&rb).Error; err != nil {
		return uuid.Nil, errors.New("assignment not found for this service account on this MCP server")
	}
	return rb.RoleID, nil
}

// ── POST /authsec/agents ──────────────────────────────────────────────────────

type registerAgentRequest struct {
	Name         string   `json:"name" binding:"required"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
}

// RegisterAgent mints a confidential A2A agent client (authorization_code +
// token-exchange + a client secret) in the caller's workspace (plan J5). The
// agent uses it to log a user in (OIDC) and exchange for an ID-JAG to reach
// other workspaces' MCP servers. Workspace-level: the client is homed here, so
// its ID-JAG's issuance workspace is this one (cross-workspace by §19).
func (ctrl *ApplicationsController) RegisterAgent(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	var req registerAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	redirects := req.RedirectURIs
	if len(redirects) == 0 {
		redirects = []string{"http://localhost:8126/callback"}
	}
	clientID, secret, err := ctrl.oauthSvc.RegisterAgentClient(workspaceID, req.Name, redirects)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	issuer := ""
	if config.AppConfig != nil {
		issuer = config.AppConfig.OAuthBaseURL()
	}
	c.JSON(http.StatusCreated, gin.H{
		"client_id":     clientID,
		"client_secret": secret, // shown once
		"redirect_uris": redirects,
		"issuer":        issuer,
	})
}

// ── POST /authsec/applications/:id/token-test/simulate-xaa ────────────────────

type simulateXAARequest struct {
	ClientID string `json:"client_id" binding:"required"`
}

// SimulateXAA debugs a CROSS-WORKSPACE (A2A / ID-JAG) call: "why can't this
// agent from another workspace reach my MCP server?" (plan Journey 8). It runs
// the redemption-path checks that are computable without an actual ID-JAG:
// §19 same-domain, registration approval, and the brokering deny gate. These
// are the failure modes unique to the cross-app flow (the per-scope checks live
// in the direct debugger). Read-only; mints nothing.
func (ctrl *ApplicationsController) SimulateXAA(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	var req simulateXAARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	var client models.MCPOAuthClient
	if err := config.DB.Where("client_id = ?", req.ClientID).First(&client).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}

	checks := make([]simulateCheck, 0, 4)
	pass := func(name string) { checks = append(checks, simulateCheck{Name: name, Status: "pass"}) }
	fail := func(name, reason string) {
		checks = append(checks, simulateCheck{Name: name, Status: "fail", Reason: reason})
	}

	// 1. Conformant XAA boundary (ID-JAG draft §4.1/§7.3): the boundary is the
	// resource server, NOT the workspace — a same-workspace agent calling a
	// distinct MCP server is valid cross-app delegation. The only rejection is
	// literal self-delegation: the RS's own client redeeming an ID-JAG to itself.
	if rs.LegacyClientID != nil && *rs.LegacyClientID == client.ID {
		fail("not_self_delegation", "this client IS this MCP server's own client — a client cannot use the cross-app flow to reach itself; call it directly")
	} else {
		pass("not_self_delegation")
	}

	// 2. registration approved for this RS.
	if reg, regErr := ctrl.oauthSvc.GetClientRegistration(rs.ID, client.ID); regErr == nil && reg.Status == models.ClientRegStatusApproved {
		pass("connection_approved")
	} else {
		fail("connection_approved", "this client is not an approved connection on this MCP server — approve its request in the Requests tab")
	}

	// 3. brokering gate (redemption): an explicit deny blocks the ID-JAG redemption.
	type brokeringRow struct{ Effect string }
	var rows []brokeringRow
	config.DB.Raw(`
		SELECT effect FROM a2a_brokering_policies
		WHERE workspace_id = ? AND side = 'redemption'
		  AND (client_id IS NULL OR client_id = ?)`,
		workspaceID, client.ClientID,
	).Scan(&rows)
	denied := false
	for _, r := range rows {
		if r.Effect == "deny" {
			denied = true
			break
		}
	}
	if denied {
		fail("brokering_permitted", "a brokering deny rule blocks cross-app redemption for this client — remove it under Trusted Issuers → Cross-app brokering")
	} else {
		pass("brokering_permitted")
	}

	wouldRedeem := true
	var firstFail *simulateCheck
	for i := range checks {
		if checks[i].Status != "pass" {
			wouldRedeem = false
			firstFail = &checks[i]
			break
		}
	}
	resp := simulateResponse{
		WouldMint:   wouldRedeem,
		SubjectType: "cross_workspace_agent",
		Checks:      checks,
	}
	if firstFail != nil {
		resp.FailureBundle = fmt.Sprintf(
			"Cross-app caller: %s   MCP server: %s\nFailure (%s): %s\nResource: %s",
			client.ClientID, rs.Name, firstFail.Name, firstFail.Reason, rs.ResourceURI,
		)
	}
	c.JSON(http.StatusOK, resp)
}

// intersectStrings returns the sorted set intersection of a and b.
func intersectStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0)
	seen := make(map[string]struct{})
	for _, s := range a {
		if _, ok := set[s]; ok {
			if _, dup := seen[s]; !dup {
				out = append(out, s)
				seen[s] = struct{}{}
			}
		}
	}
	return out
}

// subtractStrings returns elements of a not present in b.
func subtractStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0)
	for _, s := range a {
		if _, ok := set[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

// ── Workload identity (K8s only, v1) ─────────────────────────────────────────
// POST   /authsec/applications/:id/machine-access/workload   create workload
// GET    /authsec/applications/:id/workloads                 list workloads
// DELETE /authsec/applications/:id/workloads/:wid            revoke workload

type workloadRequest struct {
	ServiceAccountID   string            `json:"service_account_id,omitempty"`
	ServiceAccountName string            `json:"service_account_name,omitempty"`
	Description        string            `json:"description,omitempty"`
	RoleID             string            `json:"role_id" binding:"required"`
	Platform           string            `json:"platform"` // "kubernetes" only in v1
	Selectors          map[string]string `json:"selectors,omitempty"`
}

type workloadResponse struct {
	WorkloadID         string            `json:"workload_id"`
	SpiffeID           string            `json:"spiffe_id"`
	ServiceAccountID   string            `json:"service_account_id"`
	ServiceAccountName string            `json:"service_account_name"`
	ClientID           string            `json:"client_id"`
	RoleID             string            `json:"role_id"`
	RoleName           string            `json:"role_name"`
	AssignmentID       string            `json:"assignment_id"`
	Status             string            `json:"status"`
	Platform           string            `json:"platform"`
	Selectors          map[string]string `json:"selectors"`
	InstallSnippet     string            `json:"install_snippet"`
	TokenEndpoint      string            `json:"token_endpoint"`
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	return strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func spiffeIDFor(trustDomain, workspaceID, saName string) string {
	td := trustDomain
	if td == "" {
		td = "authsec.local"
	}
	return fmt.Sprintf("spiffe://%s/%s/%s/%s", td, workspaceID, slugify(saName), uuid.New().String())
}

func k8sInstallSnippet(spiffeID, tokenEndpoint string) string {
	aud := tokenEndpoint
	if aud == "" {
		aud = "<token-endpoint-url>"
	}
	return fmt.Sprintf(`# Configure SPIRE Agent entry for this workload:
# spire-server entry create \
#   -spiffeID %s \
#   -parentID spiffe://<trust-domain>/spire/agent/k8s_psat/<cluster>/<agent-id> \
#   -selector k8s:ns:<namespace> \
#   -selector k8s:sa:<service-account>

# Mint the JWT-SVID with THIS token endpoint as the audience — AuthSec rejects
# an SVID whose aud does not include it:
# spire-agent api fetch jwt -audience %s

# The workload presents that SVID at the token endpoint:
# POST /oauth/token
#   grant_type=client_credentials
#   client_assertion_type=urn:authsec:params:oauth:client-assertion-type:spiffe-svid
#   client_assertion=<JWT-SVID>
#   resource=<mcp-server-uri>`, spiffeID, aud)
}

// CreateWorkloadAccess handles POST /authsec/applications/:id/machine-access/workload.
func (ctrl *ApplicationsController) CreateWorkloadAccess(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req workloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.Platform != "" && req.Platform != "kubernetes" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only platform=kubernetes is supported in v1"})
		return
	}
	if req.ServiceAccountID == "" && strings.TrimSpace(req.ServiceAccountName) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide service_account_id or service_account_name"})
		return
	}

	// Validate role is scoped to this RS.
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}
	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	rsRolePrefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if !strings.HasPrefix(role.Name, rsRolePrefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this MCP server"})
		return
	}

	saSvc := services.NewServiceAccountService(config.DB)

	// Resolve or create the service account.
	var sa *models.ServiceAccount
	if req.ServiceAccountID != "" {
		saUUID, perr := uuid.Parse(req.ServiceAccountID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service_account_id"})
			return
		}
		sa, err = saSvc.GetServiceAccount(workspaceID, saUUID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
			return
		}
		// Guard: this convenience endpoint MINTS a new SPIFFE ID + OAuth client and
		// links them to the SA. If the workload already has an identity, minting
		// would clobber it — refuse and point to the grant-only path instead.
		if sa.SpiffeID != nil || sa.OAuthClientID != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": "workload already has an identity; use POST /authsec/applications/:id/access/workloads to grant access without re-minting its identity",
			})
			return
		}
	} else {
		// The acting admin is the accountable owner for an implicitly-created SA
		// (D1/F7: owner always). Falls back to a system marker if unresolved.
		ownerEmail := c.GetString("email")
		if ownerEmail == "" {
			ownerEmail = "system@authsec.local"
		}
		sa, err = saSvc.CreateServiceAccount(workspaceID, strings.TrimSpace(req.ServiceAccountName), req.Description, ownerEmail, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// Generate SPIFFE ID.
	td := ""
	if config.AppConfig != nil {
		td = config.AppConfig.SpiffeTrustDomain
	}
	spiffeID := spiffeIDFor(td, workspaceID.String(), sa.Name)

	// Create a confidential OAuth client with spiffe-svid auth (no secret needed).
	clientUUID := uuid.New()
	clientIDStr := clientUUID.String()
	now := time.Now().UTC()
	mcpClient := models.MCPOAuthClient{
		ID:                              clientUUID,
		ClientID:                        clientIDStr,
		HydraClientID:                   clientIDStr,
		ClientName:                      sa.Name + " (workload)",
		RedirectURIs:                    pq.StringArray{},
		GrantTypes:                      pq.StringArray{"client_credentials"},
		ResponseTypes:                   pq.StringArray{},
		RegistrationType:                "admin",
		AllowedTokenEndpointAuthMethods: pq.StringArray{"urn:authsec:params:oauth:client-assertion-type:spiffe-svid"},
		HomeWorkspaceID:                 &workspaceID,
		IsConfidential:                  true,
		CreatedAt:                       now,
		UpdatedAt:                       now,
	}

	selectorsJSON, _ := json.Marshal(req.Selectors)
	if selectorsJSON == nil {
		selectorsJSON = []byte("{}")
	}
	platform := req.Platform
	if platform == "" {
		platform = "kubernetes"
	}

	spiffeIDStr := spiffeID
	workloadID := uuid.New()

	// The OAuth client, the SA→client link, and the workload-identity row must
	// land together or not at all — a partial failure must never leave an
	// orphaned client, a half-linked service account, or a workload that can
	// authenticate but has no role. All five writes (client, SA link, workload
	// identity, role binding, client registration) commit in ONE transaction via
	// the tx-aware helper variants; any error rolls the whole thing back.
	spiffeIdentity := models.ApplicationSpiffeIdentity{
		ID:            workloadID,
		WorkspaceID:   workspaceID,
		ApplicationID: rs.ID,
		SpiffeID:      spiffeIDStr,
		TrustDomain:   td,
		Selectors:     json.RawMessage(selectorsJSON),
		Status:        "attestation_pending",
		CreatedAt:     now,
	}
	var assignmentID string
	if txErr := config.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&mcpClient).Error; err != nil {
			return fmt.Errorf("failed to create OAuth client: %w", err)
		}
		if err := tx.Model(&models.ServiceAccount{}).
			Where("workspace_id = ? AND id = ?", workspaceID, sa.ID).
			Updates(map[string]interface{}{
				"oauth_client_id": clientUUID,
				"spiffe_id":       spiffeIDStr,
				"status":          "active",
				"updated_at":      now,
			}).Error; err != nil {
			return fmt.Errorf("failed to link client to SA: %w", err)
		}
		if err := tx.Create(&spiffeIdentity).Error; err != nil {
			return fmt.Errorf("failed to create workload identity: %w", err)
		}
		aID, bErr := ensureServiceAccountRSBindingTx(tx, workspaceID, sa.ID, role, rs.ID)
		if bErr != nil {
			return fmt.Errorf("failed to assign role: %w", bErr)
		}
		assignmentID = aID
		if _, regErr := ctrl.oauthSvc.EnsureClientRegistrationTx(
			tx, rs.ID, clientUUID, workspaceID, "admin", models.ClientRegStatusApproved,
		); regErr != nil {
			return fmt.Errorf("failed to register client: %w", regErr)
		}
		return nil
	}); txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": txErr.Error()})
		return
	}

	selectors := req.Selectors
	if selectors == nil {
		selectors = map[string]string{}
	}

	c.JSON(http.StatusCreated, workloadResponse{
		WorkloadID:         workloadID.String(),
		SpiffeID:           spiffeIDStr,
		ServiceAccountID:   sa.ID.String(),
		ServiceAccountName: sa.Name,
		ClientID:           clientIDStr,
		RoleID:             roleUUID.String(),
		RoleName:           role.Name,
		AssignmentID:       assignmentID,
		Status:             "attestation_pending",
		Platform:           platform,
		Selectors:          selectors,
		InstallSnippet:     k8sInstallSnippet(spiffeIDStr, config.AppConfig.OAuthBaseURL()+"/oauth/token"),
		TokenEndpoint:      config.AppConfig.OAuthBaseURL() + "/oauth/token",
	})
}

// ── POST /authsec/applications/:id/access/federated-workload ──────────────────

// federatedWorkloadRequest registers a BRING-YOUR-OWN-SPIRE workload: a service
// account whose SPIFFE ID is issued by a customer's own (federated) trust domain,
// not minted by AuthSec. The issuer must already be registered as an active
// workload_identity_provider (kind=spiffe); the external SPIFFE ID is stored
// verbatim as the SA's spiffe_id so authenticateSPIFFESVID can match it.
type federatedWorkloadRequest struct {
	ProviderID         string `json:"provider_id" binding:"required"`        // a registered workload_identity_provider
	ExternalSpiffeID   string `json:"external_spiffe_id" binding:"required"` // exact spiffe://<trust-domain>/...
	RoleID             string `json:"role_id" binding:"required"`
	ServiceAccountID   string `json:"service_account_id"`   // reuse an identity-less SA, OR
	ServiceAccountName string `json:"service_account_name"` // create a new one
	Description        string `json:"description"`
}

// CreateFederatedWorkloadAccess handles
// POST /authsec/applications/:id/access/federated-workload.
//
// Unlike CreateWorkloadAccess (which MINTS an internal authsec.local SPIFFE ID),
// this registers an EXTERNAL SPIFFE ID from a federated trust domain. The two
// halves of SPIFFE trust meet here: the issuer (workload_identity_provider) plus
// the subject (this SA's spiffe_id). It creates the confidential spiffe-svid
// client, links it, grants the rs-scoped role, and records the workload identity
// as `active` (federation IS the attestation — there is no embedded-SPIRE attest
// step for an external trust domain).
func (ctrl *ApplicationsController) CreateFederatedWorkloadAccess(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req federatedWorkloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Resolve the workload identity provider (issuer half of trust). Must be an
	// ACTIVE, spiffe-kind provider in THIS workspace.
	providerUUID, err := uuid.Parse(req.ProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider_id"})
		return
	}
	var provider models.WorkloadIdentityProvider
	if err := config.DB.Where("id = ? AND workspace_id = ?", providerUUID, workspaceID).First(&provider).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workload identity provider not found"})
		return
	}
	if provider.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workload identity provider is not active"})
		return
	}
	if provider.Kind != "spiffe" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider must be kind=spiffe for a SPIFFE workload (use the OIDC federation path for CI tokens)"})
		return
	}

	// Validate the external SPIFFE ID and bind it to the provider's trust domain.
	spiffeIDStr := strings.TrimSpace(req.ExternalSpiffeID)
	if !strings.HasPrefix(spiffeIDStr, "spiffe://") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "external_spiffe_id must be a SPIFFE ID (spiffe://...)"})
		return
	}
	svidTD := strings.TrimPrefix(spiffeIDStr, "spiffe://")
	if i := strings.IndexByte(svidTD, '/'); i >= 0 {
		svidTD = svidTD[:i]
	}
	if svidTD == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "external_spiffe_id has no trust domain"})
		return
	}
	if provider.TrustDomain != nil && *provider.TrustDomain != "" && svidTD != *provider.TrustDomain {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("external_spiffe_id trust domain %q does not match provider trust domain %q", svidTD, *provider.TrustDomain)})
		return
	}

	// Validate role is scoped to this RS.
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}
	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	rsRolePrefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if !strings.HasPrefix(role.Name, rsRolePrefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this MCP server"})
		return
	}

	// Reject a duplicate SPIFFE ID up front (the column is globally unique on
	// application_spiffe_identities; surfacing it here gives a clean 409).
	var dupCount int64
	config.DB.Table("application_spiffe_identities").Where("spiffe_id = ?", spiffeIDStr).Count(&dupCount)
	if dupCount > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "this SPIFFE ID is already registered"})
		return
	}

	saSvc := services.NewServiceAccountService(config.DB)

	// Resolve or create the service account (must not already have an identity).
	var sa *models.ServiceAccount
	if req.ServiceAccountID != "" {
		saUUID, perr := uuid.Parse(req.ServiceAccountID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service_account_id"})
			return
		}
		sa, err = saSvc.GetServiceAccount(workspaceID, saUUID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
			return
		}
		if sa.SpiffeID != nil || sa.OAuthClientID != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "service account already has an identity"})
			return
		}
	} else {
		if strings.TrimSpace(req.ServiceAccountName) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "provide service_account_id or service_account_name"})
			return
		}
		// The acting admin is the accountable owner for an implicitly-created SA
		// (D1/F7: owner always). Falls back to a system marker if unresolved.
		ownerEmail := c.GetString("email")
		if ownerEmail == "" {
			ownerEmail = "system@authsec.local"
		}
		sa, err = saSvc.CreateServiceAccount(workspaceID, strings.TrimSpace(req.ServiceAccountName), req.Description, ownerEmail, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// Confidential client authenticated by the federated SVID (no secret).
	clientUUID := uuid.New()
	clientIDStr := clientUUID.String()
	now := time.Now().UTC()
	mcpClient := models.MCPOAuthClient{
		ID:                              clientUUID,
		ClientID:                        clientIDStr,
		HydraClientID:                   clientIDStr,
		ClientName:                      sa.Name + " (federated workload)",
		RedirectURIs:                    pq.StringArray{},
		GrantTypes:                      pq.StringArray{"client_credentials"},
		ResponseTypes:                   pq.StringArray{},
		RegistrationType:                "admin",
		AllowedTokenEndpointAuthMethods: pq.StringArray{"urn:authsec:params:oauth:client-assertion-type:spiffe-svid"},
		HomeWorkspaceID:                 &workspaceID,
		IsConfidential:                  true,
		CreatedAt:                       now,
		UpdatedAt:                       now,
	}

	workloadID := uuid.New()
	spiffeIdentity := models.ApplicationSpiffeIdentity{
		ID:            workloadID,
		WorkspaceID:   workspaceID,
		ApplicationID: rs.ID,
		SpiffeID:      spiffeIDStr,
		TrustDomain:   svidTD,
		Selectors:     json.RawMessage("{}"),
		Status:        "active", // federated: the external trust domain is the attestation authority
		CreatedAt:     now,
	}

	var assignmentID string
	if txErr := config.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&mcpClient).Error; err != nil {
			return fmt.Errorf("failed to create OAuth client: %w", err)
		}
		if err := tx.Model(&models.ServiceAccount{}).
			Where("workspace_id = ? AND id = ?", workspaceID, sa.ID).
			Updates(map[string]interface{}{
				"oauth_client_id":      clientUUID,
				"spiffe_id":            spiffeIDStr,
				"spiffe_match_type":    "exact",
				"workload_provider_id": provider.ID,
				"status":               "active",
				"updated_at":           now,
			}).Error; err != nil {
			return fmt.Errorf("failed to link client to SA: %w", err)
		}
		if err := tx.Create(&spiffeIdentity).Error; err != nil {
			return fmt.Errorf("failed to create workload identity: %w", err)
		}
		aID, bErr := ensureServiceAccountRSBindingTx(tx, workspaceID, sa.ID, role, rs.ID)
		if bErr != nil {
			return fmt.Errorf("failed to assign role: %w", bErr)
		}
		assignmentID = aID
		if _, regErr := ctrl.oauthSvc.EnsureClientRegistrationTx(
			tx, rs.ID, clientUUID, workspaceID, "admin", models.ClientRegStatusApproved,
		); regErr != nil {
			return fmt.Errorf("failed to register client: %w", regErr)
		}
		return nil
	}); txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": txErr.Error()})
		return
	}

	c.JSON(http.StatusCreated, workloadResponse{
		WorkloadID:         workloadID.String(),
		SpiffeID:           spiffeIDStr,
		ServiceAccountID:   sa.ID.String(),
		ServiceAccountName: sa.Name,
		ClientID:           clientIDStr,
		RoleID:             roleUUID.String(),
		RoleName:           role.Name,
		AssignmentID:       assignmentID,
		Status:             "active",
		Platform:           "federated",
		Selectors:          map[string]string{},
		InstallSnippet:     k8sInstallSnippet(spiffeIDStr, config.AppConfig.OAuthBaseURL()+"/oauth/token"),
		TokenEndpoint:      config.AppConfig.OAuthBaseURL() + "/oauth/token",
	})
}

// ── POST /authsec/applications/:id/access/workloads ───────────────────────────

// grantWorkloadRequest grants an EXISTING workload (service account) access to
// this MCP server. Unlike CreateWorkloadAccess it NEVER mints or changes the
// workload's identity (spiffe_id / oauth_client_id) — it only creates the
// RS-scoped role binding and approves the client registration. This is the
// universal "attach existing workload" path (plan: model split / Journey 1).
type grantWorkloadRequest struct {
	ServiceAccountID string   `json:"service_account_id" binding:"required"`
	RoleID           string   `json:"role_id" binding:"required"`
	RequestedScopes  []string `json:"requested_scopes,omitempty"` // informational; effective scopes returned below
	ExpiresAt        *string  `json:"expires_at,omitempty"`       // reserved; not yet enforced on the binding
}

type grantWorkloadResponse struct {
	ServiceAccountID   string   `json:"service_account_id"`
	ServiceAccountName string   `json:"service_account_name"`
	ClientID           string   `json:"client_id"`
	RoleID             string   `json:"role_id"`
	RoleName           string   `json:"role_name"`
	AssignmentID       string   `json:"assignment_id"`
	EffectiveScopes    []string `json:"effective_scopes"`
	Resource           string   `json:"resource"`
}

// GrantWorkloadAccess handles POST /authsec/applications/:id/access/workloads.
func (ctrl *ApplicationsController) GrantWorkloadAccess(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req grantWorkloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate the role belongs to this workspace and is scoped to this RS.
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}
	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	rsRolePrefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if !strings.HasPrefix(role.Name, rsRolePrefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this MCP server"})
		return
	}

	// Resolve the EXISTING workload. GetServiceAccount is workspace-scoped, so a
	// workload from another workspace resolves to not-found — cross-workspace
	// grants are rejected here (cross-workspace callers use the A2A flow).
	saUUID, perr := uuid.Parse(req.ServiceAccountID)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service_account_id"})
		return
	}
	saSvc := services.NewServiceAccountService(config.DB)
	sa, err := saSvc.GetServiceAccount(workspaceID, saUUID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workload not found in this workspace"})
		return
	}
	// A workload must already have an authentication method (a linked client)
	// before it can be granted access — otherwise there is nothing to register.
	if sa.OAuthClientID == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "workload has no authentication method; register a credential or Kubernetes identity first",
		})
		return
	}

	// Grant = RS-scoped role binding + approved client registration, in one tx.
	// Identity (spiffe_id / oauth_client_id) is intentionally left untouched.
	var assignmentID string
	if txErr := config.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		aID, bErr := ensureServiceAccountRSBindingTx(tx, workspaceID, sa.ID, role, rs.ID)
		if bErr != nil {
			return fmt.Errorf("failed to assign role: %w", bErr)
		}
		assignmentID = aID
		if _, regErr := ctrl.oauthSvc.EnsureClientRegistrationTx(
			tx, rs.ID, *sa.OAuthClientID, workspaceID, "admin", models.ClientRegStatusApproved,
		); regErr != nil {
			return fmt.Errorf("failed to register client: %w", regErr)
		}
		return nil
	}); txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": txErr.Error()})
		return
	}

	// Report current effective scopes so the caller sees what the grant yields.
	resolver := services.NewScopeResolver(config.DB)
	effective, _ := resolver.ServiceAccountEffectiveScopes(
		c.Request.Context(), workspaceID.String(), sa.ID.String(), rs.ID.String(),
	)

	clientIDStr := ""
	var mc models.MCPOAuthClient
	if e := config.DB.Where("id = ?", *sa.OAuthClientID).First(&mc).Error; e == nil {
		clientIDStr = mc.ClientID
	}

	c.JSON(http.StatusOK, grantWorkloadResponse{
		ServiceAccountID:   sa.ID.String(),
		ServiceAccountName: sa.Name,
		ClientID:           clientIDStr,
		RoleID:             roleUUID.String(),
		RoleName:           role.Name,
		AssignmentID:       assignmentID,
		EffectiveScopes:    effective,
		Resource:           rs.ResourceURI,
	})
}

// workloadListItem is the API shape for one workload in the list.
type workloadListItem struct {
	WorkloadID         string      `json:"workload_id"`
	SpiffeID           string      `json:"spiffe_id"`
	ServiceAccountID   string      `json:"service_account_id,omitempty"`
	ServiceAccountName string      `json:"service_account_name,omitempty"`
	Status             string      `json:"status"`
	Platform           string      `json:"platform"`
	Selectors          interface{} `json:"selectors"`
	LastAttestedAt     *time.Time  `json:"last_attested_at,omitempty"`
	LastTokenIssuedAt  *time.Time  `json:"last_token_issued_at,omitempty"`
	LastError          *string     `json:"last_error,omitempty"`
	LastErrorAt        *time.Time  `json:"last_error_at,omitempty"`
	CreatedAt          time.Time   `json:"created_at"`
	RevokedAt          *time.Time  `json:"revoked_at,omitempty"`
}

// ListWorkloads handles GET /authsec/applications/:id/workloads.
func (ctrl *ApplicationsController) ListWorkloads(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var rows []models.ApplicationSpiffeIdentity
	if err := config.DB.WithContext(c.Request.Context()).
		Where("application_id = ? AND workspace_id = ?", rs.ID, workspaceID).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workloads"})
		return
	}

	// Enrich with SA info.
	saCache := map[string]*models.ServiceAccount{}
	items := make([]workloadListItem, 0, len(rows))
	for _, row := range rows {
		// Find SA by spiffe_id.
		var sa *models.ServiceAccount
		if cached, ok := saCache[row.SpiffeID]; ok {
			sa = cached
		} else {
			var saRow models.ServiceAccount
			if err := config.DB.WithContext(c.Request.Context()).
				Where("workspace_id = ? AND spiffe_id = ?", workspaceID, row.SpiffeID).
				First(&saRow).Error; err == nil {
				sa = &saRow
				saCache[row.SpiffeID] = sa
			}
		}

		item := workloadListItem{
			WorkloadID:        row.ID.String(),
			SpiffeID:          row.SpiffeID,
			Status:            row.Status,
			Platform:          "kubernetes",
			Selectors:         row.Selectors,
			LastAttestedAt:    row.LastAttestedAt,
			LastTokenIssuedAt: row.LastTokenIssuedAt,
			LastError:         row.LastError,
			LastErrorAt:       row.LastErrorAt,
			CreatedAt:         row.CreatedAt,
			RevokedAt:         row.RevokedAt,
		}
		if sa != nil {
			item.ServiceAccountID = sa.ID.String()
			item.ServiceAccountName = sa.Name
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}

// RevokeWorkload handles DELETE /authsec/applications/:id/workloads/:wid.
// Marks the SPIFFE identity as revoked and disables the linked service account
// so the auth path rejects further SVID presentations.
func (ctrl *ApplicationsController) RevokeWorkload(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	widParam := c.Param("wid")
	wid, err := uuid.Parse(widParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workload id"})
		return
	}

	var identity models.ApplicationSpiffeIdentity
	if err := config.DB.WithContext(c.Request.Context()).
		Where("id = ? AND application_id = ? AND workspace_id = ?", wid, rs.ID, workspaceID).
		First(&identity).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workload not found"})
		return
	}

	now := time.Now().UTC()
	config.DB.WithContext(c.Request.Context()).
		Model(&models.ApplicationSpiffeIdentity{}).
		Where("id = ?", wid).
		Updates(map[string]interface{}{"status": "revoked", "revoked_at": now})

	// Disable the linked service account (if any) so SPIFFE SVID auth fails.
	config.DB.WithContext(c.Request.Context()).
		Model(&models.ServiceAccount{}).
		Where("workspace_id = ? AND spiffe_id = ?", workspaceID, identity.SpiffeID).
		Updates(map[string]interface{}{"status": "disabled", "updated_at": now})

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
