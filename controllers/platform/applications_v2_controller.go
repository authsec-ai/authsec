package platform

import (
	"errors"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ApplicationsV2Controller serves the tenant-scoped Application registry —
// resource_servers rows that represent MCP servers, AI agents, Clawbots and
// API services on the prod backport.
//
// Routes (mounted under /authsec/oauth/v2 in routes.go):
//
//	POST   /authsec/applications
//	GET    /authsec/applications
//	GET    /authsec/applications/:id
//	DELETE /authsec/applications/:id
type ApplicationsV2Controller struct {
	service       *services.ResourceServerService
	onboardingSvc *services.ApplicationOnboardingService
	sdkPolicySvc  *services.SDKPolicyService
	adminSvc      *services.ApplicationAdminService
}

func NewApplicationsV2Controller() *ApplicationsV2Controller {
	return &ApplicationsV2Controller{
		service:       services.NewResourceServerService(),
		onboardingSvc: services.NewApplicationOnboardingService(),
		sdkPolicySvc:  services.NewSDKPolicyService(),
		adminSvc:      services.NewApplicationAdminService(),
	}
}

type createApplicationRequest struct {
	ApplicationType   string   `json:"application_type"`
	Name              string   `json:"name" binding:"required"`
	PublicBaseURL     string   `json:"public_base_url" binding:"required"`
	ProtectedBasePath string   `json:"protected_base_path,omitempty"`
	ResourceURI       string   `json:"resource_uri" binding:"required"`
	ScopesSupported   []string `json:"scopes_supported,omitempty"`
	RegistrationModes []string `json:"registration_modes,omitempty"`
}

func (ctrl *ApplicationsV2Controller) Create(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	var req createApplicationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	row, err := ctrl.service.Create(services.CreateResourceServerInput{
		TenantID:          tenantID,
		ApplicationType:   req.ApplicationType,
		Name:              req.Name,
		PublicBaseURL:     req.PublicBaseURL,
		ProtectedBasePath: req.ProtectedBasePath,
		ResourceURI:       req.ResourceURI,
		ScopesSupported:   req.ScopesSupported,
		RegistrationModes: req.RegistrationModes,
	})
	if err != nil {
		if errors.Is(err, services.ErrResourceURIInUse) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

func (ctrl *ApplicationsV2Controller) List(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	rows, err := ctrl.service.List(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (ctrl *ApplicationsV2Controller) Get(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	row, err := ctrl.service.GetByID(tenantID, id)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

// ListClients handles GET /authsec/applications/:id/clients. Returns the
// OAuth clients that have registered against this Application, joining the
// tenant-DB registration rows with the master-DB mcp_oauth_clients metadata.
func (ctrl *ApplicationsV2Controller) ListClients(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rows, err := ctrl.service.ListClientsForApplication(tenantID, id)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

// RotateIntrospectionSecret handles POST
// /authsec/applications/:id/rotate-introspection-secret. Returns the new
// plaintext secret in the response body. Old consumers continue to work
// until they pick up the new value.
func (ctrl *ApplicationsV2Controller) RotateIntrospectionSecret(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	secret, err := ctrl.service.RotateIntrospectionSecret(tenantID, id)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"introspection_secret": secret,
	})
}

func (ctrl *ApplicationsV2Controller) Delete(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	if err := ctrl.service.SoftDelete(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ─────────────────────────────────────────────────────────────────────────
// Validate / TestLogin / Launch / AccessPolicy — ported from authsec-dev
// `applications` group. See docs/mcp_oauth_v2.md for the gaps vs dev.
// ─────────────────────────────────────────────────────────────────────────

// Validate runs live onboarding-style checks against an Application and
// returns the aggregated status. POST /authsec/applications/:id/validate.
// PHASE3-NOTE: dev persists last_validated_at + last_validation_status on
// the row; we skip that write on the backport.
func (ctrl *ApplicationsV2Controller) Validate(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rs, err := ctrl.service.GetByID(tenantID, id)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	clientCount, err := ctrl.onboardingSvc.CountRegisteredClients(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	accessPolicyEnabled, err := ctrl.onboardingSvc.GetAccessPolicySummary(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := ctrl.onboardingSvc.ValidateResourceServer(rs, int(clientCount), accessPolicyEnabled)
	c.JSON(http.StatusOK, result)
}

// TestLogin returns a state snapshot of the Application + OAuth readiness.
// POST /authsec/applications/:id/test. PHASE3-NOTE: dev also returns
// tool_count and unmapped_tools from mcp_tools; we don't have that table
// on the backport so those counts are always 0.
func (ctrl *ApplicationsV2Controller) TestLogin(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rs, err := ctrl.service.GetByID(tenantID, id)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sdkPolicyState := rs.State
	if rs.State == "" {
		sdkPolicyState = "unknown"
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_server": gin.H{
			"id":     rs.ID.String(),
			"name":   rs.Name,
			"state":  rs.State,
			"status": rs.Status,
		},
		"oauth": gin.H{
			"state":       rs.State,
			"ready_since": rs.SetupCompletedAt,
		},
		"sdk_enforcement": gin.H{
			"sdk_policy_state": sdkPolicyState,
			"tool_count":       0,
			"unmapped_tools":   0,
		},
	})
}

// Launch returns the Application metadata + its current connection list,
// only when the row is in state='ready'. Mirrors dev exactly except for
// the workspace_id field (replaced by tenant_id).
// POST /authsec/applications/:id/launch.
func (ctrl *ApplicationsV2Controller) Launch(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rs, err := ctrl.service.GetByID(tenantID, id)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rs.State != models.RSStateReady {
		c.JSON(http.StatusConflict, gin.H{
			"error": "application not ready",
			"state": rs.State,
		})
		return
	}
	conns, err := ctrl.service.ListClientsForApplication(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"application_id":   rs.ID.String(),
		"application_type": rs.ApplicationType,
		"name":             rs.Name,
		"resource_uri":     rs.ResourceURI,
		"public_base_url":  rs.PublicBaseURL,
		"scopes_supported": rs.ScopesSupported,
		"connections":      conns,
		"tenant_id":        tenantID,
	})
}

// GetAccessPolicy returns the default-role policy for the Application.
// GET /authsec/applications/:id/access-policy (also aliased at /access).
func (ctrl *ApplicationsV2Controller) GetAccessPolicy(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	if _, err := ctrl.service.GetByID(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	policy, err := ctrl.onboardingSvc.GetAccessPolicy(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// UpdateAccessPolicy upserts the default-role policy for the Application.
// PUT /authsec/applications/:id/access-policy.
func (ctrl *ApplicationsV2Controller) UpdateAccessPolicy(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	if _, err := ctrl.service.GetByID(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var req services.UpdateApplicationAccessPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	policy, err := ctrl.onboardingSvc.UpdateAccessPolicy(tenantID, id, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// ─────────────────────────────────────────────────────────────────────────
// SDK-facing endpoints — Basic auth with RS introspection credentials.
// These are mounted OUTSIDE the JWT auth group in routes.go.
// ─────────────────────────────────────────────────────────────────────────

// SDKPolicy handles GET /authsec/applications/:id/sdk-policy. Returns the
// tool->scope policy the SDK uses to gate tool calls at runtime.
//
// Authentication: HTTP Basic with `<application_id>:<introspection_secret>`.
// 401 if missing or invalid. 404 if the Application doesn't exist (or the
// credentials are valid for a different application).
func (ctrl *ApplicationsV2Controller) SDKPolicy(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rs, tenantID, err := ctrl.sdkPolicySvc.AuthorizeFromBasic(c.GetHeader("Authorization"), id)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="sdk-policy"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	resp, err := ctrl.sdkPolicySvc.GetSDKPolicy(tenantID, rs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// PutSDKManifest handles PUT /authsec/applications/:id/sdk-manifest. Accepts
// the SDK's tool list and upserts mcp_tools rows. Authentication is the same
// Basic shape as SDKPolicy.
func (ctrl *ApplicationsV2Controller) PutSDKManifest(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rs, tenantID, err := ctrl.sdkPolicySvc.AuthorizeFromBasic(c.GetHeader("Authorization"), id)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="sdk-manifest"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req services.PublishManifestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	resp, err := ctrl.sdkPolicySvc.PublishManifest(tenantID, rs, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 1 — Easy reads (admin UI tabs: Tools, Scopes, Setup)
// ─────────────────────────────────────────────────────────────────────────

// ListTools handles GET /authsec/applications/:id/tools — same data the SDK
// reads via /sdk-policy but under JWT auth for the admin UI.
func (ctrl *ApplicationsV2Controller) ListTools(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	rows, err := ctrl.adminSvc.ListTools(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

// ListScopes handles GET /authsec/applications/:id/scopes.
func (ctrl *ApplicationsV2Controller) ListScopes(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	scopes, err := ctrl.adminSvc.ListScopes(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, scopes)
}

// GetScopeMatrix handles GET /authsec/applications/:id/scope-matrix.
func (ctrl *ApplicationsV2Controller) GetScopeMatrix(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	matrix, err := ctrl.adminSvc.GetScopeMatrix(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, matrix)
}

// GetSetupChecklist handles GET /authsec/applications/:id/setup.
func (ctrl *ApplicationsV2Controller) GetSetupChecklist(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	checklist, err := ctrl.adminSvc.GetSetupChecklist(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, checklist)
}

// GetSDKManifestStatus handles GET /authsec/applications/:id/sdk-manifest-status.
func (ctrl *ApplicationsV2Controller) GetSDKManifestStatus(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	status, err := ctrl.adminSvc.GetSDKManifestStatus(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, status)
}

// GetActivationPreview handles GET /authsec/applications/:id/activation-preview.
// Combines /setup + /validate into one round-trip the UI uses on the Setup tab.
func (ctrl *ApplicationsV2Controller) GetActivationPreview(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	preview, err := ctrl.adminSvc.GetActivationPreview(tenantID, id, ctrl.onboardingSvc)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, preview)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 2 — Activation state machine
// ─────────────────────────────────────────────────────────────────────────

// Activate handles POST /authsec/applications/:id/activate. Flips state to
// 'ready' if the setup checklist passes (or force=true in the body).
func (ctrl *ApplicationsV2Controller) Activate(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var body struct {
		Force bool `json:"force,omitempty"`
	}
	_ = c.ShouldBindJSON(&body)

	userIDStr, _ := middlewares.ResolveUserID(c)
	performedBy, _ := uuid.Parse(userIDStr)

	rs, err := ctrl.adminSvc.Activate(tenantID, id, performedBy, body.Force)
	if err != nil {
		if errors.Is(err, services.ErrAlreadyActivated) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrNotReadyToActivate) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
				"hint":  "GET /applications/:id/setup to see what's missing, or POST with {\"force\": true} to override",
			})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, rs)
}

// Rescan handles POST /authsec/applications/:id/rescan. Bumps scan_generation
// so SDK clients refetch /sdk-policy on next TTL.
func (ctrl *ApplicationsV2Controller) Rescan(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	resp, err := ctrl.adminSvc.Rescan(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 3 — Connection admin (pre-register + revoke)
// ─────────────────────────────────────────────────────────────────────────

// PreregisterConnection handles POST /authsec/applications/:id/connections.
// Admin-initiated OAuth client creation, bound to the Application.
func (ctrl *ApplicationsV2Controller) PreregisterConnection(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var req services.PreregisterConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	resp, err := ctrl.adminSvc.PreregisterConnection(tenantID, id, req)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusCreated, resp)
}

// RevokeConnection handles DELETE /authsec/applications/:id/connections/:client_id.
// Marks the join row revoked + queues the master mcp_oauth_clients row for
// Hydra-side deletion via the reconciler.
func (ctrl *ApplicationsV2Controller) RevokeConnection(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id required"})
		return
	}
	reason := c.Query("reason")
	if reason == "" {
		reason = "admin-revoked"
	}
	if err := ctrl.adminSvc.RevokeConnection(tenantID, id, clientID, reason); err != nil {
		if strings.Contains(err.Error(), "connection not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "already revoked") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

// resolveTenantAndID is a one-call helper for the handlers that need
// (tenant_id, application_id) and standard error responses. Returns ok=false
// after writing a 400/401 if either is missing/invalid.
func (ctrl *ApplicationsV2Controller) resolveTenantAndID(c *gin.Context) (tenantID string, id uuid.UUID, ok bool) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return "", uuid.Nil, false
	}
	id, err = uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return "", uuid.Nil, false
	}
	return tenantID, id, true
}

// respondAdminError maps service errors to consistent HTTP responses.
func (ctrl *ApplicationsV2Controller) respondAdminError(c *gin.Context, err error) {
	if errors.Is(err, services.ErrResourceServerNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}
