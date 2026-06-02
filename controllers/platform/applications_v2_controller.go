package platform

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	driftSvc      *services.DriftService
	scopeSvc      *services.ScopeService
	toolMapSvc    *services.ToolMappingService
	roleSvc       *services.RoleService
	bindingSvc    *services.BindingService
}

func NewApplicationsV2Controller() *ApplicationsV2Controller {
	return &ApplicationsV2Controller{
		service:       services.NewResourceServerService(),
		onboardingSvc: services.NewApplicationOnboardingService(),
		sdkPolicySvc:  services.NewSDKPolicyService(),
		adminSvc:      services.NewApplicationAdminService(),
		driftSvc:      services.NewDriftService(),
		scopeSvc:      services.NewScopeService(),
		toolMapSvc:    services.NewToolMappingService(),
		roleSvc:       services.NewRoleService(),
		bindingSvc:    services.NewBindingService(),
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
	// Drift: any RS that's already activated cares that its secret moved.
	// Best-effort — log but don't block on emit failure.
	ctrl.emitDrift(c, tenantID, id, models.DriftEventSecretRotated, map[string]interface{}{
		"rotated_at": time.Now().UTC().Format(time.RFC3339),
	})
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
	// Capture prior state so we can detect a transition to disabled.
	priorPolicy, _ := ctrl.onboardingSvc.GetAccessPolicy(tenantID, id)
	priorEnabled := priorPolicy != nil && priorPolicy.Enabled

	policy, err := ctrl.onboardingSvc.UpdateAccessPolicy(tenantID, id, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Drift: enabled -> disabled means new first-time users will no longer
	// auto-bind to the default role. Worth surfacing in the banner.
	if priorEnabled && !policy.Enabled {
		ctrl.emitDrift(c, tenantID, id, models.DriftEventDefaultRoleDisabled, map[string]interface{}{
			"prior_default_role_id": priorPolicy.DefaultRoleID,
		})
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
	// Drift: revoking a connection means clients holding tokens issued
	// before this moment will fail introspection on their next call.
	ctrl.emitDrift(c, tenantID, id, models.DriftEventConnectionRevoked, map[string]interface{}{
		"client_id": clientID,
		"reason":    reason,
	})
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

// emitDrift is the best-effort wrapper around DriftService.EmitEvent. Used
// by retrofitted handlers (RotateIntrospectionSecret, UpdateAccessPolicy,
// RevokeConnection). Logs but never blocks the originating mutation.
func (ctrl *ApplicationsV2Controller) emitDrift(
	c *gin.Context,
	tenantID string,
	applicationID uuid.UUID,
	eventType string,
	payload interface{},
) {
	userIDStr, _ := middlewares.ResolveUserID(c)
	var occurredBy *uuid.UUID
	if u, err := uuid.Parse(userIDStr); err == nil {
		occurredBy = &u
	}
	if err := ctrl.driftSvc.EmitEvent(tenantID, applicationID, eventType, payload, occurredBy); err != nil {
		log.Printf("[drift] emit %s for application=%s failed: %v", eventType, applicationID, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 4 — Drift event reads + dismissals
// ─────────────────────────────────────────────────────────────────────────

// ListDriftEvents handles GET /authsec/applications/:id/drift-events.
// Query params: ?undismissed=true to filter out events the calling admin
// has already dismissed (default: include all, with `dismissed_by_me` flag).
func (ctrl *ApplicationsV2Controller) ListDriftEvents(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	userIDStr, _ := middlewares.ResolveUserID(c)
	adminUserID, _ := uuid.Parse(userIDStr) // uuid.Nil is fine — service handles it
	undismissedOnly := c.Query("undismissed") == "true"

	events, err := ctrl.driftSvc.List(tenantID, id, adminUserID, undismissedOnly)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, events)
}

// DismissDriftEvent handles POST /authsec/applications/:id/drift-events/:event_id/dismiss.
// Idempotent — already-dismissed returns 200 without error.
func (ctrl *ApplicationsV2Controller) DismissDriftEvent(c *gin.Context) {
	tenantID, _, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	eventID, err := uuid.Parse(c.Param("event_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event_id"})
		return
	}
	userIDStr, _ := middlewares.ResolveUserID(c)
	adminUserID, err := uuid.Parse(userIDStr)
	if err != nil || adminUserID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin user id not in context"})
		return
	}
	if err := ctrl.driftSvc.Dismiss(tenantID, eventID, adminUserID); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "drift event not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "dismissed"})
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 5 — Scope CRUD
// ─────────────────────────────────────────────────────────────────────────

// CreateScope handles POST /authsec/applications/:id/scopes.
func (ctrl *ApplicationsV2Controller) CreateScope(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var req services.CreateScopeInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	scope, err := ctrl.scopeSvc.Create(tenantID, id, req)
	if err != nil {
		if errors.Is(err, services.ErrScopeAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidRiskLevel) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusCreated, scope)
}

// UpdateScope handles PUT /authsec/applications/:id/scopes/:scope_id.
// scope_string is immutable post-create — display name / description /
// risk level only.
func (ctrl *ApplicationsV2Controller) UpdateScope(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope_id"})
		return
	}
	var req services.UpdateScopeInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	scope, err := ctrl.scopeSvc.Update(tenantID, id, scopeID, req)
	if err != nil {
		if errors.Is(err, services.ErrScopeNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidRiskLevel) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, scope)
}

// DeleteScope handles DELETE /authsec/applications/:id/scopes/:scope_id.
// Strips the scope from resource_servers.scopes_supported AND from every
// affected tool's required_scopes. Emits scope_deleted drift event AND
// tool_unmapped drift events for tools that lost their last required scope.
func (ctrl *ApplicationsV2Controller) DeleteScope(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope_id"})
		return
	}
	result, err := ctrl.scopeSvc.Delete(tenantID, id, scopeID)
	if err != nil {
		if errors.Is(err, services.ErrScopeNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	// Drift: the scope itself was deleted.
	ctrl.emitDrift(c, tenantID, id, models.DriftEventScopeDeleted, map[string]interface{}{
		"scope_string":   result.ScopeString,
		"affected_tools": result.AffectedTools,
	})
	// Drift: any tool that lost all its required scopes is now unmapped.
	// We could be more precise (only emit when len(required_scopes) became
	// empty), but emitting per affected tool gives clearer banner signals.
	for _, toolName := range result.AffectedTools {
		ctrl.emitDrift(c, tenantID, id, models.DriftEventToolUnmapped, map[string]interface{}{
			"tool_name":      toolName,
			"reason":         "scope_deleted",
			"deleted_scope":  result.ScopeString,
		})
	}
	c.JSON(http.StatusOK, result)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 6 — Tool ↔ scope mapping
// ─────────────────────────────────────────────────────────────────────────

// UpdateToolScopeMap handles PUT /authsec/applications/:id/tool-scope-map.
// Body: {tool_id, required_scopes}. Validates every scope is registered
// for the Application.
func (ctrl *ApplicationsV2Controller) UpdateToolScopeMap(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var body struct {
		ToolID         string   `json:"tool_id" binding:"required"`
		RequiredScopes []string `json:"required_scopes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	toolID, err := uuid.Parse(body.ToolID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool_id"})
		return
	}
	result, err := ctrl.toolMapSvc.UpdateToolScopeMap(tenantID, id, toolID,
		services.UpdateToolScopeMapInput{RequiredScopes: body.RequiredScopes})
	if err != nil {
		if errors.Is(err, services.ErrToolNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "not registered for this application") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	if result.ProtectionWeakened {
		ctrl.emitDrift(c, tenantID, id, models.DriftEventToolUnmapped, map[string]interface{}{
			"tool_name":       result.Tool.Name,
			"reason":          "required_scopes_cleared",
			"prior_required":  result.PriorRequiredScopes,
		})
	}
	c.JSON(http.StatusOK, result)
}

// MarkToolPublic handles POST /authsec/applications/:id/tools/:tool_id/public.
// Body: {is_public}. Flips the bit; emits drift event if the change makes
// the tool publicly callable when it wasn't before.
func (ctrl *ApplicationsV2Controller) MarkToolPublic(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	toolID, err := uuid.Parse(c.Param("tool_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool_id"})
		return
	}
	var body services.MarkToolPublicInput
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	result, err := ctrl.toolMapSvc.MarkToolPublic(tenantID, id, toolID, body)
	if err != nil {
		if errors.Is(err, services.ErrToolNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	if result.ProtectionWeakened {
		ctrl.emitDrift(c, tenantID, id, models.DriftEventToolUnmapped, map[string]interface{}{
			"tool_name": result.Tool.Name,
			"reason":    "marked_public",
		})
	}
	c.JSON(http.StatusOK, result)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 8 part 1 — Application-scoped RBAC roles + scope grants
// ─────────────────────────────────────────────────────────────────────────

// ListRoles handles GET /authsec/applications/:id/roles. Returns every
// role for the Application, hydrated with the scope grants on each.
func (ctrl *ApplicationsV2Controller) ListRoles(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	roles, err := ctrl.roleSvc.List(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, roles)
}

// CreateRole handles POST /authsec/applications/:id/roles.
// Body: {name, description?, scope_ids?}.
func (ctrl *ApplicationsV2Controller) CreateRole(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var req services.CreateRoleInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	role, err := ctrl.roleSvc.Create(tenantID, id, req)
	if err != nil {
		if errors.Is(err, services.ErrRoleAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidScopeID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusCreated, role)
}

// UpdateRoleScopeGrants handles PUT /authsec/applications/:id/roles/:role_id/scope-grants.
// Replace semantics: pass the complete desired set; anything not in the
// list gets removed. Pass {"scope_ids": []} to strip all grants.
func (ctrl *ApplicationsV2Controller) UpdateRoleScopeGrants(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}
	var req services.UpdateScopeGrantsInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	role, err := ctrl.roleSvc.UpdateScopeGrants(tenantID, id, roleID, req)
	if err != nil {
		if errors.Is(err, services.ErrRoleNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidScopeID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, role)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 8 part 2 — Bindings + user access reads
// ─────────────────────────────────────────────────────────────────────────

// ListBindings handles GET /authsec/applications/:id/bindings. Returns
// every binding for the Application, hydrated with user email/name and
// role name.
func (ctrl *ApplicationsV2Controller) ListBindings(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	bindings, err := ctrl.bindingSvc.ListBindings(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, bindings)
}

// CreateBinding handles POST /authsec/applications/:id/bindings.
// Body: {user_id, role_id}.
func (ctrl *ApplicationsV2Controller) CreateBinding(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var req services.CreateBindingInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	grantedByStr, _ := middlewares.ResolveUserID(c)
	grantedBy, _ := uuid.Parse(grantedByStr)

	binding, err := ctrl.bindingSvc.CreateBinding(tenantID, id, req, grantedBy)
	if err != nil {
		if errors.Is(err, services.ErrBindingAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrRoleNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role not found in this application"})
			return
		}
		if errors.Is(err, services.ErrUserNotInTenant) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found in this tenant"})
			return
		}
		if strings.Contains(err.Error(), "invalid user_id") || strings.Contains(err.Error(), "invalid role_id") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusCreated, binding)
}

// DeleteBinding handles DELETE /authsec/applications/:id/bindings/:binding_id.
func (ctrl *ApplicationsV2Controller) DeleteBinding(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	bindingID, err := uuid.Parse(c.Param("binding_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid binding_id"})
		return
	}
	if err := ctrl.bindingSvc.DeleteBinding(tenantID, id, bindingID); err != nil {
		if errors.Is(err, services.ErrBindingNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ListEligibleUsers handles GET /authsec/applications/:id/eligible-users.
// Query params: ?search=<email or name prefix>, ?limit=<1..500>.
func (ctrl *ApplicationsV2Controller) ListEligibleUsers(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	limit := 100
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
	}
	users, err := ctrl.bindingSvc.ListEligibleUsers(tenantID, id, c.Query("search"), limit)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

// ListAccessUsers handles GET /authsec/applications/:id/access/users.
// Returns every user with at least one binding on this Application.
func (ctrl *ApplicationsV2Controller) ListAccessUsers(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	users, err := ctrl.bindingSvc.ListAccessUsers(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

// GetUserEffectiveAccess handles
// GET /authsec/applications/:id/users/:user_id/effective-access.
// Returns the user's per-role grants + aggregated effective scopes.
func (ctrl *ApplicationsV2Controller) GetUserEffectiveAccess(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	access, err := ctrl.bindingSvc.GetEffectiveAccess(tenantID, id, userID)
	if err != nil {
		if errors.Is(err, services.ErrUserNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, access)
}
