package platform

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/controllers/shared"
	hydramodels "github.com/authsec-ai/authsec/internal/hydra/models"
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
	govSvc        *services.GovernanceService
	idpConfigSvc  *services.IDPConfigService
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
		govSvc:        services.NewGovernanceService(),
		idpConfigSvc:  services.NewIDPConfigService(),
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

// ListEndUsers handles GET /authsec/applications/:id/end-users.
// Returns every end-user who registered / signed in to this Application
// (users.resource_server_id), regardless of whether they have an RBAC binding.
func (ctrl *ApplicationsV2Controller) ListEndUsers(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	users, err := ctrl.bindingSvc.ListEndUsers(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

// SetEndUserActive handles PATCH /authsec/applications/:id/end-users/:user_id.
// Body: {"active": bool}. Suspends or re-activates an end-user — a suspended
// user can no longer authenticate (custom-login + federated both reject).
func (ctrl *ApplicationsV2Controller) SetEndUserActive(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	var body struct {
		Active *bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Active == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "active (bool) is required"})
		return
	}
	if err := ctrl.bindingSvc.SetEndUserActive(tenantID, id, userID, *body.Active); err != nil {
		if errors.Is(err, services.ErrUserNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "end user not found for this application"})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "active": *body.Active})
}

// DeleteEndUser handles DELETE /authsec/applications/:id/end-users/:user_id.
func (ctrl *ApplicationsV2Controller) DeleteEndUser(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	if err := ctrl.bindingSvc.DeleteEndUser(tenantID, id, userID); err != nil {
		if errors.Is(err, services.ErrUserNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "end user not found for this application"})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
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

// ─────────────────────────────────────────────────────────────────────────
// Phase 9 — Governance views (read-only joins on Phase 5/6/8 tables)
// ─────────────────────────────────────────────────────────────────────────

// ListAccessAssignments handles GET /authsec/applications/:id/access-assignments.
// Audit-grade hydrated view of every binding. Filterable via query params:
//   ?user_id=<uuid>     restrict to a single user
//   ?role_id=<uuid>     restrict to a single role
//   ?granted_after=<RFC3339>
//   ?granted_before=<RFC3339>
func (ctrl *ApplicationsV2Controller) ListAccessAssignments(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	var filters services.AccessAssignmentFilters
	if v := c.Query("user_id"); v != "" {
		u, err := uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
			return
		}
		filters.UserID = u
	}
	if v := c.Query("role_id"); v != "" {
		r, err := uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
			return
		}
		filters.RoleID = r
	}
	if v := c.Query("granted_after"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid granted_after (expect RFC3339)"})
			return
		}
		filters.GrantedAfter = &t
	}
	if v := c.Query("granted_before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid granted_before (expect RFC3339)"})
			return
		}
		filters.GrantedBefore = &t
	}
	rows, err := ctrl.govSvc.ListAccessAssignments(tenantID, id, filters)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

// PreviewAccessChange handles GET /authsec/applications/:id/access-change-previews.
// Query params (NOT body — this is a GET):
//   user_id=<uuid>             required
//   add_role_ids=<csv of uuids>
//   remove_role_ids=<csv of uuids>
func (ctrl *ApplicationsV2Controller) PreviewAccessChange(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	userIDStr := c.Query("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id query param required"})
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	addIDs, err := parseCSVUUIDs(c.Query("add_role_ids"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid add_role_ids: " + err.Error()})
		return
	}
	removeIDs, err := parseCSVUUIDs(c.Query("remove_role_ids"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remove_role_ids: " + err.Error()})
		return
	}
	preview, err := ctrl.govSvc.PreviewAccessChange(tenantID, id, services.AccessChangePreviewRequest{
		UserID:      userID,
		AddRoles:    addIDs,
		RemoveRoles: removeIDs,
	})
	if err != nil {
		if errors.Is(err, services.ErrUserNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if strings.Contains(err.Error(), "role") && strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, preview)
}

// SimulateAccess handles GET /authsec/applications/:id/access-simulations.
// Query params:
//   user_id=<uuid>     required
//   role_ids=<csv of uuids>  the role set to simulate (empty = no roles)
func (ctrl *ApplicationsV2Controller) SimulateAccess(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	userIDStr := c.Query("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id query param required"})
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	roleIDs, err := parseCSVUUIDs(c.Query("role_ids"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_ids: " + err.Error()})
		return
	}
	resp, err := ctrl.govSvc.SimulateAccess(tenantID, id, services.AccessSimulationRequest{
		UserID:  userID,
		RoleIDs: roleIDs,
	})
	if err != nil {
		if errors.Is(err, services.ErrUserNotInTenant) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if strings.Contains(err.Error(), "role_ids not found") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// GetApplicationEffectiveAccess handles
// GET /authsec/applications/:id/effective-access. Application-wide
// effective-scope view for all bound users.
func (ctrl *ApplicationsV2Controller) GetApplicationEffectiveAccess(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	rows, err := ctrl.govSvc.GetApplicationEffectiveAccess(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

// EndUserAccessSummary handles GET /authsec/applications/:id/end-user-access-summary.
// Paged via ?page= and ?limit= (page is 1-indexed).
func (ctrl *ApplicationsV2Controller) EndUserAccessSummary(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	page := 1
	if v := c.Query("page"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			page = parsed
		}
	}
	limit := 50
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
	}
	pageData, err := ctrl.govSvc.EndUserAccessSummary(tenantID, id, page, limit)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, pageData)
}

// EvidenceExport handles GET /authsec/applications/:id/evidence-exports.
// Returns one JSON row per (user, role, scope) — designed to be loaded
// into CSV by the consumer.
func (ctrl *ApplicationsV2Controller) EvidenceExport(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	rows, err := ctrl.govSvc.EvidenceExport(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

// PostureSummary handles GET /authsec/applications/:id/posture-summary.
// Single-shot compliance snapshot.
func (ctrl *ApplicationsV2Controller) PostureSummary(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	summary, err := ctrl.govSvc.GetPostureSummary(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, summary)
}

// ToolExposure handles GET /authsec/applications/:id/tool-exposure.
// One row per tool with the user-email list of who can reach it.
func (ctrl *ApplicationsV2Controller) ToolExposure(c *gin.Context) {
	tenantID, id, ok := ctrl.resolveTenantAndID(c)
	if !ok {
		return
	}
	rows, err := ctrl.govSvc.GetToolExposure(tenantID, id)
	if err != nil {
		ctrl.respondAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

// parseCSVUUIDs parses a comma-separated list of UUIDs. Empty input
// returns nil, nil (caller treats nil as "none").
func parseCSVUUIDs(raw string) ([]uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		u, err := uuid.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("invalid uuid %q: %w", p, err)
		}
		out = append(out, u)
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Per-MCP IDP config CRUD (migration 035)
//
// Each Application can override the tenant's default Google/Okta/SAML IDP
// configuration with its own row. Tenant-wide rows (resource_server_id IS
// NULL) stay managed via the legacy /authsec/oocmgr/* surface; this CRUD
// only writes per-MCP rows scoped to the URL's :id Application.
// ─────────────────────────────────────────────────────────────────────────

// ListOIDCProviders handles GET /authsec/applications/:id/oidc-providers.
// Returns both per-MCP rows for this Application and the tenant-wide
// defaults so admins can see the full resolved view in one call.
func (ctrl *ApplicationsV2Controller) ListOIDCProviders(c *gin.Context) {
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
	rows, err := ctrl.idpConfigSvc.ListOIDCProviders(tenantID, id)
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

// CreateOIDCProvider handles POST /authsec/applications/:id/oidc-providers.
func (ctrl *ApplicationsV2Controller) CreateOIDCProvider(c *gin.Context) {
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
	var in services.OIDCProviderInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	row, err := ctrl.idpConfigSvc.CreateOIDCProvider(tenantID, id, in)
	if err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

// UpdateOIDCProvider handles PUT /authsec/applications/:id/oidc-providers/:provider_id.
func (ctrl *ApplicationsV2Controller) UpdateOIDCProvider(c *gin.Context) {
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
	providerID, err := uuid.Parse(c.Param("provider_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
		return
	}
	var in services.OIDCProviderInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	row, err := ctrl.idpConfigSvc.UpdateOIDCProvider(tenantID, id, providerID, in)
	if err != nil {
		if errors.Is(err, services.ErrIDPConfigNotFound) || errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

// DeleteOIDCProvider handles DELETE /authsec/applications/:id/oidc-providers/:provider_id.
func (ctrl *ApplicationsV2Controller) DeleteOIDCProvider(c *gin.Context) {
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
	providerID, err := uuid.Parse(c.Param("provider_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
		return
	}
	if err := ctrl.idpConfigSvc.DeleteOIDCProvider(tenantID, id, providerID); err != nil {
		if errors.Is(err, services.ErrIDPConfigNotFound) || errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SAMLProviderInput is the body of POST + PUT for SAML provider CRUD. Same
// partial-update pattern as OIDC. Lives in the controller (not services)
// because the SAML model lives in internal/hydra/models which can't be
// imported from services (would cause a cycle).
type SAMLProviderInput struct {
	ProviderName     string  `json:"provider_name"`
	DisplayName      string  `json:"display_name"`
	EntityID         string  `json:"entity_id"`
	SSOURL           string  `json:"sso_url"`
	SLOURL           string  `json:"slo_url,omitempty"`
	Certificate      string  `json:"certificate"`
	MetadataURL      string  `json:"metadata_url,omitempty"`
	NameIDFormat     string  `json:"name_id_format,omitempty"`
	AttributeMapping *string `json:"attribute_mapping,omitempty"` // JSON string; nil = don't change
	IsActive         *bool   `json:"is_active,omitempty"`
	SortOrder        *int    `json:"sort_order,omitempty"`
}

// ListSAMLProviders handles GET /authsec/applications/:id/saml-providers.
func (ctrl *ApplicationsV2Controller) ListSAMLProviders(c *gin.Context) {
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
	if _, err := ctrl.idpConfigSvc.EnsureApplication(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	tenantDB, err := ctrl.idpConfigSvc.TenantDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant db unavailable"})
		return
	}
	var rows []hydramodels.SAMLProvider
	if err := tenantDB.
		Where("resource_server_id = ? OR resource_server_id IS NULL", id).
		Order("resource_server_id NULLS LAST, sort_order ASC, provider_name ASC").
		Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list saml_providers: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

// CreateSAMLProvider handles POST /authsec/applications/:id/saml-providers.
func (ctrl *ApplicationsV2Controller) CreateSAMLProvider(c *gin.Context) {
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
	if _, err := ctrl.idpConfigSvc.EnsureApplication(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var in SAMLProviderInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if in.ProviderName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_name required"})
		return
	}
	if in.EntityID == "" || in.SSOURL == "" || in.Certificate == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity_id, sso_url, and certificate are all required"})
		return
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}
	tenantDB, err := ctrl.idpConfigSvc.TenantDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant db unavailable"})
		return
	}
	displayName := in.DisplayName
	if displayName == "" {
		displayName = in.ProviderName
	}
	nameIDFormat := in.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	sortOrder := 0
	if in.SortOrder != nil {
		sortOrder = *in.SortOrder
	}
	rs := id
	row := hydramodels.SAMLProvider{
		TenantID:         tenantUUID,
		ResourceServerID: &rs,
		ProviderName:     in.ProviderName,
		DisplayName:      displayName,
		EntityID:         in.EntityID,
		SSOURL:           in.SSOURL,
		SLOURL:           in.SLOURL,
		Certificate:      in.Certificate,
		MetadataURL:      in.MetadataURL,
		NameIDFormat:     nameIDFormat,
		IsActive:         in.IsActive == nil || *in.IsActive,
		SortOrder:        sortOrder,
	}
	if in.AttributeMapping != nil {
		row.AttributeMapping = []byte(*in.AttributeMapping)
	}
	if err := tenantDB.Create(&row).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "insert saml_providers: " + err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

// UpdateSAMLProvider handles PUT /authsec/applications/:id/saml-providers/:provider_id.
func (ctrl *ApplicationsV2Controller) UpdateSAMLProvider(c *gin.Context) {
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
	providerID, err := uuid.Parse(c.Param("provider_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
		return
	}
	if _, err := ctrl.idpConfigSvc.EnsureApplication(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var in SAMLProviderInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	tenantDB, err := ctrl.idpConfigSvc.TenantDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant db unavailable"})
		return
	}
	var row hydramodels.SAMLProvider
	if err := tenantDB.
		Where("id = ? AND resource_server_id = ?", providerID, id).
		First(&row).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}
	updates := map[string]interface{}{}
	if in.ProviderName != "" {
		updates["provider_name"] = in.ProviderName
	}
	if in.DisplayName != "" {
		updates["display_name"] = in.DisplayName
	}
	if in.EntityID != "" {
		updates["entity_id"] = in.EntityID
	}
	if in.SSOURL != "" {
		updates["sso_url"] = in.SSOURL
	}
	if in.SLOURL != "" {
		updates["slo_url"] = in.SLOURL
	}
	if in.Certificate != "" {
		updates["certificate"] = in.Certificate
	}
	if in.MetadataURL != "" {
		updates["metadata_url"] = in.MetadataURL
	}
	if in.NameIDFormat != "" {
		updates["name_id_format"] = in.NameIDFormat
	}
	if in.AttributeMapping != nil {
		updates["attribute_mapping"] = []byte(*in.AttributeMapping)
	}
	if in.IsActive != nil {
		updates["is_active"] = *in.IsActive
	}
	if in.SortOrder != nil {
		updates["sort_order"] = *in.SortOrder
	}
	if len(updates) > 0 {
		if err := tenantDB.Model(&row).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "update saml_providers: " + err.Error()})
			return
		}
		if err := tenantDB.Where("id = ?", providerID).First(&row).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, row)
}

// DeleteSAMLProvider handles DELETE /authsec/applications/:id/saml-providers/:provider_id.
func (ctrl *ApplicationsV2Controller) DeleteSAMLProvider(c *gin.Context) {
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
	providerID, err := uuid.Parse(c.Param("provider_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
		return
	}
	if _, err := ctrl.idpConfigSvc.EnsureApplication(tenantID, id); err != nil {
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	tenantDB, err := ctrl.idpConfigSvc.TenantDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant db unavailable"})
		return
	}
	res := tenantDB.
		Where("id = ? AND resource_server_id = ?", providerID, id).
		Delete(&hydramodels.SAMLProvider{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete saml_providers: " + res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
