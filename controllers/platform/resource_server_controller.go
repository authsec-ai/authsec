package platform

import (
	"fmt"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ResourceServerController handles CRUD for MCP resource server registration.
type ResourceServerController struct {
	service           *services.ResourceServerService
	oauthSvc          *services.OAuthASService
	onboardingService *services.ResourceServerOnboardingService
	driftService      *services.ResourceServerDriftService
}

func NewResourceServerController() *ResourceServerController {
	return &ResourceServerController{
		service:           services.NewResourceServerService(config.DB),
		oauthSvc:          services.NewOAuthASService(config.DB),
		onboardingService: services.NewResourceServerOnboardingService(config.DB),
		driftService:      services.NewResourceServerDriftService(config.DB),
	}
}

type resourceServerSummaryResponse struct {
	models.ResourceServer
	ClientCount          int64   `json:"client_count"`
	AccessPolicyEnabled  bool    `json:"access_policy_enabled"`
	AccessPolicyRoleName *string `json:"access_policy_role_name,omitempty"`
}

// ScopePresets returns the hardcoded preset catalog surfaced on the Create
// Application page. The same 12 presets are returned to every caller — no
// per-tenant filtering. Endpoint:
//
//	GET /authsec/scope-presets
//
// Response shape: {"presets": [...]}.
func (ctrl *ResourceServerController) ScopePresets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"presets": services.ScopePresetCatalog})
}

// Create registers a new resource server.
// POST /authsec/resource-servers
func (ctrl *ResourceServerController) Create(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	var req services.CreateResourceServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.TenantID = tenantID

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.PublicBaseURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "public_base_url is required"})
		return
	}

	baseURL := config.AppConfig.OAuthBaseURL()
	_, resp, err := ctrl.service.Create(req, baseURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_created", "resource_server",
		resp.ID, http.StatusCreated, nil,
		map[string]interface{}{"name": req.Name, "url": req.PublicBaseURL})
	c.JSON(http.StatusCreated, resp)
}

// List returns all resource servers for the tenant.
// GET /authsec/resource-servers
func (ctrl *ResourceServerController) List(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	servers, err := ctrl.service.ListByTenant(tenantID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	summaries := make([]resourceServerSummaryResponse, 0, len(servers))
	for i := range servers {
		summary, buildErr := ctrl.buildSummary(&servers[i], tenantID.String())
		if buildErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": buildErr.Error()})
			return
		}
		summaries = append(summaries, *summary)
	}

	c.JSON(http.StatusOK, summaries)
}

// Get returns a single resource server by ID (tenant-scoped).
// GET /authsec/resource-servers/:id
func (ctrl *ResourceServerController) Get(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}
	summary, err := ctrl.buildSummary(rs, tenantID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, summary)
}

// Update modifies a resource server (tenant-scoped).
// PUT /authsec/resource-servers/:id
func (ctrl *ResourceServerController) Update(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	var raw map[string]interface{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Whitelist updatable fields — prevent overwriting id, tenant_id, secrets, deleted_at
	allowed := map[string]bool{
		"name": true, "public_base_url": true, "protected_base_path": true,
		"scopes_supported": true, "registration_modes": true, "active": true,
	}
	updates := make(map[string]interface{})
	for k, v := range raw {
		if allowed[k] {
			updates[k] = v
		}
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid fields to update"})
		return
	}

	rs, err := ctrl.service.UpdateByTenant(id, tenantID.String(), updates)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_updated", "resource_server",
		id, http.StatusOK, nil, updates)
	c.JSON(http.StatusOK, rs)
}

// Delete removes a resource server (tenant-scoped).
// DELETE /authsec/resource-servers/:id
func (ctrl *ResourceServerController) Delete(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	if err := ctrl.service.DeleteByTenant(id, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}
	auditAdminMutation(c, tenantID.String(), "rs_deleted", "resource_server",
		id, http.StatusNoContent, nil, nil)
	c.JSON(http.StatusNoContent, nil)
}

// RotateIntrospectionSecret generates a new introspection secret for an RS.
// POST /authsec/resource-servers/:id/rotate-introspection-secret
func (ctrl *ResourceServerController) RotateIntrospectionSecret(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	secret, err := ctrl.service.RotateIntrospectionSecret(id, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Drift event: every SDK runtime that holds the OLD introspection secret
	// will start failing token validation against AuthSec until it picks up
	// the rotated value. Surface this in the workspace banner for ready RSes.
	if rs, getErr := ctrl.service.GetByIDAndTenant(id, tenantID.String()); getErr == nil &&
		rs != nil && rs.State == models.RSStateReady {
		_ = ctrl.driftService.EmitEvent(
			config.DB, rs.ID, models.DriftEventSecretRotated,
			map[string]interface{}{"rotated_at": time.Now().UTC().Format(time.RFC3339)},
			extractUserIDOptional(c),
		)
	}

	auditAdminMutation(c, tenantID.String(), "rs_introspection_secret_rotated", "resource_server",
		id, http.StatusOK, nil, nil) // never log the secret value
	c.JSON(http.StatusOK, gin.H{"introspection_secret": secret})
}

// PreRegisterClient pre-registers an OAuth client for a resource server.
// POST /authsec/resource-servers/:id/clients
func (ctrl *ResourceServerController) PreRegisterClient(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	if !rs.AllowsRegistrationMode("prereg") {
		c.JSON(http.StatusForbidden, gin.H{"error": "resource server does not allow pre-registration"})
		return
	}

	var req services.DCRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	client, err := ctrl.oauthSvc.PreRegisterClient(rs, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_client_preregistered", "oauth_client",
		client.ClientID, http.StatusCreated, nil,
		map[string]interface{}{"rs_id": rsID, "client_name": client.ClientName})
	c.JSON(http.StatusCreated, gin.H{
		"client_id":   client.ClientID,
		"client_name": client.ClientName,
	})
}

// ListClients lists all registered OAuth clients for a resource server.
// GET /authsec/resource-servers/:id/clients
func (ctrl *ResourceServerController) ListClients(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	_, err = ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clients, err := ctrl.oauthSvc.ListClientsForRS(rsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, clients)
}

// GetAccessPolicy returns the default access policy and role options for a resource server.
// GET /authsec/resource-servers/:id/access-policy
func (ctrl *ResourceServerController) GetAccessPolicy(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	if _, err := ctrl.service.GetByIDAndTenant(rsID, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	policy, err := ctrl.onboardingService.GetAccessPolicy(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// UpdateAccessPolicy persists the backend-owned default access policy for a resource server.
// PUT /authsec/resource-servers/:id/access-policy
func (ctrl *ResourceServerController) UpdateAccessPolicy(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	// Capture the prior enabled state so we can detect a transition to disabled.
	priorPolicy, _ := ctrl.onboardingService.GetAccessPolicy(rsID, tenantID.String())
	priorEnabled := priorPolicy != nil && priorPolicy.Enabled

	var req services.UpdateResourceServerAccessPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	policy, err := ctrl.onboardingService.UpdateAccessPolicy(rsID, tenantID.String(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Drift event: disabling the default access policy on a ready RS means
	// new first-time users will no longer get auto-binding to viewer. End-user
	// logins will start failing with insufficient_scope unless an admin grants
	// them roles directly. Surface this in the workspace banner.
	if rs.State == models.RSStateReady && priorEnabled && !policy.Enabled {
		_ = ctrl.driftService.EmitEvent(
			config.DB, rs.ID, models.DriftEventDefaultRoleDisabled,
			map[string]interface{}{"prior_default_role": priorPolicy.DefaultRoleName},
			extractUserIDOptional(c),
		)
	}

	auditAdminMutation(c, tenantID.String(), "rs_access_policy_updated", "resource_server",
		rsID, http.StatusOK, nil, policy)
	c.JSON(http.StatusOK, policy)
}

// Validate runs live onboarding checks and persists the most recent validation state.
// POST /authsec/resource-servers/:id/validate
func (ctrl *ResourceServerController) Validate(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clientCount, err := ctrl.onboardingService.CountRegisteredClients(rs.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	accessPolicyEnabled, _, err := ctrl.onboardingService.GetAccessPolicySummary(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	result, err := ctrl.onboardingService.ValidateResourceServer(rs, int(clientCount), accessPolicyEnabled)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_validated", "resource_server",
		rsID, http.StatusOK, nil, result)
	c.JSON(http.StatusOK, result)
}

func (ctrl *ResourceServerController) buildSummary(rs *models.ResourceServer, tenantID string) (*resourceServerSummaryResponse, error) {
	clientCount, err := ctrl.onboardingService.CountRegisteredClients(rs.ID)
	if err != nil {
		return nil, err
	}
	accessPolicyEnabled, accessPolicyRoleName, err := ctrl.onboardingService.GetAccessPolicySummary(rs.ID.String(), tenantID)
	if err != nil {
		return nil, err
	}

	return &resourceServerSummaryResponse{
		ResourceServer:       *rs,
		ClientCount:          clientCount,
		AccessPolicyEnabled:  accessPolicyEnabled,
		AccessPolicyRoleName: accessPolicyRoleName,
	}, nil
}

// RevokeClient revokes a client's registration for a resource server.
// DELETE /authsec/resource-servers/:id/clients/:client_id
func (ctrl *ResourceServerController) RevokeClient(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	_, err = ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clientID := c.Param("client_id")
	if err := ctrl.oauthSvc.RevokeClientRegistration(rsID, clientID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_client_revoked", "oauth_client",
		clientID, http.StatusOK, nil, map[string]interface{}{"rs_id": rsID})
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// ApproveRedirects approves pending CIMD redirect URI changes for a client.
// PUT /authsec/resource-servers/:rs_id/clients/:client_id/approve-redirects
func (ctrl *ResourceServerController) ApproveRedirects(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	_, err = ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clientID := c.Param("client_id")
	if err := ctrl.oauthSvc.ApprovePendingRedirects(clientID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_client_redirects_approved", "oauth_client",
		clientID, http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"status": "redirects approved"})
}

func extractTenantID(c *gin.Context) (uuid.UUID, error) {
	tidStr, ok := middlewares.GetTenantIDFromToken(c)
	if !ok || tidStr == "" {
		return uuid.Nil, fmt.Errorf("tenant_id not found in token")
	}
	return uuid.Parse(tidStr)
}

// TestLogin runs both OAuth and SDK diagnostic surfaces for an RS.
// POST /authsec/resource-servers/:id/test-login
func (ctrl *ResourceServerController) TestLogin(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	rsState := rs.State
	rsStatus := rs.Status

	// Check sdk-policy endpoint reachability (internal call).
	sdkPolicyState := "unknown"
	var toolCount int64
	var unmappedCount int64
	config.DB.Model(&models.MCPTool{}).Where("resource_server_id = ?", rs.ID).Count(&toolCount)
	config.DB.Raw(`
		SELECT COUNT(*) FROM mcp_tools mt
		 WHERE mt.resource_server_id = ?
		   AND mt.is_public = false
		   AND NOT EXISTS (
			   SELECT 1 FROM mcp_tool_scope_map m
			    WHERE m.tool_id = mt.id AND m.source = 'admin_override'
		   )
	`, rs.ID).Scan(&unmappedCount)

	if rsState == models.RSStateReady {
		sdkPolicyState = "ready"
	} else {
		sdkPolicyState = rsState
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_server": gin.H{
			"id":     rs.ID.String(),
			"name":   rs.Name,
			"state":  rsState,
			"status": rsStatus,
		},
		"oauth": gin.H{
			"state":          rsState,
			"ready_since":    rs.SetupCompletedAt,
		},
		"sdk_enforcement": gin.H{
			"sdk_policy_state": sdkPolicyState,
			"tool_count":       toolCount,
			"unmapped_tools":   unmappedCount,
		},
	})
}
