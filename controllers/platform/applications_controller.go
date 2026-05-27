package platform

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
)

// ApplicationsController serves the workspace-scoped Application facade.
//
// Applications are the product object — MCP servers, AI agents, Clawbots, and
// API services. The physical table is still resource_servers; this controller
// is the read/write surface that matches the v4 product model.
//
// Compared with ResourceServerController:
//   - workspace_id is sourced from the JWT and used for ownership filtering,
//     falling back to tenant_id during the rollout.
//   - application_type is accepted on create and used as a list filter.
//   - The OAuth client subresource is exposed under "connections" instead of
//     "clients" to remove the product-vs-protocol confusion.
//
// Anything not duplicated here (tools, scopes, access policy, validate, etc.)
// is mounted at /authsec/applications/:id/* in routes.go pointing at the
// existing ResourceServerController/ScopeMatrixController handlers — they
// don't care which URL prefix invoked them.
type ApplicationsController struct {
	service  *services.ResourceServerService
	oauthSvc *services.OAuthASService
}

func NewApplicationsController() *ApplicationsController {
	return &ApplicationsController{
		service:  services.NewResourceServerService(config.DB),
		oauthSvc: services.NewOAuthASService(config.DB),
	}
}

// applicationCreateRequest is the inbound payload for POST /authsec/applications.
// Mirrors services.CreateResourceServerRequest but accepts application_type as
// a first-class field — the only payload-shape divergence from the legacy
// resource_servers create.
type applicationCreateRequest struct {
	Name                 string   `json:"name" binding:"required"`
	PublicBaseURL        string   `json:"public_base_url" binding:"required"`
	ProtectedBasePath    string   `json:"protected_base_path,omitempty"`
	ApplicationType      string   `json:"application_type,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	RegistrationModes    []string `json:"registration_modes,omitempty"`
	ScopePresetID        *string  `json:"scope_preset_id,omitempty"`
	DefaultAccessEnabled *bool    `json:"default_access_enabled,omitempty"`
}

// Create handles POST /authsec/applications.
func (ctrl *ApplicationsController) Create(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var req applicationCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if !services.ValidApplicationType(req.ApplicationType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application_type"})
		return
	}

	svcReq := services.CreateResourceServerRequest{
		WorkspaceID:          workspaceID,
		Name:                 req.Name,
		PublicBaseURL:        req.PublicBaseURL,
		ProtectedBasePath:    req.ProtectedBasePath,
		ApplicationType:      req.ApplicationType,
		ScopesSupported:      req.ScopesSupported,
		RegistrationModes:    req.RegistrationModes,
		ScopePresetID:        req.ScopePresetID,
		DefaultAccessEnabled: req.DefaultAccessEnabled,
	}

	baseURL := config.AppConfig.OAuthBaseURL()
	_, resp, err := ctrl.service.Create(svcReq, baseURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "application_created", "application",
		resp.ID, http.StatusCreated, nil,
		map[string]interface{}{"name": req.Name, "application_type": svcReq.ApplicationType})
	c.JSON(http.StatusCreated, resp)
}

// List handles GET /authsec/applications. Supports ?application_type= filter.
func (ctrl *ApplicationsController) List(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	appType := c.Query("application_type")
	if !services.ValidApplicationType(appType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application_type filter"})
		return
	}

	apps, err := ctrl.service.ListByWorkspace(workspaceID.String(), appType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for i := range apps {
		app := &apps[i]
		config.DB.Table("mcp_tools").
			Where("tenant_id = ? AND resource_server_id = ?", workspaceID, app.ID).
			Count(&app.ToolsCount)
		config.DB.Table("oauth_scopes").
			Where("tenant_id = ? AND resource_server_id = ?", workspaceID, app.ID).
			Count(&app.ScopesCount)
		config.DB.Table("roles").
			Where("tenant_id = ? AND name LIKE ?", workspaceID, "rs-"+app.ID.String()+":%").
			Count(&app.RolesCount)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.tenant_id = ?", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Count(&app.BindingsCount)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.tenant_id = ? AND rb.user_id IS NOT NULL", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Select("COUNT(DISTINCT rb.user_id)").Scan(&app.EndUsersCount)
		config.DB.Table("resource_server_access_policies p").
			Select("COALESCE(r.name, '')").
			Joins("LEFT JOIN roles r ON r.id = p.default_role_id").
			Where("p.tenant_id = ? AND p.resource_server_id = ?", workspaceID, app.ID).
			Scan(&app.DefaultRoleName)
		if app.DefaultRoleName == "" {
			app.LatestAccessIssue = "No default application role"
		}
	}

	c.JSON(http.StatusOK, apps)
}

// PostureSummary returns a workspace-level application access queue for IAM
// cockpit surfaces. It intentionally summarizes only operator-actionable
// state: blockers, unmapped tools, public/risky exposure, assignments, and
// users with access.
func (ctrl *ApplicationsController) PostureSummary(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	if routeWorkspaceID := c.Param("workspace_id"); routeWorkspaceID != "" && routeWorkspaceID != workspaceID.String() {
		c.JSON(http.StatusForbidden, gin.H{"error": "workspace_id does not match authenticated workspace"})
		return
	}

	apps, err := ctrl.service.ListByWorkspace(workspaceID.String(), "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type actionItem struct {
		ApplicationID string `json:"application_id"`
		Application   string `json:"application"`
		Type          string `json:"type"`
		Severity      string `json:"severity"`
		Label         string `json:"label"`
		Action        string `json:"action"`
		Href          string `json:"href"`
	}

	var totalTools, unmappedTools, publicTools, riskyScopes, assignments, usersWithAccess int64
	var launched int
	queue := make([]actionItem, 0)

	for _, app := range apps {
		var appTools, appUnmapped, appPublic, appRisky, appBindings, appUsers int64
		config.DB.Table("mcp_tools").
			Where("tenant_id = ? AND resource_server_id = ?", workspaceID, app.ID).
			Count(&appTools)
		config.DB.Table("mcp_tools t").
			Where("t.tenant_id = ? AND t.resource_server_id = ? AND t.is_public = false", workspaceID, app.ID).
			Where(`NOT EXISTS (
				SELECT 1 FROM mcp_tool_scope_map mtsm
				WHERE mtsm.tool_id = t.id AND mtsm.source = 'admin_override'
			)`).
			Count(&appUnmapped)
		config.DB.Table("mcp_tools").
			Where("tenant_id = ? AND resource_server_id = ? AND is_public = true", workspaceID, app.ID).
			Count(&appPublic)
		config.DB.Table("oauth_scopes").
			Where("tenant_id = ? AND resource_server_id = ? AND risk_level IN ?", workspaceID, app.ID, []string{"high", "critical"}).
			Count(&appRisky)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.tenant_id = ?", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Count(&appBindings)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.tenant_id = ? AND rb.user_id IS NOT NULL", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Select("COUNT(DISTINCT rb.user_id)").Scan(&appUsers)

		totalTools += appTools
		unmappedTools += appUnmapped
		publicTools += appPublic
		riskyScopes += appRisky
		assignments += appBindings
		usersWithAccess += appUsers
		if app.IsReady() {
			launched++
		}

		hrefBase := "/applications/" + app.ID.String()
		switch {
		case !app.IsReady():
			queue = append(queue, actionItem{ApplicationID: app.ID.String(), Application: app.Name, Type: "launch_blocker", Severity: "warning", Label: "Application is not launched", Action: "Open overview", Href: hrefBase + "/overview"})
		case appUnmapped > 0:
			queue = append(queue, actionItem{ApplicationID: app.ID.String(), Application: app.Name, Type: "unmapped_tools", Severity: "warning", Label: "Tools are denied until mapped", Action: "Review tools", Href: hrefBase + "/tools"})
		case appPublic > 0 || appRisky > 0:
			queue = append(queue, actionItem{ApplicationID: app.ID.String(), Application: app.Name, Type: "exposure_review", Severity: "review", Label: "Public or high-risk access needs review", Action: "Review exposure", Href: hrefBase + "/tools"})
		case appBindings == 0:
			queue = append(queue, actionItem{ApplicationID: app.ID.String(), Application: app.Name, Type: "access_gap", Severity: "info", Label: "No users have application access", Action: "Choose role", Href: hrefBase + "/access"})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"workspace_id": workspaceID.String(),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary": gin.H{
			"applications":        len(apps),
			"launched":            launched,
			"tools":               totalTools,
			"unmapped_tools":      unmappedTools,
			"public_tools":        publicTools,
			"risky_scopes":        riskyScopes,
			"access_assignments":  assignments,
			"users_with_access":   usersWithAccess,
			"recommended_actions": len(queue),
		},
		"action_queue":    queue,
		"applied_filters": gin.H{},
	})
}

// Get handles GET /authsec/applications/:id.
func (ctrl *ApplicationsController) Get(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	app, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	c.JSON(http.StatusOK, app)
}

// Update handles PUT /authsec/applications/:id. Same allowed fields as the
// legacy resource_servers update plus application_type.
func (ctrl *ApplicationsController) Update(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	var raw map[string]interface{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	allowed := map[string]bool{
		"name": true, "public_base_url": true, "protected_base_path": true,
		"scopes_supported": true, "registration_modes": true, "active": true,
		"application_type": true,
	}
	updates := make(map[string]interface{})
	for k, v := range raw {
		if !allowed[k] {
			continue
		}
		if k == "application_type" {
			if s, ok := v.(string); !ok || !services.ValidApplicationType(s) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application_type"})
				return
			}
		}
		updates[k] = v
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid fields to update"})
		return
	}

	app, err := ctrl.service.UpdateByTenant(id, workspaceID.String(), updates)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "application_updated", "application",
		id, http.StatusOK, nil, updates)
	c.JSON(http.StatusOK, app)
}

// Delete handles DELETE /authsec/applications/:id.
func (ctrl *ApplicationsController) Delete(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	if err := ctrl.service.DeleteByTenant(id, workspaceID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	auditAdminMutation(c, workspaceID.String(), "application_deleted", "application",
		id, http.StatusNoContent, nil, nil)
	c.JSON(http.StatusNoContent, nil)
}

// ListConnections handles GET /authsec/applications/:id/connections.
// "Connections" is the new product name for OAuth client registrations against
// the Application — the underlying records are still in mcp_oauth_clients via
// resource_server_client_registrations. The legacy /clients URL stays as a
// compatibility shim under resource_server_controller.
func (ctrl *ApplicationsController) ListConnections(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	if _, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	conns, err := ctrl.oauthSvc.ListClientsForRS(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, conns)
}

// RevokeConnection handles DELETE /authsec/applications/:id/connections/:connection_id.
func (ctrl *ApplicationsController) RevokeConnection(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	if _, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	connectionID := c.Param("connection_id")
	if err := ctrl.oauthSvc.RevokeClientRegistration(id, connectionID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "application_connection_revoked", "oauth_client",
		connectionID, http.StatusOK, nil, map[string]interface{}{"application_id": id})
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// Launch handles POST /authsec/applications/:id/launch.
//
// At v1 this returns the data the UI needs to drive a "Launch" CTA — issuer,
// resource URL, supported scopes, application_type, and the OAuth client
// registrations the launching client can choose from. The actual OAuth flow
// is initiated by the caller against /oauth/authorize using these inputs.
//
// This is intentionally a thin endpoint: launch state (PDP check, drift
// banner, etc.) is composed by the UI from existing endpoints. Returning the
// composed bundle as one call keeps the launch button single-roundtrip.
func (ctrl *ApplicationsController) Launch(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	app, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	if app.State != models.RSStateReady {
		c.JSON(http.StatusConflict, gin.H{
			"error": "application not ready",
			"state": app.State,
		})
		return
	}

	conns, err := ctrl.oauthSvc.ListClientsForRS(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"application_id":   app.ID.String(),
		"application_type": app.ApplicationType,
		"name":             app.Name,
		"resource_uri":     app.ResourceURI,
		"public_base_url":  app.PublicBaseURL,
		"scopes_supported": app.ScopesSupported,
		"connections":      conns,
		"workspace_id":     workspaceID.String(),
	})
}
