package platform

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ApplicationsController serves the workspace-scoped Application facade.
//
// Applications are the product object — MCP servers, AI agents, Clawbots, and
// API services. The physical table is still resource_servers; this controller
// is the read/write surface that matches the v4 product model.
//
// Compared with ResourceServerController:
//   - workspace_id is sourced from the JWT and used for ownership filtering,
//     falling back to workspace_id during the rollout.
//   - application_type is accepted on create and used as a list filter.
//   - The OAuth client subresource is exposed under "connections" instead of
//     "clients" to remove the product-vs-protocol confusion.
//
// Anything not duplicated here (tools, scopes, access policy, validate, etc.)
// is mounted at /authsec/applications/:id/* in routes.go pointing at the
// existing ResourceServerController/ScopeMatrixController handlers — they
// don't care which URL prefix invoked them.
type ApplicationsController struct {
	service       *services.ResourceServerService
	oauthSvc      *services.OAuthASService
	onboardingSvc *services.ResourceServerOnboardingService
}

func NewApplicationsController() *ApplicationsController {
	return &ApplicationsController{
		service:       services.NewResourceServerService(config.DB),
		oauthSvc:      services.NewOAuthASService(config.DB),
		onboardingSvc: services.NewResourceServerOnboardingService(config.DB),
	}
}

// prmOverrideBody is the inbound payload for SetPRMOverride.
type prmOverrideBody struct {
	ScopesSupported []string `json:"scopes_supported"`
	TTLDays         int      `json:"ttl_days,omitempty"`
}

// SetPRMOverride handles POST /authsec/applications/:id/prm-override — the
// operator escape hatch (plan §7) for resource servers that can't serve RFC 9728
// metadata cleanly. The admin supplies scopes_supported; the RS is flipped to a
// time-boxed manual override that the reconciler re-verifies.
func (ctrl *ApplicationsController) SetPRMOverride(c *gin.Context) {
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
	var body prmOverrideBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	ttl := time.Duration(body.TTLDays) * 24 * time.Hour
	if err := ctrl.onboardingSvc.SetManualPRMOverride(app.ID, workspaceID, body.ScopesSupported, ttl); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, workspaceID.String(), "application_prm_override_set", "application",
		id, http.StatusOK, nil, map[string]interface{}{"scopes_supported": body.ScopesSupported})
	c.JSON(http.StatusOK, gin.H{
		"status":     "manual_override_active",
		"prm_source": "manual_override",
		"note":       "Manual PRM metadata recorded. The reconciler will re-verify the real metadata endpoint and auto-clear the override on success, or flag metadata_stale at expiry.",
	})
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
			Where("workspace_id = ? AND resource_server_id = ?", workspaceID, app.ID).
			Count(&app.ToolsCount)
		config.DB.Table("oauth_scopes").
			Where("workspace_id = ? AND resource_server_id = ?", workspaceID, app.ID).
			Count(&app.ScopesCount)
		config.DB.Table("roles").
			Where("workspace_id = ? AND name LIKE ?", workspaceID, "rs-"+app.ID.String()+":%").
			Count(&app.RolesCount)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.workspace_id = ?", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Count(&app.BindingsCount)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.workspace_id = ? AND rb.user_id IS NOT NULL", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Select("COUNT(DISTINCT rb.user_id)").Scan(&app.EndUsersCount)
		config.DB.Table("resource_server_access_policies p").
			Select("COALESCE(r.name, '')").
			Joins("LEFT JOIN roles r ON r.id = p.default_role_id").
			Where("p.workspace_id = ? AND p.resource_server_id = ?", workspaceID, app.ID).
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
			Where("workspace_id = ? AND resource_server_id = ?", workspaceID, app.ID).
			Count(&appTools)
		config.DB.Table("mcp_tools t").
			Where("t.workspace_id = ? AND t.resource_server_id = ? AND t.is_public = false", workspaceID, app.ID).
			Where(`NOT EXISTS (
				SELECT 1 FROM mcp_tool_scope_map mtsm
				WHERE mtsm.tool_id = t.id AND mtsm.source = 'admin_override'
			)`).
			Count(&appUnmapped)
		config.DB.Table("mcp_tools").
			Where("workspace_id = ? AND resource_server_id = ? AND is_public = true", workspaceID, app.ID).
			Count(&appPublic)
		config.DB.Table("oauth_scopes").
			Where("workspace_id = ? AND resource_server_id = ? AND risk_level IN ?", workspaceID, app.ID, []string{"high", "critical"}).
			Count(&appRisky)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.workspace_id = ?", workspaceID).
			Where("r.name LIKE ?", "rs-"+app.ID.String()+":%").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Count(&appBindings)
		config.DB.Table("role_bindings rb").
			Joins("JOIN roles r ON r.id = rb.role_id").
			Where("rb.workspace_id = ? AND rb.user_id IS NOT NULL", workspaceID).
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

// connectionAuthority is the identity that bears the access for a connection:
// the service account (M2M) or the acting user (XAA/A2A).
type connectionAuthority struct {
	Type  string `json:"type"` // "service_account" | "user"
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// connectionGrantedThrough describes the role + scopes through which the
// authority holds access to this MCP server.
type connectionGrantedThrough struct {
	RoleID   string   `json:"role_id,omitempty"`
	RoleName string   `json:"role_name,omitempty"`
	Scopes   []string `json:"scopes"`
}

type connectionItem struct {
	ConnectionID     string                    `json:"connection_id"`
	ClientID         string                    `json:"client_id"`
	ClientName       string                    `json:"client_name"`
	ClientKind       string                    `json:"client_kind"`
	RegistrationType string                    `json:"registration_type"`
	Status           string                    `json:"status"`
	AccessMethod     string                    `json:"access_method"` // "m2m" | "xaa"
	Authority        *connectionAuthority      `json:"authority,omitempty"`
	GrantedThrough   *connectionGrantedThrough `json:"granted_through,omitempty"`
	CreatedAt        string                    `json:"created_at"`
}

// ListConnections handles GET /authsec/applications/:id/connections.
// Reshaped to include Authority (who bears access) and GrantedThrough (their
// role + scopes). Authority is the linked service account for M2M connections
// or the acting user for XAA/A2A connections.
func (ctrl *ApplicationsController) ListConnections(c *gin.Context) {
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

	type rawConn struct {
		RegID        string    `gorm:"column:reg_id"`
		RegStatus    string    `gorm:"column:reg_status"`
		RegType      string    `gorm:"column:reg_type"`
		ClientID     string    `gorm:"column:client_id"`
		ClientName   string    `gorm:"column:client_name"`
		ClientKind   string    `gorm:"column:client_kind"`
		SAID         string    `gorm:"column:sa_id"`
		SAName       string    `gorm:"column:sa_name"`
		SARoleID     string    `gorm:"column:sa_role_id"`
		SARoleName   string    `gorm:"column:sa_role_name"`
		UserID       string    `gorm:"column:user_id"`
		UserEmail    string    `gorm:"column:user_email"`
		UserName     string    `gorm:"column:user_name"`
		UserRoleID   string    `gorm:"column:user_role_id"`
		UserRoleName string    `gorm:"column:user_role_name"`
		CreatedAt    time.Time `gorm:"column:created_at"`
	}

	var rows []rawConn
	err = config.DB.Raw(`
		SELECT
			r.id::text                                               AS reg_id,
			r.status                                                 AS reg_status,
			r.registration_type                                      AS reg_type,
			c.client_id                                              AS client_id,
			COALESCE(c.client_name, c.client_id)                    AS client_name,
			COALESCE(c.client_kind, '')                              AS client_kind,
			COALESCE(sa.id::text, '')                               AS sa_id,
			COALESCE(sa.name, '')                                    AS sa_name,
			COALESCE(rb_sa.role_id::text, '')                       AS sa_role_id,
			COALESCE(rb_sa.role_name, '')                           AS sa_role_name,
			COALESCE(u.id::text, '')                                AS user_id,
			COALESCE(u.email, '')                                    AS user_email,
			COALESCE(u.name, '')                                     AS user_name,
			COALESCE(rb_u.role_id::text, '')                        AS user_role_id,
			COALESCE(rb_u.role_name, '')                            AS user_role_name,
			r.created_at                                             AS created_at
		FROM resource_server_client_registrations r
		JOIN mcp_oauth_clients c ON c.id = r.oauth_client_id
		LEFT JOIN service_accounts sa ON sa.oauth_client_id = c.id
		LEFT JOIN role_bindings rb_sa
			ON  rb_sa.service_account_id = sa.id
			AND rb_sa.workspace_id = r.workspace_id
			AND rb_sa.scope_type = 'resource_server'
			AND rb_sa.scope_id = r.resource_server_id
		LEFT JOIN LATERAL (
			SELECT subject_id FROM access_requests
			WHERE requested_by_client = c.client_id
			  AND resource_server_id = r.resource_server_id
			  AND status = 'approved'
			ORDER BY updated_at DESC LIMIT 1
		) ar ON true
		LEFT JOIN users u ON u.id = ar.subject_id
		LEFT JOIN role_bindings rb_u
			ON  rb_u.user_id = u.id
			AND rb_u.workspace_id = r.workspace_id
			AND rb_u.scope_type = 'resource_server'
			AND rb_u.scope_id = r.resource_server_id
		WHERE r.resource_server_id = ?
		  AND r.workspace_id = ?
		ORDER BY r.created_at DESC
	`, rs.ID, workspaceID).Scan(&rows).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Collect role IDs to batch-resolve effective scopes.
	roleIDSet := map[string]struct{}{}
	for _, r := range rows {
		if r.SARoleID != "" {
			roleIDSet[r.SARoleID] = struct{}{}
		}
		if r.UserRoleID != "" {
			roleIDSet[r.UserRoleID] = struct{}{}
		}
	}
	scopesByRole := map[string][]string{}
	if len(roleIDSet) > 0 {
		roleIDs := make([]string, 0, len(roleIDSet))
		for rid := range roleIDSet {
			roleIDs = append(roleIDs, rid)
		}
		type sr struct {
			RoleID      string `gorm:"column:role_id"`
			ScopeString string `gorm:"column:scope_string"`
		}
		var scopeRows []sr
		config.DB.Raw(`
			SELECT rp.role_id::text AS role_id, os.scope_string AS scope_string
			FROM role_permissions rp
			JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id
			JOIN oauth_scopes os ON os.id = osp.scope_id
			WHERE rp.role_id::text IN ?
			  AND os.resource_server_id = ?
		`, roleIDs, rs.ID).Scan(&scopeRows)
		for _, s := range scopeRows {
			scopesByRole[s.RoleID] = append(scopesByRole[s.RoleID], s.ScopeString)
		}
	}

	items := make([]connectionItem, 0, len(rows))
	for _, r := range rows {
		accessMethod := "xaa"
		if r.ClientKind == "m2m" {
			accessMethod = "m2m"
		}

		item := connectionItem{
			// connection_id is the public client_id — the identifier every
			// connection mutation (revoke/approve/deny) and ConnectionSubjectScopeGap
			// resolves by. Exposing the registration-row UUID here (the old bug)
			// made revoke 404, since RevokeClientRegistration looks the client up by
			// client_id, not reg id.
			ConnectionID:     r.ClientID,
			ClientID:         r.ClientID,
			ClientName:       r.ClientName,
			ClientKind:       r.ClientKind,
			RegistrationType: r.RegType,
			Status:           r.RegStatus,
			AccessMethod:     accessMethod,
			CreatedAt:        r.CreatedAt.UTC().Format(time.RFC3339),
		}

		// Authority + GrantedThrough: prefer SA (M2M), fall back to acting user (XAA).
		if r.SAID != "" {
			item.Authority = &connectionAuthority{
				Type: "service_account",
				ID:   r.SAID,
				Name: r.SAName,
			}
			if r.SARoleID != "" {
				scopes := scopesByRole[r.SARoleID]
				if scopes == nil {
					scopes = []string{}
				}
				item.GrantedThrough = &connectionGrantedThrough{
					RoleID:   r.SARoleID,
					RoleName: r.SARoleName,
					Scopes:   scopes,
				}
			}
		} else if r.UserID != "" {
			item.Authority = &connectionAuthority{
				Type:  "user",
				ID:    r.UserID,
				Name:  r.UserName,
				Email: r.UserEmail,
			}
			if r.UserRoleID != "" {
				scopes := scopesByRole[r.UserRoleID]
				if scopes == nil {
					scopes = []string{}
				}
				item.GrantedThrough = &connectionGrantedThrough{
					RoleID:   r.UserRoleID,
					RoleName: r.UserRoleName,
					Scopes:   scopes,
				}
			}
		}

		items = append(items, item)
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
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

// approveConnectionBody is the OPTIONAL body for ApproveConnection. When a
// role_id (+ subject) is supplied, the approval also creates the role binding
// atomically (plan §1). Omit it for connection-only approval (default).
type approveConnectionBody struct {
	RoleID      string `json:"role_id,omitempty"`
	SubjectType string `json:"subject_type,omitempty"` // "user" | "service_account"
	SubjectID   string `json:"subject_id,omitempty"`
}

// ApproveConnection handles PUT /authsec/applications/:id/connections/:connection_id/approve.
// It flips a pending_approval registration to approved. If the body carries a
// role_id + subject, it ALSO grants that RS-scoped role binding in the same
// transaction so the subject obtains usable scopes immediately (plan §1).
// Without a role_id the approval is connection-only (decision #1) and the
// response reports which subjects still lack scopes.
func (ctrl *ApplicationsController) ApproveConnection(c *gin.Context) {
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

	// Optional atomic role grant. Body is optional, so ignore bind errors on an
	// empty/absent body.
	var body approveConnectionBody
	_ = c.ShouldBindJSON(&body)
	var binding *services.ApprovalRoleBinding
	if body.RoleID != "" {
		roleUUID, rErr := uuid.Parse(body.RoleID)
		subjUUID, sErr := uuid.Parse(body.SubjectID)
		if rErr != nil || sErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id or subject_id"})
			return
		}
		if body.SubjectType != "user" && body.SubjectType != "service_account" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subject_type must be 'user' or 'service_account' when role_id is supplied"})
			return
		}
		binding = &services.ApprovalRoleBinding{
			RoleID:      roleUUID,
			SubjectType: body.SubjectType,
			SubjectID:   subjUUID,
		}
	}

	if err := ctrl.oauthSvc.ApproveClientRegistrationWithBinding(id, connectionID, binding); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "application_connection_approved", "oauth_client",
		connectionID, http.StatusOK, nil, map[string]interface{}{"application_id": id, "role_bound": binding != nil})

	// Honesty contract (finding #1): without an atomic role grant, approving a
	// connection authorizes the client↔RS link only — it does NOT grant scopes.
	// Report the subjects that still resolve zero effective scopes so the UI
	// never implies usable access.
	resp := gin.H{"status": "approved"}
	if gap, gerr := ctrl.oauthSvc.ConnectionSubjectScopeGap(c.Request.Context(), id, connectionID); gerr == nil && len(gap) > 0 {
		resp["subjects_without_scopes"] = gap
		resp["scopes_granted"] = false
		resp["note"] = "Connection approved, but the listed subjects have no role bindings yet and will receive zero scopes until a role is assigned."
	}
	c.JSON(http.StatusOK, resp)
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

// DenyConnection handles PUT /authsec/applications/:id/connections/:connection_id/deny.
// It removes a pending_approval registration and marks any open access_requests denied.
func (ctrl *ApplicationsController) DenyConnection(c *gin.Context) {
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
	if err := ctrl.oauthSvc.DenyClientRegistration(id, connectionID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "application_connection_denied", "oauth_client",
		connectionID, http.StatusOK, nil, map[string]interface{}{"application_id": id})
	c.JSON(http.StatusOK, gin.H{"status": "denied"})
}

// ListCrossWorkspaceConnections handles GET /authsec/connections.
// Returns all cross-workspace client registrations and pending access_requests
// for resource servers owned by this workspace — the admin governance view.
func (ctrl *ApplicationsController) ListCrossWorkspaceConnections(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	conns, err := ctrl.oauthSvc.ListCrossWorkspaceConnections(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"connections": conns})
}

// RevokeTokenByJTI handles DELETE /authsec/tokens/:jti.
// Admin endpoint to explicitly revoke a native token by JTI. Workspace-scoped:
// an admin can only revoke tokens that belong to their workspace.
func (ctrl *ApplicationsController) RevokeTokenByJTI(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	jti := c.Param("jti")
	if jti == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jti required"})
		return
	}

	if err := ctrl.oauthSvc.RevokeNativeTokenByJTI(workspaceID, jti); err != nil {
		if err.Error() == "token not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "token_revoked_by_jti", "native_token",
		jti, http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "jti": jti})
}

// ListWorkspaceClients handles GET /authsec/clients.
// Optional ?resource_server_id=<uuid> scopes the result to a single application
// (used by the app-scoped Clients tab via GET /authsec/clients?resource_server_id=X).
func (ctrl *ApplicationsController) ListWorkspaceClients(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var rsID *uuid.UUID
	if rsIDStr := c.Query("resource_server_id"); rsIDStr != "" {
		parsed, parseErr := uuid.Parse(rsIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource_server_id"})
			return
		}
		rsID = &parsed
	}

	clients, err := ctrl.oauthSvc.ListWorkspaceClients(workspaceID, rsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, clients)
}
