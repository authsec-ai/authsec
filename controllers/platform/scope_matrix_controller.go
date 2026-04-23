package platform

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ScopeMatrixController handles scope registry, tool discovery, and scope matrix APIs.
type ScopeMatrixController struct {
	rsService     *services.ResourceServerService
	scopeRegistry *services.ScopeRegistryService
	oauthService  *services.OAuthASService
	scopeResolver *services.ScopeResolver
}

func NewScopeMatrixController() *ScopeMatrixController {
	return &ScopeMatrixController{
		rsService:     services.NewResourceServerService(config.DB),
		scopeRegistry: services.NewScopeRegistryService(config.DB),
		oauthService:  services.NewOAuthASService(config.DB),
		scopeResolver: services.NewScopeResolver(config.DB),
	}
}

// GetScopeMatrix returns the full tool × scope × role matrix for a resource server.
// GET /authsec/resource-servers/:id/scope-matrix
func (ctrl *ScopeMatrixController) GetScopeMatrix(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	rsUUID := rs.ID

	// Get tools with their scope mappings, filtered to the last successful generation.
	// This ensures clients see only the latest committed serving snapshot.
	var tools []models.MCPTool
	config.DB.Preload("Scopes").
		Where("tenant_id = ? AND resource_server_id = ? AND last_scan_generation = ?",
			tenantID, rsUUID, rs.LastSuccessfulGeneration).
		Order("name").
		Find(&tools)

	// Get all scopes for this RS
	scopes, _ := ctrl.scopeRegistry.ListByResourceServer(tenantID, rsUUID)

	// Build tool responses (initialize as empty slice so JSON marshals as [] not null)
	toolResponses := make([]models.MCPToolResponse, 0, len(tools))
	mappedScopeIDs := make(map[uuid.UUID]bool)

	for _, tool := range tools {
		tr := models.MCPToolResponse{
			ID:          tool.ID.String(),
			Name:        tool.Name,
			Title:       tool.Title,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
			Annotations: tool.Annotations,
			Scopes:      make([]models.ScopeMapEntry, 0), // initialize so JSON marshals as [] not null
		}

		for _, scope := range tool.Scopes {
			// Look up auto_matched from join table
			var mapping models.MCPToolScopeMap
			config.DB.Where("tool_id = ? AND scope_id = ?", tool.ID, scope.ID).First(&mapping)

			tr.Scopes = append(tr.Scopes, models.ScopeMapEntry{
				ScopeID:     scope.ID.String(),
				ScopeString: scope.ScopeString,
				DisplayName: scope.DisplayName,
				RiskLevel:   scope.RiskLevel,
				AutoMatched: mapping.AutoMatched,
			})
			mappedScopeIDs[scope.ID] = true
		}

		toolResponses = append(toolResponses, tr)
	}

	// Find unmapped scopes (initialize as empty slice so JSON marshals as [] not null)
	unmappedScopes := make([]models.OAuthScopeResponse, 0)
	for _, scope := range scopes {
		if !mappedScopeIDs[scope.ID] {
			unmappedScopes = append(unmappedScopes, models.OAuthScopeResponse{
				ID:               scope.ID.String(),
				ScopeString:      scope.ScopeString,
				DisplayName:      scope.DisplayName,
				RiskLevel:        scope.RiskLevel,
				IsAutoDiscovered: scope.IsAutoDiscovered,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_server": gin.H{
			"id":                        rs.ID.String(),
			"name":                      rs.Name,
			"url":                       rs.PublicBaseURL,
			"status":                    rs.Status,
			"last_scan_status":          rs.LastScanStatus,
			"scan_generation":           rs.ScanGeneration,
			"last_successful_generation": rs.LastSuccessfulGeneration,
			"last_scan_started_at":      rs.LastScanStartedAt,
			"last_scan_completed_at":    rs.LastScanCompletedAt,
		},
		"tools":           toolResponses,
		"unmapped_scopes": unmappedScopes,
		"total_scopes":    len(scopes),
		"total_tools":     len(tools),
	})
}

// Rescan re-discovers tools and scopes from the MCP server.
// POST /authsec/resource-servers/:id/rescan
func (ctrl *ScopeMatrixController) Rescan(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// result is always non-nil — DiscoverAndSync guarantees this.
	result, err := ctrl.rsService.DiscoverAndSync(ctx, rs)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, services.ErrScanInProgress) {
			status = http.StatusConflict // 409
		}
		c.JSON(status, gin.H{
			"error":          err.Error(),
			"failure_reason": result.FailureReason,
		})
		return
	}

	// Re-fetch the RS to surface the updated lifecycle fields in the response.
	updatedRS, _ := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String())
	resp := gin.H{"result": result}
	if updatedRS != nil {
		resp["status"] = updatedRS.Status
		resp["last_scan_status"] = updatedRS.LastScanStatus
		resp["scan_generation"] = updatedRS.ScanGeneration
		resp["last_successful_generation"] = updatedRS.LastSuccessfulGeneration
	}
	auditAdminMutation(c, tenantID.String(), "rs_rescanned", "resource_server",
		rsID, http.StatusOK, nil, result)
	c.JSON(http.StatusOK, resp)
}

// ListScopes returns all scopes for a resource server.
// GET /authsec/resource-servers/:id/scopes
func (ctrl *ScopeMatrixController) ListScopes(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource server ID"})
		return
	}

	scopes, err := ctrl.scopeRegistry.ListByResourceServer(tenantID, rsUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, scopes)
}

// CreateScope creates a new scope in the registry.
// POST /authsec/resource-servers/:id/scopes
func (ctrl *ScopeMatrixController) CreateScope(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource server ID"})
		return
	}

	// Ownership gate: RS must belong to the requesting tenant.
	if _, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	var req models.CreateOAuthScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	scope := &models.OAuthScope{
		TenantID:         tenantID,
		ResourceServerID: &rsUUID,
		ScopeString:      req.ScopeString,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		Icon:             req.Icon,
		RiskLevel:        req.RiskLevel,
	}
	if scope.RiskLevel == "" {
		scope.RiskLevel = "low"
	}

	// Validate parent_scope_id through the service so the domain isolation rule
	// lives in exactly one place (ScopeRegistryService.ValidateParentScope).
	if req.ParentScopeID != "" {
		pid, err := ctrl.scopeRegistry.ValidateParentScope(req.ParentScopeID, tenantID, &rsUUID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		scope.ParentScopeID = &pid
	}

	if err := ctrl.scopeRegistry.Create(scope); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	// Link permissions with tenant ownership enforcement (skips foreign IDs silently).
	if len(req.PermissionIDs) > 0 {
		ctrl.scopeRegistry.LinkPermissionsTenantScoped(scope.ID, tenantID, req.PermissionIDs)
	}

	auditAdminMutation(c, tenantID.String(), "scope_created", "oauth_scope",
		scope.ID.String(), http.StatusCreated, nil,
		map[string]interface{}{"scope_string": scope.ScopeString, "rs_id": rsID})
	c.JSON(http.StatusCreated, scope)
}

// UpdateScope updates scope metadata.
// PUT /authsec/scopes/:scope_id
func (ctrl *ScopeMatrixController) UpdateScope(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope ID"})
		return
	}

	var req models.UpdateOAuthScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// UpdateByTenant → applyUpdate enforces tenant ownership, parent domain isolation,
	// and permission tenant filtering.
	scope, err := ctrl.scopeRegistry.UpdateByTenant(scopeID, tenantID, &req)
	if err != nil {
		status := http.StatusNotFound
		if errors.Is(err, services.ErrInvalidParentScope) {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "scope_updated", "oauth_scope",
		scopeID.String(), http.StatusOK, nil, &req)
	c.JSON(http.StatusOK, scope)
}

// DeleteScope removes a scope.
// DELETE /authsec/scopes/:scope_id
func (ctrl *ScopeMatrixController) DeleteScope(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope ID"})
		return
	}

	if err := ctrl.scopeRegistry.DeleteByTenant(scopeID, tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "scope_deleted", "oauth_scope",
		scopeID.String(), http.StatusNoContent, nil, nil)
	c.JSON(http.StatusNoContent, nil)
}

// UpdateToolScopeMap manually maps/unmaps tools to scopes.
// PUT /authsec/resource-servers/:id/tool-scope-map
func (ctrl *ScopeMatrixController) UpdateToolScopeMap(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	// Ownership gate: RS must belong to the requesting tenant.
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}
	rsUUID := rs.ID

	var req struct {
		Mappings []struct {
			ToolID  string `json:"tool_id"  binding:"required"`
			ScopeID string `json:"scope_id" binding:"required"`
			Remove  bool   `json:"remove"`
		} `json:"mappings" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	applied := 0
	for _, m := range req.Mappings {
		toolID, errT := uuid.Parse(m.ToolID)
		scopeID, errS := uuid.Parse(m.ScopeID)
		if errT != nil || errS != nil {
			continue
		}

		// Tool must belong to this tenant AND this specific RS.
		var toolCount int64
		config.DB.Model(&models.MCPTool{}).
			Where("id = ? AND tenant_id = ? AND resource_server_id = ?", toolID, tenantID, rsUUID).
			Count(&toolCount)
		if toolCount == 0 {
			continue
		}

		// Scope must belong to this tenant AND this specific RS.
		var scopeCount int64
		config.DB.Model(&models.OAuthScope{}).
			Where("id = ? AND tenant_id = ? AND resource_server_id = ?", scopeID, tenantID, rsUUID).
			Count(&scopeCount)
		if scopeCount == 0 {
			continue
		}

		if m.Remove {
			config.DB.Where("tool_id = ? AND scope_id = ?", toolID, scopeID).Delete(&models.MCPToolScopeMap{})
		} else {
			mapping := models.MCPToolScopeMap{
				ToolID:      toolID,
				ScopeID:     scopeID,
				AutoMatched: false,
			}
			config.DB.Where("tool_id = ? AND scope_id = ?", toolID, scopeID).FirstOrCreate(&mapping)
		}
		applied++
	}

	auditAdminMutation(c, tenantID.String(), "tool_scope_map_updated", "resource_server",
		rsUUID.String(), http.StatusOK, nil,
		map[string]interface{}{"requested": len(req.Mappings), "applied": applied})
	c.JSON(http.StatusOK, gin.H{"status": "updated", "applied": applied, "requested": len(req.Mappings)})
}

// SDKPolicy returns a flat tool→scope mapping for SDK consumption.
// GET /authsec/resource-servers/:id/sdk-policy
//
// Authenticated via HTTP Basic Auth using the RS introspection credentials
// (introspection_client_id : introspection_secret) — the same credentials
// the SDK already holds for token introspection.
func (ctrl *ScopeMatrixController) SDKPolicy(c *gin.Context) {
	clientID, secret, ok := c.Request.BasicAuth()
	if !ok {
		c.Header("WWW-Authenticate", `Basic realm="sdk-policy"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "resource server credentials required"})
		return
	}

	rs, err := ctrl.oauthService.ValidateIntrospectionCredentials(clientID, secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Verify the authenticated RS matches the :id URL parameter
	rsID := c.Param("id")
	if rs.ID.String() != rsID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credentials do not match the requested resource server"})
		return
	}

	// Guard: only block when no successful scan has ever completed.
	// During degraded or pending_scan (with a prior success) we serve the last
	// good snapshot — consistent with "SDKPolicy reflects latest successful policy".
	if rs.LastSuccessfulGeneration == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "resource server has not completed initial discovery",
			"status": rs.Status,
		})
		return
	}

	// Fetch tools filtered to last_successful_generation only.
	// This is the atomic serving snapshot committed by the last full scan.
	var tools []models.MCPTool
	config.DB.Preload("Scopes").
		Where("tenant_id = ? AND resource_server_id = ? AND last_scan_generation = ?",
			rs.TenantID, rs.ID, rs.LastSuccessfulGeneration).
		Find(&tools)

	// Build flat map: tool_name -> [scope_string, ...]
	toolMap := make(map[string][]string, len(tools))
	for _, tool := range tools {
		var scopeStrings []string
		for _, scope := range tool.Scopes {
			scopeStrings = append(scopeStrings, scope.ScopeString)
		}
		if scopeStrings == nil {
			scopeStrings = []string{}
		}
		toolMap[tool.Name] = scopeStrings
	}

	c.JSON(http.StatusOK, gin.H{
		"tools":       toolMap,
		"fetched_at":  time.Now().UTC().Format(time.RFC3339),
		"ttl_seconds": 300,
	})
}

// ScopeResolutionPreview returns a full per-scope diagnostic report for a given user
// against a specific resource server. Admin-only; inherits auth from the resourceServers group.
//
// OIDC core scopes are excluded — their grantability depends on client type, not RS
// configuration. This endpoint covers RS-scoped scope diagnostics only.
//
// GET /authsec/resource-servers/:id/scope-resolution-preview?user_id=<uuid>&scope=<s1>&scope=<s2>
func (ctrl *ScopeMatrixController) ScopeResolutionPreview(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id query parameter required"})
		return
	}

	// Default to all RS-declared scopes when no explicit scope params provided
	requestedScopes := c.QueryArray("scope")
	if len(requestedScopes) == 0 {
		requestedScopes = rs.ScopesSupported
	}

	// Filter out OIDC core scopes — they require client context to diagnose accurately.
	var rsScopes []string
	for _, s := range requestedScopes {
		if !services.IsOIDCCoreScope(s) {
			rsScopes = append(rsScopes, s)
		}
	}

	report, err := ctrl.scopeResolver.ResolveWithReport(
		c.Request.Context(),
		tenantID.String(), userID, rs.ID.String(),
		rsScopes, rs, nil, // client=nil: admin view, OIDC scopes already filtered above
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "scope resolution failed"})
		return
	}

	// Enrich diagnostics with scope metadata
	allScopes, _ := ctrl.scopeRegistry.ListByResourceServer(tenantID, rs.ID)
	scopeMeta := make(map[string]*models.OAuthScope, len(allScopes))
	for i := range allScopes {
		scopeMeta[allScopes[i].ScopeString] = &allScopes[i]
	}

	type enrichedDiagnostic struct {
		services.ScopeDiagnostic
		DisplayName string `json:"display_name,omitempty"`
		Description string `json:"description,omitempty"`
		RiskLevel   string `json:"risk_level,omitempty"`
	}

	enriched := make([]enrichedDiagnostic, 0, len(report.Diagnostics))
	for _, d := range report.Diagnostics {
		ed := enrichedDiagnostic{ScopeDiagnostic: d}
		if meta, ok := scopeMeta[d.Scope]; ok {
			ed.DisplayName = meta.DisplayName
			ed.Description = meta.Description
			ed.RiskLevel = meta.RiskLevel
		}
		enriched = append(enriched, ed)
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_server_id": rs.ID.String(),
		"user_id":            userID,
		"requested":          report.Requested,
		"rs_supported":       report.RSSupported,
		"user_effective":     report.UserEffective,
		"grantable":          report.Grantable,
		"diagnostics":        enriched,
	})
}
