package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ScopeMatrixController handles scope registry, tool discovery, and scope matrix APIs.
type ScopeMatrixController struct {
	rsService     *services.ResourceServerService
	scopeRegistry *services.ScopeRegistryService
	oauthService  *services.OAuthASService
	scopeResolver *services.ScopeResolver
	driftService  *services.ResourceServerDriftService
}

func NewScopeMatrixController() *ScopeMatrixController {
	return &ScopeMatrixController{
		rsService:     services.NewResourceServerService(config.DB),
		scopeRegistry: services.NewScopeRegistryService(config.DB),
		oauthService:  services.NewOAuthASService(config.DB),
		scopeResolver: services.NewScopeResolver(config.DB),
		driftService:  services.NewResourceServerDriftService(config.DB),
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

	// Get tools with their scope mappings across policy-effective inventory.
	// SDK manifest and manual tools are always eligible. MCP scan tools are
	// only eligible from the last successful generation so partial/in-flight
	// scans do not leak into admin review or runtime policy.
	var tools []models.MCPTool
	config.DB.Preload("Scopes").
		Where(
			"tenant_id = ? AND resource_server_id = ? AND (inventory_source IN ? OR last_scan_generation = ?)",
			tenantID,
			rsUUID,
			[]string{models.InventorySourceSDKManifest, models.InventorySourceManual},
			rs.LastSuccessfulGeneration,
		).
		Order("name").
		Find(&tools)

	// Get all scopes for this RS
	scopes, _ := ctrl.scopeRegistry.ListByResourceServer(tenantID, rsUUID)

	// Build tool responses (initialize as empty slice so JSON marshals as [] not null)
	toolResponses := make([]models.MCPToolResponse, 0, len(tools))
	mappedScopeIDs := make(map[uuid.UUID]bool)

	for _, tool := range tools {
		tr := models.MCPToolResponse{
			ID:              tool.ID.String(),
			Name:            tool.Name,
			Title:           tool.Title,
			Description:     tool.Description,
			InputSchema:     tool.InputSchema,
			Annotations:     tool.Annotations,
			InventorySource: tool.InventorySource,
			IsPublic:        tool.IsPublic,
			Scopes:          make([]models.ScopeMapEntry, 0), // initialize so JSON marshals as [] not null
		}
		adminOverrideScopes := make(map[string]bool)

		for _, scope := range tool.Scopes {
			// Look up auto_matched from join table
			var mapping models.MCPToolScopeMap
			config.DB.Where("tool_id = ? AND scope_id = ?", tool.ID, scope.ID).First(&mapping)
			if mapping.Source == models.ScopeMapSourceAdminOverride {
				adminOverrideScopes[scope.ScopeString] = true
			}

			tr.Scopes = append(tr.Scopes, models.ScopeMapEntry{
				ScopeID:     scope.ID.String(),
				ScopeString: scope.ScopeString,
				DisplayName: scope.DisplayName,
				RiskLevel:   scope.RiskLevel,
				AutoMatched: mapping.AutoMatched,
				Source:      mapping.Source,
			})
			mappedScopeIDs[scope.ID] = true
		}
		pendingSuggestions := make([]string, 0, len(tool.SuggestedScopes))
		for _, suggestedScope := range tool.SuggestedScopes {
			if !adminOverrideScopes[suggestedScope] {
				pendingSuggestions = append(pendingSuggestions, suggestedScope)
			}
		}
		tr.SuggestedScopes = pendingSuggestions

		toolResponses = append(toolResponses, tr)
	}

	// `scopes` — the full list of OAuth scopes registered against this RS.
	// Returned to the UI so the Tool detail sidebar can compute PER-TOOL
	// available scopes ("scopes for this app NOT yet mapped to *this* tool").
	// The legacy `unmapped_scopes` (below) reports scopes mapped to no tool at
	// all (global), which is a strictly smaller set and would hide already-
	// mapped-elsewhere scopes from the per-tool picker.
	allScopes := make([]models.OAuthScopeResponse, 0, len(scopes))
	for _, scope := range scopes {
		allScopes = append(allScopes, models.OAuthScopeResponse{
			ID:               scope.ID.String(),
			ScopeString:      scope.ScopeString,
			DisplayName:      scope.DisplayName,
			RiskLevel:        scope.RiskLevel,
			IsAutoDiscovered: scope.IsAutoDiscovered,
		})
	}

	// Find unmapped scopes (initialize as empty slice so JSON marshals as [] not null).
	// Kept for back-compat with any caller that already reads this field.
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
			"id":                         rs.ID.String(),
			"name":                       rs.Name,
			"url":                        rs.PublicBaseURL,
			"status":                     rs.Status,
			"last_scan_status":           rs.LastScanStatus,
			"scan_generation":            rs.ScanGeneration,
			"last_successful_generation": rs.LastSuccessfulGeneration,
			"last_scan_started_at":       rs.LastScanStartedAt,
			"last_scan_completed_at":     rs.LastScanCompletedAt,
		},
		"tools":           toolResponses,
		"scopes":          allScopes,
		"unmapped_scopes": unmappedScopes,
		"total_scopes":    len(scopes),
		"total_tools":     len(tools),
	})
}

// Rescan re-discovers tools and scopes from the MCP server.
// POST /authsec/resource-servers/:id/rescan
//
// Body (optional):
//
//	{ "mcp_token": "<bearer token>" }
//
// When mcp_token is present, it is forwarded to the MCP server's tools/list
// call as Authorization: Bearer. The token is NEVER persisted — it lives on
// the mcpclient for the duration of this request and is dropped immediately.
// This is the "authenticated scan" path the wizard exposes for MCP servers
// that require auth on tools/list.
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

	// Pull optional one-shot bearer token from the request body. We tolerate
	// an empty/missing body — the unauthenticated path still works.
	var rescanReq struct {
		MCPToken string `json:"mcp_token"`
	}
	if c.Request.ContentLength > 0 {
		// Bind errors are non-fatal: an empty/malformed body just means
		// "scan without a token". Don't 400 the wizard for that.
		_ = c.ShouldBindJSON(&rescanReq)
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// result is always non-nil — DiscoverAndSync guarantees this.
	result, err := ctrl.rsService.DiscoverAndSyncWithToken(ctx, rs, rescanReq.MCPToken)
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

	// Backfill the auto-generated access permission bridge for older scopes that
	// predate this behavior. Without this, the Access tab can display scopes but
	// has no real permission strings to persist into role_permissions.
	needsRefetch := false
	for i := range scopes {
		if len(scopes[i].Permissions) == 0 {
			autoCreateScopePermission(tenantID, &scopes[i])
			needsRefetch = true
		}
	}
	if needsRefetch {
		scopes, err = ctrl.scopeRegistry.ListByResourceServer(tenantID, rsUUID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// Coerce nil → [] so the JSON response is always an array, never null.
	// Without this, GORM's empty-result Find leaves a nil slice, which Go
	// marshals as JSON null — and the frontend's destructuring defaults
	// (`{ data = [] }`) only catch undefined, not null, so consumers crash
	// on .map / .length.
	if scopes == nil {
		scopes = []models.OAuthScope{}
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
		Source:           "manual",
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

	// Correctness fix #5: auto-create matching permission + bridge in same transaction.
	// This ensures default roles can grant the scope at OAuth time without manual wiring.
	autoCreateScopePermission(tenantID, scope)

	// Correctness fix #4: keep scopes_supported in sync with oauth_scopes.
	syncScopesSupported(rsUUID, tenantID)

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

	// Read scope before deletion to get RS info for drift event and scopes_supported sync.
	var scope models.OAuthScope
	config.DB.Where("id = ? AND tenant_id = ?", scopeID, tenantID).First(&scope)

	if err := ctrl.scopeRegistry.DeleteByTenant(scopeID, tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Sync scopes_supported after deletion.
	if scope.ResourceServerID != nil {
		syncScopesSupported(*scope.ResourceServerID, tenantID)

		// Emit drift event if RS is ready (post-activation destructive edit).
		var rs models.ResourceServer
		if config.DB.Where("id = ?", *scope.ResourceServerID).First(&rs).Error == nil && rs.IsReady() {
			adminUserID := extractUserIDOptional(c)
			_ = ctrl.driftService.EmitEvent(nil, rs.ID, models.DriftEventScopeDeleted,
				map[string]interface{}{"scope_id": scopeID.String(), "scope_string": scope.ScopeString},
				adminUserID)
		}
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

			// Drift event: unmapping a tool's scope on a ready RS may break
			// end-user logins that depended on this scope mapping. Surface it
			// so the admin sees the change in the workspace banner.
			if rs.State == models.RSStateReady {
				_ = ctrl.driftService.EmitEvent(
					config.DB, rsUUID, models.DriftEventToolUnmapped,
					map[string]interface{}{
						"tool_id":  toolID.String(),
						"scope_id": scopeID.String(),
					},
					extractUserIDOptional(c),
				)
			}
		} else {
			// Correctness fix #7: upsert with source='admin_override' and auto_matched=false.
			// FirstOrCreate kept the old auto_matched=true value on conflict — this fixes that.
			config.DB.Exec(`
				INSERT INTO mcp_tool_scope_map (tool_id, scope_id, auto_matched, source)
				VALUES (?, ?, false, 'admin_override')
				ON CONFLICT (tool_id, scope_id)
				DO UPDATE SET source = 'admin_override', auto_matched = false
			`, toolID, scopeID)
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

	// When RS is not ready, return state-aware response (deny-all signal for SDK).
	// SDK consumers MUST treat policy_complete=false as deny-all.
	if rs.State != models.RSStateReady {
		reason := "rs_needs_setup"
		if rs.State == models.RSStateScanFailed {
			reason = "rs_scan_failed"
		} else if rs.State == models.RSStatePendingScan {
			reason = "rs_pending_scan"
		}
		c.JSON(http.StatusOK, gin.H{
			"state":           rs.State,
			"policy_complete": false,
			"reason":          reason,
			"rs_id":           rs.ID.String(),
			"generation":      rs.LastSuccessfulGeneration,
			"tools":           gin.H{},
			"tool_policy":     []interface{}{},
			"tool_metadata":   gin.H{},
			"fetched_at":      time.Now().UTC().Format(time.RFC3339),
			"ttl_seconds":     60,
		})
		return
	}

	// State == ready guarantees the activation gates passed (≥1 tool, ≥1 scope,
	// every non-public tool mapped, viewer role populated). The legacy gen==0
	// 503 check incorrectly blocked manifest-only and manual-only RSes whose
	// tools were ingested without a discovery-driven generation bump — those
	// flows never advance last_successful_generation, but the activation
	// gates still confirm the policy is serveable.

	// Fetch policy-effective tools across inventory sources. SDK manifest and
	// manual tools are always eligible; MCP scan tools must belong to the last
	// successful generation so a partial later scan cannot appear in a ready
	// SDK policy before admin review.
	var allTools []models.MCPTool
	config.DB.Preload("Scopes").
		Where(
			"tenant_id = ? AND resource_server_id = ? AND (inventory_source IN ? OR last_scan_generation = ?)",
			rs.TenantID,
			rs.ID,
			[]string{models.InventorySourceSDKManifest, models.InventorySourceManual},
			rs.LastSuccessfulGeneration,
		).
		Find(&allTools)

	// Legacy flat map: tool_name -> [scope_string, ...] (backwards compat)
	toolMap := make(map[string][]string, len(allTools))
	// New authoritative array: tool_policy
	type toolPolicyEntry struct {
		Name           string   `json:"name"`
		IsPublic       bool     `json:"is_public"`
		RequiredScopes []string `json:"required_scopes"`
	}
	toolPolicyArr := make([]toolPolicyEntry, 0, len(allTools))
	// Tool metadata
	type toolMetaEntry struct {
		Annotations     json.RawMessage `json:"annotations,omitempty"`
		InventorySource string          `json:"inventory_source"`
	}
	toolMeta := make(map[string]toolMetaEntry, len(allTools))

	for _, tool := range allTools {
		// Only admin_override mappings are runtime-effective.
		var overrideMappings []models.MCPToolScopeMap
		config.DB.Where("tool_id = ? AND source = 'admin_override'", tool.ID).Find(&overrideMappings)

		var scopeIDs []uuid.UUID
		for _, m := range overrideMappings {
			scopeIDs = append(scopeIDs, m.ScopeID)
		}

		var scopeStrings []string
		if len(scopeIDs) > 0 {
			var scopes []models.OAuthScope
			config.DB.Where("id IN ?", scopeIDs).Find(&scopes)
			for _, s := range scopes {
				scopeStrings = append(scopeStrings, s.ScopeString)
			}
		}
		if scopeStrings == nil {
			scopeStrings = []string{}
		}

		toolMap[tool.Name] = scopeStrings
		toolPolicyArr = append(toolPolicyArr, toolPolicyEntry{
			Name:           tool.Name,
			IsPublic:       tool.IsPublic,
			RequiredScopes: scopeStrings,
		})
		toolMeta[tool.Name] = toolMetaEntry{
			Annotations:     tool.Annotations,
			InventorySource: tool.InventorySource,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"state":           rs.State,
		"policy_complete": true,
		"reason":          "",
		"rs_id":           rs.ID.String(),
		"generation":      rs.LastSuccessfulGeneration,
		"tools":           toolMap,
		"tool_policy":     toolPolicyArr,
		"tool_metadata":   toolMeta,
		"fetched_at":      time.Now().UTC().Format(time.RFC3339),
		"ttl_seconds":     300,
	})
}

// ── New wizard + workspace handlers ─────────────────────────────────────────────────────────────

// PutSDKManifest receives a tool manifest PUT from the Go SDK and upserts tools.
// PUT /authsec/resource-servers/:id/sdk-manifest  (Basic auth with RS introspection creds)
func (ctrl *ScopeMatrixController) PutSDKManifest(c *gin.Context) {
	clientID, secret, ok := c.Request.BasicAuth()
	if !ok {
		c.Header("WWW-Authenticate", `Basic realm="sdk-manifest"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "resource server credentials required"})
		return
	}

	rs, err := ctrl.oauthService.ValidateIntrospectionCredentials(clientID, secret)
	if err != nil {
		recordManifestAttempt(rs, models.ManifestAttemptAuthFailed, "invalid credentials", 0, "")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	rsID := c.Param("id")
	if rs.ID.String() != rsID {
		recordManifestAttempt(rs, models.ManifestAttemptAuthFailed, "credential RS mismatch", 0, "")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credentials do not match the requested resource server"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 4*1024*1024))
	if err != nil {
		recordManifestAttempt(rs, models.ManifestAttemptServerError, "body read error", 0, "")
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var payload struct {
		Tools []struct {
			Name            string          `json:"name"`
			Title           string          `json:"title"`
			Description     string          `json:"description"`
			InputSchema     json.RawMessage `json:"input_schema"`
			Annotations     json.RawMessage `json:"annotations"`
			SuggestedScopes []string        `json:"suggested_scopes"`
		} `json:"tools"`
		ManifestVersion string `json:"manifest_version"`
		SDKBuildID      string `json:"sdk_build_id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		recordManifestAttempt(rs, models.ManifestAttemptInvalidPayload, "invalid JSON: "+err.Error(), 0, "")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid manifest JSON"})
		return
	}
	if len(payload.Tools) == 0 {
		recordManifestAttempt(rs, models.ManifestAttemptEmptyToolList, "no tools in manifest", 0, payload.ManifestVersion)
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "manifest must contain at least one tool"})
		return
	}

	toolCount := len(payload.Tools)
	upsertedCount := 0
	for _, t := range payload.Tools {
		existing := models.MCPTool{}
		if config.DB.Where("resource_server_id = ? AND name = ? AND inventory_source = ?",
			rs.ID, t.Name, models.InventorySourceSDKManifest).First(&existing).Error == nil {
			config.DB.Model(&existing).Updates(map[string]interface{}{
				"title":            t.Title,
				"description":      t.Description,
				"input_schema":     t.InputSchema,
				"annotations":      t.Annotations,
				"suggested_scopes": t.SuggestedScopes,
			})
		} else {
			// Don't overwrite an existing mcp_scan or manual tool — just update suggested_scopes.
			var conflictCount int64
			config.DB.Model(&models.MCPTool{}).
				Where("resource_server_id = ? AND name = ?", rs.ID, t.Name).
				Count(&conflictCount)
			if conflictCount > 0 {
				config.DB.Model(&models.MCPTool{}).
					Where("resource_server_id = ? AND name = ?", rs.ID, t.Name).
					Update("suggested_scopes", t.SuggestedScopes)
			} else {
				newTool := models.MCPTool{
					TenantID:         rs.TenantID,
					ResourceServerID: rs.ID,
					Name:             t.Name,
					Title:            t.Title,
					Description:      t.Description,
					InputSchema:      t.InputSchema,
					Annotations:      t.Annotations,
					SuggestedScopes:  t.SuggestedScopes,
					InventorySource:  models.InventorySourceSDKManifest,
				}
				config.DB.Create(&newTool)
			}
		}

		// Upsert sdk_suggested scope mappings for each suggested scope.
		// If a suggested scope isn't yet in the registry, seed it with
		// source='manifest' so the UI can label its origin correctly.
		if len(t.SuggestedScopes) > 0 {
			var tool models.MCPTool
			config.DB.Where("resource_server_id = ? AND name = ?", rs.ID, t.Name).First(&tool)
			for _, scopeStr := range t.SuggestedScopes {
				var scope models.OAuthScope
				err := config.DB.Where("tenant_id = ? AND resource_server_id = ? AND scope_string = ?",
					rs.TenantID, rs.ID, scopeStr).First(&scope).Error
				if err != nil {
					scope = models.OAuthScope{
						TenantID:         rs.TenantID,
						ResourceServerID: &rs.ID,
						ScopeString:      scopeStr,
						DisplayName:      scopeStr,
						RiskLevel:        "low",
						Source:           "manifest",
						IsAutoDiscovered: false,
					}
					if createErr := config.DB.Create(&scope).Error; createErr != nil {
						// best-effort — keep going
						continue
					}
				}
				config.DB.Exec(`
					INSERT INTO mcp_tool_scope_map (tool_id, scope_id, auto_matched, source)
					VALUES (?, ?, true, 'sdk_suggested')
					ON CONFLICT (tool_id, scope_id) DO NOTHING
				`, tool.ID, scope.ID)
			}
		}
		upsertedCount++
	}

	// Advance the generation pointer on every successful manifest publish so:
	//   - the /sdk-policy response carries a meaningful, monotonic generation
	//     for SDK observability (instead of always 0 for manifest-only RSes),
	//   - any future consumer that filters by last_scan_generation sees the
	//     manifest-published tools tagged with the current generation.
	// We do this in a single update so generation and tool tags stay consistent.
	nextGen := max(rs.LastSuccessfulGeneration, rs.ScanGeneration) + 1
	config.DB.Model(rs).Updates(map[string]interface{}{
		"scan_generation":            nextGen,
		"last_successful_generation": nextGen,
	})
	config.DB.Model(&models.MCPTool{}).
		Where("resource_server_id = ? AND inventory_source = ?", rs.ID, models.InventorySourceSDKManifest).
		Update("last_scan_generation", nextGen)

	recordManifestAttemptWithVersion(rs, models.ManifestAttemptSuccess, "", toolCount, payload.ManifestVersion, payload.SDKBuildID)

	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"tools_seen": upsertedCount,
		"generation": nextGen,
	})
}

// Activate completes RS setup and flips state to 'ready'.
// POST /authsec/resource-servers/:id/activate
func (ctrl *ScopeMatrixController) Activate(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource server ID"})
		return
	}

	userID := extractUserIDRequired(c)
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required"})
		return
	}

	if err := ctrl.rsService.Activate(rsID, tenantID, *userID); err != nil {
		var gateErr services.ActivationGateError
		if errors.As(err, &gateErr) {
			c.JSON(http.StatusConflict, gin.H{
				"error":  "activation blocked",
				"failed": gateErr.Failed,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_activated", "resource_server",
		rsID.String(), http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// SetupChecklist returns wizard step completion status.
// GET /authsec/resource-servers/:id/setup
func (ctrl *ScopeMatrixController) SetupChecklist(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource server ID"})
		return
	}

	steps, err := ctrl.rsService.SetupChecklist(rsID, tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	// Compute can_activate from steps
	canActivate := true
	for _, s := range steps {
		if s.Step < 6 && !s.Complete {
			canActivate = false
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"steps":        steps,
		"can_activate": canActivate,
	})
}

// ActivationPreview returns the activation review summary card.
// GET /authsec/resource-servers/:id/activation-preview
func (ctrl *ScopeMatrixController) ActivationPreview(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource server ID"})
		return
	}

	preview, err := ctrl.rsService.ActivationPreview(rsID, tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	c.JSON(http.StatusOK, preview)
}

// CreateManualTool registers a tool that the admin types in by hand. This is
// the wizard's "Path C: Manual entry" — the escape hatch for closed MCP servers
// whose tools/list cannot be discovered automatically (no SDK manifest, no
// authenticated scan working).
// POST /authsec/resource-servers/:id/tools
func (ctrl *ScopeMatrixController) CreateManualTool(c *gin.Context) {
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

	// Verify the RS exists for this tenant.
	if _, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	var req struct {
		Name            string `json:"name" binding:"required"`
		Description     string `json:"description"`
		InventorySource string `json:"inventory_source"` // optional; default 'manual'
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tool name is required"})
		return
	}
	source := req.InventorySource
	if source == "" {
		source = models.InventorySourceManual
	}
	// Only manual is allowed via this endpoint — sdk_manifest goes through
	// PutSDKManifest, mcp_scan through Rescan. Reject explicit overrides.
	if source != models.InventorySourceManual {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this endpoint only accepts inventory_source=manual"})
		return
	}

	// Conflict check: a tool with this name from another source already exists.
	// Don't silently overwrite — the wizard's whole point is letting admins see
	// when paths are mixed.
	var existing models.MCPTool
	conflictErr := config.DB.
		Where("tenant_id = ? AND resource_server_id = ? AND name = ?", tenantID, rsUUID, req.Name).
		First(&existing).Error
	if conflictErr == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":            "a tool with this name already exists for this RS",
			"existing_source":  existing.InventorySource,
			"existing_tool_id": existing.ID,
		})
		return
	}

	tool := models.MCPTool{
		TenantID:         tenantID,
		ResourceServerID: rsUUID,
		Name:             req.Name,
		Description:      req.Description,
		InventorySource:  source,
	}
	if err := config.DB.Create(&tool).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "tool_added_manual", "mcp_tool",
		tool.ID.String(), http.StatusCreated, nil,
		map[string]interface{}{"tool_name": tool.Name})
	c.JSON(http.StatusCreated, gin.H{
		"tool_id":          tool.ID,
		"name":             tool.Name,
		"inventory_source": tool.InventorySource,
	})
}

// MarkToolPublic sets is_public=true on a tool with admin acknowledgement.
// POST /authsec/resource-servers/:id/tools/:tool_id/public
func (ctrl *ScopeMatrixController) MarkToolPublic(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	toolID, err := uuid.Parse(c.Param("tool_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool ID"})
		return
	}

	var req struct {
		IsPublic          bool   `json:"is_public"`
		ConfirmationToken string `json:"confirmation_token"` // typed confirmation for destructive tools
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Verify tool belongs to this tenant+RS.
	var tool models.MCPTool
	if err := config.DB.Where("id = ? AND tenant_id = ? AND resource_server_id = ?",
		toolID, tenantID, rsID).First(&tool).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found"})
		return
	}

	// Confirmation gate: marking a tool public bypasses scope enforcement on
	// every token issued for this RS, so we require the admin to type the
	// tool's exact name as a "are you sure?" gate. Toggling back to scoped
	// (is_public=false) doesn't need confirmation — that's the safe direction.
	if req.IsPublic {
		expected := strings.TrimSpace(tool.Name)
		got := strings.TrimSpace(req.ConfirmationToken)
		if got == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":              "confirmation_token required",
				"confirmation_hint":  "type the exact tool name to confirm",
				"expected_tool_name": expected,
			})
			return
		}
		if got != expected {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":              "confirmation_token does not match tool name",
				"confirmation_hint":  "type the exact tool name to confirm",
				"expected_tool_name": expected,
			})
			return
		}
	}

	userID := extractUserIDOptional(c)
	updates := map[string]interface{}{
		"is_public": req.IsPublic,
	}
	if req.IsPublic && userID != nil {
		updates["is_public_acknowledged_by"] = userID
	}

	if err := config.DB.Model(&tool).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "tool_public_flag_set", "mcp_tool",
		toolID.String(), http.StatusOK, nil,
		map[string]interface{}{"is_public": req.IsPublic, "tool_name": tool.Name})
	c.JSON(http.StatusOK, gin.H{"tool_id": toolID, "is_public": req.IsPublic})
}

// SDKManifestStatus returns the most-recent and most-recent-successful manifest attempt.
// GET /authsec/resource-servers/:id/sdk-manifest-status
func (ctrl *ScopeMatrixController) SDKManifestStatus(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	if _, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	rsUUID, _ := uuid.Parse(rsID)

	var lastAttempt models.ResourceServerManifestAttempt
	lastAttemptExists := config.DB.
		Where("rs_id = ?", rsUUID).
		Order("attempted_at DESC").
		First(&lastAttempt).Error == nil

	var lastSuccess models.ResourceServerManifestAttempt
	lastSuccessExists := config.DB.
		Where("rs_id = ? AND status = ?", rsUUID, models.ManifestAttemptSuccess).
		Order("attempted_at DESC").
		First(&lastSuccess).Error == nil

	c.JSON(http.StatusOK, gin.H{
		"last_attempt": maybeAttempt(lastAttemptExists, lastAttempt),
		"last_success": maybeAttempt(lastSuccessExists, lastSuccess),
		"never_seen":   !lastSuccessExists,
	})
}

// DriftEvents returns undismissed drift events for an RS.
// GET /authsec/resource-servers/:id/drift-events
func (ctrl *ScopeMatrixController) DriftEvents(c *gin.Context) {
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

	adminUserID := extractUserIDOptional(c)
	if adminUserID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required"})
		return
	}

	events, err := ctrl.driftService.ListUndismissed(rs.ID, *adminUserID, rs.SetupCompletedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

// DismissDriftEvent records a dismissal of a single drift event.
// POST /authsec/resource-servers/:id/drift-events/:event_id/dismiss
func (ctrl *ScopeMatrixController) DismissDriftEvent(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	if _, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	eventID, err := uuid.Parse(c.Param("event_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event ID"})
		return
	}

	adminUserID := extractUserIDOptional(c)
	if adminUserID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required"})
		return
	}

	if err := ctrl.driftService.Dismiss(eventID, *adminUserID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "dismissed"})
}

// ── Roles + Bindings (per-RS) ────────────────────────────────────────────────────────────────────

// rsRoleSummary is the per-RS role list payload. Includes the auto-generated
// rs-{id}:admin / :viewer / :readonly roles plus any custom roles whose name
// starts with the rs-{id}: prefix.
type rsRoleSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsDefault   bool   `json:"is_default"`
	Permissions int64  `json:"permissions"`
	Bindings    int64  `json:"bindings"`
}

// ListRSRoles returns all roles associated with this RS (rs-{id}:* names).
// GET /authsec/resource-servers/:id/roles
func (ctrl *ScopeMatrixController) ListRSRoles(c *gin.Context) {
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

	prefix := fmt.Sprintf("rs-%s:", rs.ID.String())

	var roles []models.RBACRole
	config.DB.Where("tenant_id = ? AND name LIKE ?", tenantID, prefix+"%").
		Order("name ASC").Find(&roles)

	// Fetch the policy default for the is_default flag.
	var policy models.ResourceServerAccessPolicy
	policyErr := config.DB.Where("resource_server_id = ? AND tenant_id = ?", rs.ID, tenantID).
		First(&policy).Error
	defaultRoleID := uuid.Nil
	if policyErr == nil && policy.DefaultRoleID != nil {
		defaultRoleID = *policy.DefaultRoleID
	}

	out := make([]rsRoleSummary, 0, len(roles))
	for _, r := range roles {
		var permCount int64
		config.DB.Model(&models.RolePermission{}).Where("role_id = ?", r.ID).Count(&permCount)
		var bindingCount int64
		config.DB.Model(&models.RoleBinding{}).
			Where("role_id = ? AND tenant_id = ?", r.ID, tenantID).
			Where("(scope_type IS NULL AND scope_id IS NULL) OR (scope_type = 'resource_server' AND scope_id = ?)", rs.ID).
			Count(&bindingCount)
		out = append(out, rsRoleSummary{
			ID:          r.ID.String(),
			Name:        r.Name,
			Description: r.Description,
			IsDefault:   r.ID == defaultRoleID,
			Permissions: permCount,
			Bindings:    bindingCount,
		})
	}
	c.JSON(http.StatusOK, gin.H{"roles": out})
}

// rsBindingResponse is the per-binding payload for the RolesAccessTab.
type rsBindingResponse struct {
	ID        string  `json:"id"`
	UserID    string  `json:"user_id"`
	Username  string  `json:"username"`
	UserEmail string  `json:"user_email"`
	RoleID    string  `json:"role_id"`
	RoleName  string  `json:"role_name"`
	ScopeType *string `json:"scope_type"`
	ScopeID   *string `json:"scope_id"`
	CreatedAt string  `json:"created_at"`
	Source    string  `json:"assignment_source,omitempty"`
}

type accessApplicationRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ResourceURI string `json:"resource_uri"`
}

type accessUserRef struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
}

type accessRoleRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Label     string `json:"label"`
	Source    string `json:"source,omitempty"`
	BindingID string `json:"binding_id,omitempty"`
}

type accessScopeRef struct {
	ID          string `json:"id"`
	ScopeString string `json:"scope_string"`
	DisplayName string `json:"display_name"`
	RiskLevel   string `json:"risk_level"`
	Source      string `json:"source,omitempty"`
}

type scopeGrantSource struct {
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	BindingID string `json:"binding_id"`
	Source    string `json:"source"`
}

type effectiveAccessScope struct {
	ID             string             `json:"id"`
	ScopeString    string             `json:"scope_string"`
	DisplayName    string             `json:"display_name"`
	RiskLevel      string             `json:"risk_level"`
	Status         string             `json:"status"`
	GrantedThrough []scopeGrantSource `json:"granted_through"`
	Removable      bool               `json:"removable"`
}

type applicationRoleResponse struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Label       string               `json:"label"`
	Description string               `json:"description"`
	Application accessApplicationRef `json:"application"`
	IsDefault   bool                 `json:"is_default"`
	UsersCount  int64                `json:"users_count"`
	ScopesCount int                  `json:"scopes_count"`
	Scopes      []accessScopeRef     `json:"scopes"`
	Source      string               `json:"source"`
	UpdatedAt   string               `json:"updated_at"`
}

type applicationAccessUserResponse struct {
	User           accessUserRef       `json:"user"`
	Roles          []accessRoleRef     `json:"roles"`
	Scopes         []accessScopeRef    `json:"scopes"`
	Bindings       []rsBindingResponse `json:"bindings"`
	FirstConsentAt string              `json:"first_consent_at,omitempty"`
	LastSeenAt     string              `json:"last_seen_at,omitempty"`
}

type scopeCatalogEntryResponse struct {
	ID                 string                `json:"id"`
	Kind               string                `json:"kind"`
	Key                string                `json:"key"`
	ScopeString        string                `json:"scope_string"`
	DisplayName        string                `json:"display_name"`
	Description        string                `json:"description"`
	RiskLevel          string                `json:"risk_level"`
	Source             string                `json:"source"`
	Application        *accessApplicationRef `json:"application,omitempty"`
	ToolsCount         int64                 `json:"tools_count"`
	RolesCount         int64                 `json:"roles_count"`
	UsersCount         int64                 `json:"users_count"`
	ConsentGrantsCount int64                 `json:"consent_grants_count"`
	UpdatedAt          string                `json:"updated_at"`
}

func applicationRoleLabel(roleName string) string {
	if idx := strings.LastIndex(roleName, ":"); idx >= 0 && idx < len(roleName)-1 {
		raw := roleName[idx+1:]
		parts := strings.FieldsFunc(raw, func(r rune) bool {
			return r == '-' || r == '_' || r == ':'
		})
		for i, part := range parts {
			if part == "" {
				continue
			}
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
		label := strings.Join(parts, " ")
		if strings.TrimSpace(label) != "" {
			return label
		}
	}
	return roleName
}

func applicationRoleSource(roleName string) string {
	label := strings.ToLower(applicationRoleLabel(roleName))
	switch label {
	case "viewer", "admin", "operator", "readonly":
		return "generated"
	default:
		return "manual"
	}
}

func scopeRefsForRole(db *gorm.DB, tenantID, roleID, appID uuid.UUID) []accessScopeRef {
	type scopeRow struct {
		ID          uuid.UUID
		ScopeString string
		DisplayName string
		RiskLevel   string
		Source      string
	}
	var rows []scopeRow
	db.Table("role_permissions rp").
		Select("DISTINCT os.id, os.scope_string, os.display_name, os.risk_level, os.source").
		Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id").
		Joins("JOIN oauth_scopes os ON os.id = osp.scope_id").
		Where("rp.role_id = ? AND os.tenant_id = ? AND os.resource_server_id = ?", roleID, tenantID, appID).
		Order("os.scope_string ASC").
		Scan(&rows)

	out := make([]accessScopeRef, 0, len(rows))
	for _, row := range rows {
		out = append(out, accessScopeRef{
			ID:          row.ID.String(),
			ScopeString: row.ScopeString,
			DisplayName: row.DisplayName,
			RiskLevel:   row.RiskLevel,
			Source:      row.Source,
		})
	}
	return out
}

func appendUniqueScopeRef(scopes []accessScopeRef, scope accessScopeRef) []accessScopeRef {
	for _, existing := range scopes {
		if existing.ID == scope.ID {
			return scopes
		}
	}
	return append(scopes, scope)
}

func normalizeApplicationRoleSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		isAlphaNum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlphaNum {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// ListApplicationRoles returns all application-scoped roles across the workspace.
// GET /authsec/application-roles
func (ctrl *ScopeMatrixController) ListApplicationRoles(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	var apps []models.ResourceServer
	if err := config.DB.Where("tenant_id = ?", tenantID).Order("name ASC").Find(&apps).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var roles []models.RBACRole
	if err := config.DB.Where("tenant_id = ? AND name LIKE ?", tenantID, "rs-%:%").
		Order("name ASC").Find(&roles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type updatedRow struct {
		ID        uuid.UUID
		UpdatedAt time.Time
	}
	var updatedRows []updatedRow
	config.DB.Table("roles").Select("id, updated_at").Where("tenant_id = ?", tenantID).Scan(&updatedRows)
	updatedByRole := map[uuid.UUID]time.Time{}
	for _, row := range updatedRows {
		updatedByRole[row.ID] = row.UpdatedAt
	}

	type policyRow struct {
		ResourceServerID uuid.UUID
		DefaultRoleID    *uuid.UUID
	}
	var policies []policyRow
	config.DB.Table("resource_server_access_policies").
		Select("resource_server_id, default_role_id").
		Where("tenant_id = ? AND default_role_id IS NOT NULL", tenantID).
		Scan(&policies)
	defaultByApp := map[uuid.UUID]uuid.UUID{}
	for _, p := range policies {
		if p.DefaultRoleID != nil {
			defaultByApp[p.ResourceServerID] = *p.DefaultRoleID
		}
	}

	out := make([]applicationRoleResponse, 0)
	for _, role := range roles {
		var app *models.ResourceServer
		for i := range apps {
			if strings.HasPrefix(role.Name, fmt.Sprintf("rs-%s:", apps[i].ID.String())) {
				app = &apps[i]
				break
			}
		}
		if app == nil {
			continue
		}

		scopes := scopeRefsForRole(config.DB, tenantID, role.ID, app.ID)
		var usersCount int64
		config.DB.Table("role_bindings rb").
			Where("rb.tenant_id = ? AND rb.role_id = ? AND rb.user_id IS NOT NULL", tenantID, role.ID).
			Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
			Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", app.ID).
			Select("COUNT(DISTINCT rb.user_id)").Scan(&usersCount)

		updatedAt := role.CreatedAt
		if v, ok := updatedByRole[role.ID]; ok && !v.IsZero() {
			updatedAt = v
		}
		out = append(out, applicationRoleResponse{
			ID:          role.ID.String(),
			Name:        role.Name,
			Label:       applicationRoleLabel(role.Name),
			Description: role.Description,
			Application: accessApplicationRef{ID: app.ID.String(), Name: app.Name, ResourceURI: app.ResourceURI},
			IsDefault:   defaultByApp[app.ID] == role.ID,
			UsersCount:  usersCount,
			ScopesCount: len(scopes),
			Scopes:      scopes,
			Source:      applicationRoleSource(role.Name),
			UpdatedAt:   updatedAt.UTC().Format(time.RFC3339),
		})
	}

	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	appFilter := strings.TrimSpace(c.Query("application_id"))
	sourceFilter := strings.ToLower(strings.TrimSpace(c.Query("source")))
	defaultFilter := strings.ToLower(strings.TrimSpace(c.Query("default")))
	if q != "" || appFilter != "" || sourceFilter != "" || defaultFilter != "" {
		filtered := make([]applicationRoleResponse, 0, len(out))
		for _, role := range out {
			if appFilter != "" && role.Application.ID != appFilter {
				continue
			}
			if sourceFilter != "" && strings.ToLower(role.Source) != sourceFilter {
				continue
			}
			if defaultFilter == "true" && !role.IsDefault {
				continue
			}
			if defaultFilter == "false" && role.IsDefault {
				continue
			}
			if q != "" {
				haystack := strings.ToLower(strings.Join([]string{
					role.Label,
					role.Name,
					role.Description,
					role.Application.Name,
					role.Application.ResourceURI,
				}, " "))
				for _, scope := range role.Scopes {
					haystack += " " + strings.ToLower(scope.ScopeString+" "+scope.DisplayName+" "+scope.RiskLevel)
				}
				if !strings.Contains(haystack, q) {
					continue
				}
			}
			filtered = append(filtered, role)
		}
		out = filtered
	}

	c.JSON(http.StatusOK, gin.H{"roles": out, "count": len(out)})
}

// ListApplicationAccessUsers materializes users, roles, bindings, and effective
// app scopes for one application.
// GET /authsec/applications/:id/access/users
func (ctrl *ScopeMatrixController) ListApplicationAccessUsers(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	rs, err := ctrl.rsService.GetByIDAndTenant(c.Param("id"), tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	type row struct {
		BindingID      uuid.UUID
		UserID         uuid.UUID
		UserEmail      string
		UserName       string
		Username       string
		UserStatus     string
		FirstConsentAt *time.Time
		LastSeenAt     *time.Time
		RoleID         uuid.UUID
		RoleName       string
		ScopeType      *string
		ScopeID        *uuid.UUID
		CreatedAt      time.Time
		Source         string
	}
	var rows []row
	prefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	err = config.DB.Table("role_bindings rb").
		Select(`rb.id AS binding_id, rb.user_id, COALESCE(u.email, '') AS user_email,
			COALESCE(NULLIF(u.name, ''), u.email, rb.username, '') AS user_name,
			COALESCE(u.username, rb.username, '') AS username,
			COALESCE(teus.status, 'active') AS user_status,
			teus.first_consent_at, teus.last_seen_at,
			rb.role_id, COALESCE(rb.role_name, ro.name, '') AS role_name,
			rb.scope_type, rb.scope_id, rb.created_at, rb.assignment_source AS source`).
		Joins("JOIN roles ro ON ro.id = rb.role_id").
		Joins("LEFT JOIN users u ON u.id = rb.user_id AND u.tenant_id = rb.tenant_id").
		Joins("LEFT JOIN tenant_end_user_states teus ON teus.user_id = rb.user_id AND teus.tenant_id = rb.tenant_id").
		Where("rb.tenant_id = ? AND rb.user_id IS NOT NULL", tenantID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("ro.name LIKE ?", prefix+"%").
		Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", rs.ID).
		Order("u.email ASC, rb.created_at DESC").
		Scan(&rows).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	byUser := map[uuid.UUID]*applicationAccessUserResponse{}
	for _, r := range rows {
		item := byUser[r.UserID]
		if item == nil {
			item = &applicationAccessUserResponse{
				User: accessUserRef{
					ID:     r.UserID.String(),
					Email:  r.UserEmail,
					Name:   r.UserName,
					Status: r.UserStatus,
				},
				Roles:    []accessRoleRef{},
				Scopes:   []accessScopeRef{},
				Bindings: []rsBindingResponse{},
			}
			if r.FirstConsentAt != nil {
				item.FirstConsentAt = r.FirstConsentAt.UTC().Format(time.RFC3339)
			}
			if r.LastSeenAt != nil {
				item.LastSeenAt = r.LastSeenAt.UTC().Format(time.RFC3339)
			}
			byUser[r.UserID] = item
		}

		seenRole := false
		for _, role := range item.Roles {
			if role.ID == r.RoleID.String() {
				seenRole = true
				break
			}
		}
		if !seenRole {
			item.Roles = append(item.Roles, accessRoleRef{
				ID:        r.RoleID.String(),
				Name:      r.RoleName,
				Label:     applicationRoleLabel(r.RoleName),
				Source:    r.Source,
				BindingID: r.BindingID.String(),
			})
		}
		for _, scope := range scopeRefsForRole(config.DB, tenantID, r.RoleID, rs.ID) {
			item.Scopes = appendUniqueScopeRef(item.Scopes, scope)
		}
		var scopeIDStr *string
		if r.ScopeID != nil {
			s := r.ScopeID.String()
			scopeIDStr = &s
		}
		item.Bindings = append(item.Bindings, rsBindingResponse{
			ID:        r.BindingID.String(),
			UserID:    r.UserID.String(),
			Username:  r.Username,
			UserEmail: r.UserEmail,
			RoleID:    r.RoleID.String(),
			RoleName:  r.RoleName,
			ScopeType: r.ScopeType,
			ScopeID:   scopeIDStr,
			CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
			Source:    r.Source,
		})
	}

	out := make([]applicationAccessUserResponse, 0, len(byUser))
	for _, item := range byUser {
		out = append(out, *item)
	}
	c.JSON(http.StatusOK, gin.H{"users": out, "count": len(out)})
}

// GetApplicationUserEffectiveAccess computes one user's effective app scopes.
// GET /authsec/applications/:id/users/:user_id/effective-access
func (ctrl *ScopeMatrixController) GetApplicationUserEffectiveAccess(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	rs, err := ctrl.rsService.GetByIDAndTenant(c.Param("id"), tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	var user accessUserRef
	if err := config.DB.Table("users u").
		Select("u.id::text AS id, COALESCE(u.email, '') AS email, COALESCE(NULLIF(u.name, ''), u.email, u.username, '') AS name, COALESCE(teus.status, 'active') AS status").
		Joins("LEFT JOIN tenant_end_user_states teus ON teus.user_id = u.id AND teus.tenant_id = u.tenant_id").
		Where("u.id = ? AND u.tenant_id = ?", userID, tenantID).
		Take(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found for this tenant"})
		return
	}

	type bindingRoleRow struct {
		BindingID uuid.UUID
		RoleID    uuid.UUID
		RoleName  string
		Source    string
		ScopeType *string
		ScopeID   *uuid.UUID
	}
	var bindingRows []bindingRoleRow
	prefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if err := config.DB.Table("role_bindings rb").
		Select("rb.id AS binding_id, rb.role_id, COALESCE(rb.role_name, ro.name, '') AS role_name, rb.assignment_source AS source, rb.scope_type, rb.scope_id").
		Joins("JOIN roles ro ON ro.id = rb.role_id").
		Where("rb.tenant_id = ? AND rb.user_id = ?", tenantID, userID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("ro.name LIKE ?", prefix+"%").
		Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", rs.ID).
		Order("rb.created_at DESC").
		Scan(&bindingRows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	roles := make([]accessRoleRef, 0, len(bindingRows))
	grantsByScope := map[string][]scopeGrantSource{}
	removableByScope := map[string]bool{}
	for _, row := range bindingRows {
		roles = append(roles, accessRoleRef{
			ID:        row.RoleID.String(),
			Name:      row.RoleName,
			Label:     applicationRoleLabel(row.RoleName),
			Source:    row.Source,
			BindingID: row.BindingID.String(),
		})
		for _, scope := range scopeRefsForRole(config.DB, tenantID, row.RoleID, rs.ID) {
			grantsByScope[scope.ID] = append(grantsByScope[scope.ID], scopeGrantSource{
				RoleID:    row.RoleID.String(),
				RoleName:  row.RoleName,
				BindingID: row.BindingID.String(),
				Source:    row.Source,
			})
			if row.ScopeType != nil && *row.ScopeType == "resource_server" && row.ScopeID != nil && *row.ScopeID == rs.ID {
				removableByScope[scope.ID] = true
			}
		}
	}

	allScopes, err := ctrl.scopeRegistry.ListByResourceServer(tenantID, rs.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	scopes := make([]effectiveAccessScope, 0, len(allScopes))
	for _, scope := range allScopes {
		id := scope.ID.String()
		through := grantsByScope[id]
		status := "not_granted"
		if len(through) > 0 {
			status = "granted"
		}
		scopes = append(scopes, effectiveAccessScope{
			ID:             id,
			ScopeString:    scope.ScopeString,
			DisplayName:    scope.DisplayName,
			RiskLevel:      scope.RiskLevel,
			Status:         status,
			GrantedThrough: through,
			Removable:      removableByScope[id],
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"user":        user,
		"application": accessApplicationRef{ID: rs.ID.String(), Name: rs.Name, ResourceURI: rs.ResourceURI},
		"roles":       roles,
		"scopes":      scopes,
	})
}

// CreateApplicationRole creates an application-scoped role, grants selected
// application scopes, and optionally assigns it to users.
// POST /authsec/applications/:id/roles
func (ctrl *ScopeMatrixController) CreateApplicationRole(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	rs, err := ctrl.rsService.GetByIDAndTenant(c.Param("id"), tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req struct {
		Name          string   `json:"name" binding:"required"`
		Description   string   `json:"description"`
		ScopeIDs      []string `json:"scope_ids"`
		DefaultRole   bool     `json:"default_role"`
		AssignUserIDs []string `json:"assign_user_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	slug := normalizeApplicationRoleSlug(req.Name)
	if slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name must contain letters or numbers"})
		return
	}
	roleName := fmt.Sprintf("rs-%s:%s", rs.ID.String(), slug)

	scopeIDs := make([]uuid.UUID, 0, len(req.ScopeIDs))
	seenScopes := map[uuid.UUID]struct{}{}
	for _, raw := range req.ScopeIDs {
		parsed, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope_id"})
			return
		}
		if _, ok := seenScopes[parsed]; ok {
			continue
		}
		seenScopes[parsed] = struct{}{}
		scopeIDs = append(scopeIDs, parsed)
	}

	userIDs := make([]uuid.UUID, 0, len(req.AssignUserIDs))
	seenUsers := map[uuid.UUID]struct{}{}
	for _, raw := range req.AssignUserIDs {
		parsed, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assign_user_id"})
			return
		}
		if _, ok := seenUsers[parsed]; ok {
			continue
		}
		seenUsers[parsed] = struct{}{}
		userIDs = append(userIDs, parsed)
	}

	var selectedScopes []models.OAuthScope
	if len(scopeIDs) > 0 {
		if err := config.DB.Where("tenant_id = ? AND resource_server_id = ? AND id IN ?", tenantID, rs.ID, scopeIDs).
			Find(&selectedScopes).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if len(selectedScopes) != len(scopeIDs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "one or more scopes do not belong to this application"})
			return
		}
		for i := range selectedScopes {
			autoCreateScopePermission(tenantID, &selectedScopes[i])
		}
	}

	type userRow struct {
		ID       uuid.UUID
		Email    string
		Name     string
		Username *string
	}
	usersByID := map[uuid.UUID]userRow{}
	if len(userIDs) > 0 {
		var rows []userRow
		if err := config.DB.Table("users").
			Select("id, email, name, username").
			Where("tenant_id = ? AND id IN ?", tenantID, userIDs).
			Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if len(rows) != len(userIDs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "one or more users do not belong to this tenant"})
			return
		}
		for _, row := range rows {
			usersByID[row.ID] = row
		}
	}

	var permissionIDs []uuid.UUID
	if len(scopeIDs) > 0 {
		if err := config.DB.Table("oauth_scope_permissions").
			Select("DISTINCT permission_id").
			Where("scope_id IN ?", scopeIDs).
			Scan(&permissionIDs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	workspaceID := tenantID
	role := models.RBACRole{
		TenantID:    &tenantID,
		WorkspaceID: &workspaceID,
		Name:        roleName,
		Description: strings.TrimSpace(req.Description),
		IsSystem:    false,
	}
	rsScopeType := "resource_server"
	rsScopeID := rs.ID
	if err := config.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&role).Error; err != nil {
			return err
		}
		for _, permissionID := range permissionIDs {
			if err := tx.FirstOrCreate(&models.RolePermission{
				RoleID:       role.ID,
				PermissionID: permissionID,
			}).Error; err != nil {
				return err
			}
		}
		if req.DefaultRole {
			var policy models.ResourceServerAccessPolicy
			err := tx.Where("tenant_id = ? AND resource_server_id = ?", tenantID, rs.ID).First(&policy).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				policy = models.ResourceServerAccessPolicy{
					TenantID:          tenantID,
					ResourceServerID:  rs.ID,
					Enabled:           true,
					DefaultRoleID:     &role.ID,
					AssignmentTrigger: "first_successful_login",
					AssignmentSource:  "default_policy",
				}
				if err := tx.Create(&policy).Error; err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else if err := tx.Model(&policy).Updates(map[string]interface{}{
				"enabled":         true,
				"default_role_id": role.ID,
				"updated_at":      time.Now().UTC(),
			}).Error; err != nil {
				return err
			}
		}
		for _, userID := range userIDs {
			row := usersByID[userID]
			username := ""
			if row.Username != nil {
				username = *row.Username
			}
			if username == "" {
				username = row.Email
			}
			if username == "" {
				username = row.ID.String()
			}
			binding := models.RoleBinding{
				TenantID:         &tenantID,
				WorkspaceID:      &workspaceID,
				UserID:           &userID,
				Username:         username,
				RoleID:           role.ID,
				RoleName:         role.Name,
				ScopeType:        &rsScopeType,
				ScopeID:          &rsScopeID,
				Conditions:       json.RawMessage([]byte("{}")),
				AssignmentSource: "manual_admin",
				CreatedAt:        time.Now().UTC(),
			}
			if err := tx.Where(
				"tenant_id = ? AND user_id = ? AND role_id = ? AND scope_type = ? AND scope_id = ?",
				tenantID, userID, role.ID, rsScopeType, rsScopeID,
			).FirstOrCreate(&binding).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	scopes := scopeRefsForRole(config.DB, tenantID, role.ID, rs.ID)
	var usersCount int64
	config.DB.Table("role_bindings rb").
		Where("rb.tenant_id = ? AND rb.role_id = ? AND rb.user_id IS NOT NULL", tenantID, role.ID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("rb.scope_type = 'resource_server' AND rb.scope_id = ?", rs.ID).
		Select("COUNT(DISTINCT rb.user_id)").Scan(&usersCount)

	auditAdminMutation(c, tenantID.String(), "application_role_created", "role",
		role.ID.String(), http.StatusCreated, nil,
		map[string]interface{}{"rs_id": rs.ID, "scope_count": len(scopes), "users_count": usersCount})
	c.JSON(http.StatusCreated, applicationRoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Label:       applicationRoleLabel(role.Name),
		Description: role.Description,
		Application: accessApplicationRef{ID: rs.ID.String(), Name: rs.Name, ResourceURI: rs.ResourceURI},
		IsDefault:   req.DefaultRole,
		UsersCount:  usersCount,
		ScopesCount: len(scopes),
		Scopes:      scopes,
		Source:      applicationRoleSource(role.Name),
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

// ListScopeCatalog returns reusable catalog entries plus app-owned runtime
// scopes. Catalog entries do not directly grant runtime access.
// GET /authsec/scope-catalog
func (ctrl *ScopeMatrixController) ListScopeCatalog(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	out := []scopeCatalogEntryResponse{}
	var catalog []models.ScopeCatalogEntry
	if err := config.DB.Where("workspace_id = ?", tenantID).Order("key ASC").Find(&catalog).Error; err == nil {
		for _, entry := range catalog {
			out = append(out, scopeCatalogEntryResponse{
				ID:          entry.ID.String(),
				Kind:        "catalog",
				Key:         entry.Key,
				ScopeString: entry.Key,
				DisplayName: entry.DisplayName,
				Description: entry.Description,
				RiskLevel:   entry.RiskLevel,
				Source:      entry.Source,
				UpdatedAt:   entry.UpdatedAt.UTC().Format(time.RFC3339),
			})
		}
	}

	type scopeRow struct {
		ID          uuid.UUID
		ScopeString string
		DisplayName string
		Description string
		RiskLevel   string
		Source      string
		UpdatedAt   time.Time
		AppID       uuid.UUID
		AppName     string
		ResourceURI string
	}
	var rows []scopeRow
	if err := config.DB.Table("oauth_scopes os").
		Select(`os.id, os.scope_string, os.display_name, os.description, os.risk_level, os.source, os.updated_at,
			rs.id AS app_id, rs.name AS app_name, rs.resource_uri`).
		Joins("LEFT JOIN resource_servers rs ON rs.id = os.resource_server_id").
		Where("os.tenant_id = ?", tenantID).
		Order("COALESCE(rs.name, ''), os.scope_string ASC").
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for _, row := range rows {
		var toolsCount, rolesCount, usersCount, grantsCount int64
		config.DB.Table("mcp_tool_scope_map").Where("scope_id = ?", row.ID).Count(&toolsCount)
		config.DB.Table("role_permissions rp").
			Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id").
			Where("osp.scope_id = ?", row.ID).
			Select("COUNT(DISTINCT rp.role_id)").Scan(&rolesCount)
		config.DB.Table("role_bindings rb").
			Joins("JOIN role_permissions rp ON rp.role_id = rb.role_id").
			Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id").
			Where("rb.tenant_id = ? AND rb.user_id IS NOT NULL AND osp.scope_id = ?", tenantID, row.ID).
			Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
			Select("COUNT(DISTINCT rb.user_id)").Scan(&usersCount)
		config.DB.Table("oauth_consent_grants").
			Where("tenant_id = ? AND ? = ANY(granted_scopes) AND revoked_at IS NULL", tenantID, row.ScopeString).
			Count(&grantsCount)

		var appRef *accessApplicationRef
		if row.AppID != uuid.Nil {
			appRef = &accessApplicationRef{ID: row.AppID.String(), Name: row.AppName, ResourceURI: row.ResourceURI}
		}
		kind := "global"
		if appRef != nil {
			kind = "application"
		}
		out = append(out, scopeCatalogEntryResponse{
			ID:                 row.ID.String(),
			Kind:               kind,
			Key:                row.ScopeString,
			ScopeString:        row.ScopeString,
			DisplayName:        row.DisplayName,
			Description:        row.Description,
			RiskLevel:          row.RiskLevel,
			Source:             row.Source,
			Application:        appRef,
			ToolsCount:         toolsCount,
			RolesCount:         rolesCount,
			UsersCount:         usersCount,
			ConsentGrantsCount: grantsCount,
			UpdatedAt:          row.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}

	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	kindFilter := strings.ToLower(strings.TrimSpace(c.Query("kind")))
	riskFilter := strings.ToLower(strings.TrimSpace(c.Query("risk_level")))
	appFilter := strings.TrimSpace(c.Query("application_id"))
	if q != "" || kindFilter != "" || riskFilter != "" || appFilter != "" {
		filtered := make([]scopeCatalogEntryResponse, 0, len(out))
		for _, item := range out {
			if kindFilter != "" && strings.ToLower(item.Kind) != kindFilter {
				continue
			}
			if riskFilter != "" && strings.ToLower(item.RiskLevel) != riskFilter {
				continue
			}
			if appFilter != "" {
				if item.Application == nil || item.Application.ID != appFilter {
					continue
				}
			}
			if q != "" {
				haystack := strings.ToLower(strings.Join([]string{
					item.Key,
					item.ScopeString,
					item.DisplayName,
					item.Description,
					item.RiskLevel,
					item.Source,
					item.Kind,
				}, " "))
				if item.Application != nil {
					haystack += " " + strings.ToLower(item.Application.Name+" "+item.Application.ResourceURI)
				}
				if !strings.Contains(haystack, q) {
					continue
				}
			}
			filtered = append(filtered, item)
		}
		out = filtered
	}

	c.JSON(http.StatusOK, gin.H{"items": out, "count": len(out)})
}

// CreateScopeCatalogEntry creates a reusable scope template. Catalog entries
// do not grant access directly; they are copied into application-owned scopes.
// POST /authsec/scope-catalog
func (ctrl *ScopeMatrixController) CreateScopeCatalogEntry(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	var req struct {
		Key         string `json:"key" binding:"required"`
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
		RiskLevel   string `json:"risk_level"`
		Source      string `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if req.Key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key is required"})
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Key
	}
	if req.RiskLevel == "" {
		req.RiskLevel = "low"
	}
	if req.Source == "" {
		req.Source = "manual"
	}

	entry := models.ScopeCatalogEntry{
		WorkspaceID: tenantID,
		Key:         req.Key,
		DisplayName: req.DisplayName,
		Description: req.Description,
		RiskLevel:   req.RiskLevel,
		Source:      req.Source,
	}
	if err := config.DB.Create(&entry).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, scopeCatalogEntryResponse{
		ID:          entry.ID.String(),
		Kind:        "catalog",
		Key:         entry.Key,
		ScopeString: entry.Key,
		DisplayName: entry.DisplayName,
		Description: entry.Description,
		RiskLevel:   entry.RiskLevel,
		Source:      entry.Source,
		UpdatedAt:   entry.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

// AttachScopeCatalogEntryToApplication copies a catalog template into an
// application-owned runtime scope. Access checks still resolve only against the
// application scope.
// POST /authsec/scope-catalog/:catalog_id/applications/:application_id
func (ctrl *ScopeMatrixController) AttachScopeCatalogEntryToApplication(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	catalogID, err := uuid.Parse(c.Param("catalog_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid catalog_id"})
		return
	}
	appID, err := uuid.Parse(c.Param("application_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application_id"})
		return
	}
	rs, err := ctrl.rsService.GetByIDAndTenant(appID.String(), tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var entry models.ScopeCatalogEntry
	if err := config.DB.Where("id = ? AND workspace_id = ?", catalogID, tenantID).Take(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "catalog entry not found"})
		return
	}

	scope := models.OAuthScope{
		TenantID:         tenantID,
		WorkspaceID:      &tenantID,
		ResourceServerID: &appID,
		ScopeString:      entry.Key,
		DisplayName:      entry.DisplayName,
		Description:      entry.Description,
		RiskLevel:        entry.RiskLevel,
		Source:           "preset",
	}
	result := config.DB.Where(
		"tenant_id = ? AND resource_server_id = ? AND scope_string = ?",
		tenantID, appID, entry.Key,
	).FirstOrCreate(&scope)
	if result.Error != nil {
		c.JSON(http.StatusConflict, gin.H{"error": result.Error.Error()})
		return
	}

	autoCreateScopePermission(tenantID, &scope)
	syncScopesSupported(appID, tenantID)
	c.JSON(http.StatusOK, scopeCatalogEntryResponse{
		ID:          scope.ID.String(),
		Kind:        "application",
		Key:         scope.ScopeString,
		ScopeString: scope.ScopeString,
		DisplayName: scope.DisplayName,
		Description: scope.Description,
		RiskLevel:   scope.RiskLevel,
		Source:      scope.Source,
		Application: &accessApplicationRef{ID: rs.ID.String(), Name: rs.Name, ResourceURI: rs.ResourceURI},
		UpdatedAt:   scope.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

// UpdateRSRoleScopeGrants replaces the Application-scope grants on one
// Application-scoped role. The UI sends scope IDs, not permission IDs/strings;
// the backend owns the scope -> permission translation through
// oauth_scope_permissions.
// PUT /authsec/applications/:id/roles/:role_id/scope-grants
func (ctrl *ScopeMatrixController) UpdateRSRoleScopeGrants(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}

	var req struct {
		ScopeIDs []string `json:"scope_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	var role models.RBACRole
	if err := config.DB.Where("id = ? AND tenant_id = ?", roleID, tenantID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	prefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if !strings.HasPrefix(role.Name, prefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this application"})
		return
	}

	scopeIDs := make([]uuid.UUID, 0, len(req.ScopeIDs))
	seenScopeIDs := map[uuid.UUID]struct{}{}
	for _, raw := range req.ScopeIDs {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope_id: " + raw})
			return
		}
		if _, ok := seenScopeIDs[parsed]; ok {
			continue
		}
		seenScopeIDs[parsed] = struct{}{}
		scopeIDs = append(scopeIDs, parsed)
	}

	var selectedScopes []models.OAuthScope
	if len(scopeIDs) > 0 {
		if err := config.DB.
			Where("tenant_id = ? AND resource_server_id = ? AND id IN ?", tenantID, rs.ID, scopeIDs).
			Find(&selectedScopes).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if len(selectedScopes) != len(scopeIDs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "one or more scopes do not belong to this application"})
			return
		}
	}

	var allAppPermissionIDs []uuid.UUID
	if err := config.DB.
		Table("oauth_scope_permissions osp").
		Select("DISTINCT osp.permission_id").
		Joins("JOIN oauth_scopes os ON os.id = osp.scope_id").
		Where("os.tenant_id = ? AND os.resource_server_id = ?", tenantID, rs.ID).
		Scan(&allAppPermissionIDs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	selectedPermissionIDs := make([]uuid.UUID, 0)
	if len(scopeIDs) > 0 {
		if err := config.DB.
			Table("oauth_scope_permissions").
			Select("DISTINCT permission_id").
			Where("scope_id IN ?", scopeIDs).
			Scan(&selectedPermissionIDs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	err = config.DB.Transaction(func(tx *gorm.DB) error {
		if len(allAppPermissionIDs) > 0 {
			if err := tx.
				Where("role_id = ? AND permission_id IN ?", roleID, allAppPermissionIDs).
				Delete(&models.RolePermission{}).Error; err != nil {
				return err
			}
		}
		for _, permissionID := range selectedPermissionIDs {
			if err := tx.FirstOrCreate(&models.RolePermission{
				RoleID:       roleID,
				PermissionID: permissionID,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	grantedScopeStrings := make([]string, 0, len(selectedScopes))
	for _, scope := range selectedScopes {
		grantedScopeStrings = append(grantedScopeStrings, scope.ScopeString)
	}

	auditAdminMutation(c, tenantID.String(), "application_role_scope_grants_updated", "role",
		roleID.String(), http.StatusOK, nil,
		map[string]interface{}{"application_id": rs.ID, "scope_count": len(scopeIDs)})
	c.JSON(http.StatusOK, gin.H{
		"role_id":           roleID.String(),
		"role_name":         role.Name,
		"scope_ids":         req.ScopeIDs,
		"granted_scopes":    grantedScopeStrings,
		"permissions_count": len(selectedPermissionIDs),
	})
}

// ListRSBindings returns role_bindings that apply to this RS — either explicit
// (scope_type='resource_server' AND scope_id=rs.ID) or global (scope_type IS NULL),
// for any role whose name starts with rs-{id}: (i.e. RS-scoped roles only).
// GET /authsec/resource-servers/:id/bindings
func (ctrl *ScopeMatrixController) ListRSBindings(c *gin.Context) {
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

	prefix := fmt.Sprintf("rs-%s:", rs.ID.String())

	type row struct {
		ID        uuid.UUID
		UserID    *uuid.UUID
		Username  string
		UserEmail string
		RoleID    uuid.UUID
		RoleName  string
		ScopeType *string
		ScopeID   *uuid.UUID
		CreatedAt time.Time
		Source    string
	}
	var rows []row
	err = config.DB.
		Table("role_bindings rb").
		Select(`rb.id, rb.user_id, rb.username, COALESCE(u.email, '') AS user_email,
			rb.role_id, rb.role_name, rb.scope_type, rb.scope_id, rb.created_at, rb.assignment_source AS source`).
		Joins("JOIN roles ro ON ro.id = rb.role_id").
		Joins("LEFT JOIN users u ON u.id = rb.user_id AND u.tenant_id = rb.tenant_id").
		Where("rb.tenant_id = ?", tenantID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("ro.name LIKE ?", prefix+"%").
		Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?)", rs.ID).
		Order("rb.created_at DESC").
		Scan(&rows).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	out := make([]rsBindingResponse, 0, len(rows))
	for _, r := range rows {
		userIDStr := ""
		if r.UserID != nil {
			userIDStr = r.UserID.String()
		}
		var scopeIDStr *string
		if r.ScopeID != nil {
			s := r.ScopeID.String()
			scopeIDStr = &s
		}
		out = append(out, rsBindingResponse{
			ID:        r.ID.String(),
			UserID:    userIDStr,
			Username:  r.Username,
			UserEmail: r.UserEmail,
			RoleID:    r.RoleID.String(),
			RoleName:  r.RoleName,
			ScopeType: r.ScopeType,
			ScopeID:   scopeIDStr,
			CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
			Source:    r.Source,
		})
	}
	c.JSON(http.StatusOK, gin.H{"bindings": out})
}

// CreateRSBinding assigns a user to a role with scope_type='resource_server'
// and scope_id=rs.ID. The user must already exist in master users (admin
// users are there from signup; tenant end-users get mirrored on first
// consent flow via EnsureDefaultAccessBinding).
// POST /authsec/resource-servers/:id/bindings
func (ctrl *ScopeMatrixController) CreateRSBinding(c *gin.Context) {
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

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		RoleID string `json:"role_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id and role_id required"})
		return
	}
	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}

	// Verify the role belongs to this tenant and is RS-scoped (rs-{id}: prefix).
	var role models.RBACRole
	if err := config.DB.Where("id = ? AND tenant_id = ?", roleUUID, tenantID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	prefix := fmt.Sprintf("rs-%s:", rs.ID.String())
	if !strings.HasPrefix(role.Name, prefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this resource server"})
		return
	}

	// Single-tenant world: users live in one table. Verify the user belongs
	// to this tenant before creating the binding (FK will reject otherwise,
	// but a clean 404 is friendlier than a 500).
	var userRow struct {
		ID       uuid.UUID
		Email    string
		Name     string
		Username *string
	}
	if err := config.DB.Table("users").
		Select("id, email, name, username").
		Where("id = ? AND tenant_id = ?", userUUID, tenantID).
		Take(&userRow).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "user not found for this tenant",
			"hint":  "verify the user_id belongs to this tenant",
		})
		return
	}

	// Idempotent: don't create a duplicate.
	rsScopeType := "resource_server"
	rsScopeID := rs.ID
	var existingCount int64
	config.DB.Model(&models.RoleBinding{}).
		Where("tenant_id = ? AND user_id = ? AND role_id = ?", tenantID, userUUID, roleUUID).
		Where("scope_type = ? AND scope_id = ?", rsScopeType, rsScopeID).
		Count(&existingCount)
	if existingCount > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "binding already exists for this user+role+rs"})
		return
	}

	username := ""
	if userRow.Username != nil {
		username = *userRow.Username
	}
	if username == "" {
		username = userRow.Email
	}
	if username == "" {
		username = userRow.ID.String()
	}
	tenantUUID := tenantID
	binding := models.RoleBinding{
		TenantID:         &tenantUUID,
		UserID:           &userUUID,
		Username:         username,
		RoleID:           roleUUID,
		RoleName:         role.Name,
		ScopeType:        &rsScopeType,
		ScopeID:          &rsScopeID,
		Conditions:       json.RawMessage([]byte("{}")),
		AssignmentSource: "manual_admin",
		CreatedAt:        time.Now().UTC(),
	}
	if err := config.DB.Create(&binding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_binding_created", "role_binding",
		binding.ID.String(), http.StatusCreated, nil,
		map[string]interface{}{"user_id": userUUID, "role_id": roleUUID, "rs_id": rs.ID})
	c.JSON(http.StatusCreated, gin.H{
		"id":         binding.ID.String(),
		"user_id":    userUUID.String(),
		"role_id":    roleUUID.String(),
		"role_name":  role.Name,
		"scope_type": rsScopeType,
		"scope_id":   rsScopeID.String(),
	})
}

// DeleteRSBinding removes a role binding for this RS.
// DELETE /authsec/resource-servers/:id/bindings/:binding_id
func (ctrl *ScopeMatrixController) DeleteRSBinding(c *gin.Context) {
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

	bindingID, err := uuid.Parse(c.Param("binding_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid binding_id"})
		return
	}

	// Refuse to delete bindings that aren't actually scoped to this RS — defends
	// against the resolver's accept-globals path being used as a delete vector
	// for tenant-wide bindings.
	res := config.DB.
		Where("id = ? AND tenant_id = ?", bindingID, tenantID).
		Where("scope_type = 'resource_server' AND scope_id = ?", rs.ID).
		Delete(&models.RoleBinding{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "binding not found or not scoped to this RS"})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_binding_deleted", "role_binding",
		bindingID.String(), http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ListRSEndUsers lists end-users in the tenant DB so the RolesAccessTab can
// populate its "Assign to user" dropdown. Reads from the tenant DB via
// GetConnectionDynamically, with a small projection (no password hashes).
// GET /authsec/resource-servers/:id/eligible-users
func (ctrl *ScopeMatrixController) ListRSEndUsers(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	if _, err := ctrl.rsService.GetByIDAndTenant(c.Param("id"), tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}
	tenantDB := config.DB
	type u struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	var users []u
	tenantDB.Table("users").
		Select("id::text AS id, email, COALESCE(NULLIF(name, ''), email) AS name").
		Where("active = true").
		Order("created_at DESC").Limit(200).Scan(&users)
	// Always emit a JSON array, never null — destructuring defaults on the
	// frontend catch undefined but not null.
	if users == nil {
		users = []u{}
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// ── Helper functions ──────────────────────────────────────────────────────────────────────────────

// autoCreateScopePermission creates a matching permission + bridge for a scope (correctness #5).
func autoCreateScopePermission(tenantID uuid.UUID, scope *models.OAuthScope) {
	perm := models.RBACPermission{}
	if config.DB.Where("tenant_id = ? AND resource = ? AND action = ?",
		tenantID, scope.ScopeString, "access").First(&perm).Error != nil {
		perm = models.RBACPermission{
			TenantID:    &tenantID,
			Resource:    scope.ScopeString,
			Action:      "access",
			Description: fmt.Sprintf("OAuth scope: %s", scope.DisplayName),
		}
		config.DB.Create(&perm)
	}

	bridge := models.OAuthScopePermission{ScopeID: scope.ID, PermissionID: perm.ID}
	config.DB.Where("scope_id = ? AND permission_id = ?", scope.ID, perm.ID).FirstOrCreate(&bridge)
}

// syncScopesSupported keeps resource_servers.scopes_supported in sync with oauth_scopes (correctness #4).
func syncScopesSupported(rsID uuid.UUID, tenantID uuid.UUID) {
	var scopeStrings []string
	config.DB.Model(&models.OAuthScope{}).
		Where("resource_server_id = ? AND tenant_id = ?", rsID, tenantID).
		Pluck("scope_string", &scopeStrings)
	if scopeStrings == nil {
		scopeStrings = []string{}
	}
	config.DB.Model(&models.ResourceServer{}).
		Where("id = ?", rsID).
		Update("scopes_supported", scopeStrings)
}

// extractUserIDOptional tries to extract user ID from JWT claims without failing.
func extractUserIDOptional(c *gin.Context) *uuid.UUID {
	rawID, exists := c.Get("user_id")
	if !exists {
		return nil
	}
	switch v := rawID.(type) {
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			return nil
		}
		return &id
	case uuid.UUID:
		return &v
	}
	return nil
}

// extractUserIDRequired extracts user ID from JWT, returns nil if missing.
func extractUserIDRequired(c *gin.Context) *uuid.UUID {
	return extractUserIDOptional(c)
}

// recordManifestAttempt writes a ResourceServerManifestAttempt row.
func recordManifestAttempt(rs *models.ResourceServer, status string, reason string, toolCount int, manifestVersion string) {
	if rs == nil {
		return
	}
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	var versionPtr *string
	if manifestVersion != "" {
		versionPtr = &manifestVersion
	}
	var countPtr *int
	if toolCount > 0 {
		countPtr = &toolCount
	}
	config.DB.Create(&models.ResourceServerManifestAttempt{
		RSID:            rs.ID,
		AttemptedAt:     time.Now().UTC(),
		Status:          status,
		Reason:          reasonPtr,
		ToolCount:       countPtr,
		ManifestVersion: versionPtr,
	})
}

func recordManifestAttemptWithVersion(rs *models.ResourceServer, status string, reason string, toolCount int, manifestVersion string, sdkBuildID string) {
	if rs == nil {
		return
	}
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	var versionPtr *string
	if manifestVersion != "" {
		versionPtr = &manifestVersion
	}
	var buildPtr *string
	if sdkBuildID != "" {
		buildPtr = &sdkBuildID
	}
	tc := toolCount
	config.DB.Create(&models.ResourceServerManifestAttempt{
		RSID:            rs.ID,
		AttemptedAt:     time.Now().UTC(),
		Status:          status,
		Reason:          reasonPtr,
		ToolCount:       &tc,
		ManifestVersion: versionPtr,
		SDKBuildID:      buildPtr,
	})
}

func maybeAttempt(exists bool, a models.ResourceServerManifestAttempt) interface{} {
	if !exists {
		return nil
	}
	return a
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
