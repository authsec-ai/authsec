package platform

import (
	"context"
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
	rsService      *services.ResourceServerService
	scopeRegistry  *services.ScopeRegistryService
	oauthService   *services.OAuthASService
}

func NewScopeMatrixController() *ScopeMatrixController {
	return &ScopeMatrixController{
		rsService:     services.NewResourceServerService(config.DB),
		scopeRegistry: services.NewScopeRegistryService(config.DB),
		oauthService:  services.NewOAuthASService(config.DB),
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

	// Get tools with their scope mappings
	var tools []models.MCPTool
	config.DB.Preload("Scopes").
		Where("tenant_id = ? AND resource_server_id = ?", tenantID, rsUUID).
		Order("name").
		Find(&tools)

	// Get all scopes for this RS
	scopes, _ := ctrl.scopeRegistry.ListByResourceServer(tenantID, rsUUID)

	// Build tool responses
	var toolResponses []models.MCPToolResponse
	mappedScopeIDs := make(map[uuid.UUID]bool)

	for _, tool := range tools {
		tr := models.MCPToolResponse{
			ID:          tool.ID.String(),
			Name:        tool.Name,
			Title:       tool.Title,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
			Annotations: tool.Annotations,
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

	// Find unmapped scopes
	var unmappedScopes []models.OAuthScopeResponse
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
			"id":   rs.ID.String(),
			"name": rs.Name,
			"url":  rs.PublicBaseURL,
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

	result, err := ctrl.rsService.DiscoverAndSync(ctx, rs)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
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

	if req.ParentScopeID != "" {
		pid, err := uuid.Parse(req.ParentScopeID)
		if err == nil {
			scope.ParentScopeID = &pid
		}
	}

	if err := ctrl.scopeRegistry.Create(scope); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	// Link permissions if provided
	for _, pidStr := range req.PermissionIDs {
		pid, err := uuid.Parse(pidStr)
		if err != nil {
			continue
		}
		config.DB.Create(&models.OAuthScopePermission{ScopeID: scope.ID, PermissionID: pid})
	}

	c.JSON(http.StatusCreated, scope)
}

// UpdateScope updates scope metadata.
// PUT /authsec/scopes/:scope_id
func (ctrl *ScopeMatrixController) UpdateScope(c *gin.Context) {
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

	scope, err := ctrl.scopeRegistry.Update(scopeID, &req)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, scope)
}

// DeleteScope removes a scope.
// DELETE /authsec/scopes/:scope_id
func (ctrl *ScopeMatrixController) DeleteScope(c *gin.Context) {
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope ID"})
		return
	}

	if err := ctrl.scopeRegistry.Delete(scopeID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// UpdateToolScopeMap manually maps/unmaps tools to scopes.
// PUT /authsec/resource-servers/:id/tool-scope-map
func (ctrl *ScopeMatrixController) UpdateToolScopeMap(c *gin.Context) {
	rsID := c.Param("id")

	var req struct {
		Mappings []struct {
			ToolID  string `json:"tool_id" binding:"required"`
			ScopeID string `json:"scope_id" binding:"required"`
			Remove  bool   `json:"remove"`
		} `json:"mappings" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	for _, m := range req.Mappings {
		toolID, _ := uuid.Parse(m.ToolID)
		scopeID, _ := uuid.Parse(m.ScopeID)

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
	}

	_ = rsID // validated by middleware
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
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

	// Fetch MCP tools with their scope mappings (same query as GetScopeMatrix)
	var tools []models.MCPTool
	config.DB.Preload("Scopes").
		Where("tenant_id = ? AND resource_server_id = ?", rs.TenantID, rs.ID).
		Order("name").
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
