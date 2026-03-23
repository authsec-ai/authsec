package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type APIScopesController struct {
	service *scopeService
}

func NewAPIScopesController() *APIScopesController {
	return &APIScopesController{service: newScopeService()}
}

func (sc *APIScopesController) CreateAPIScopeAdmin(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.createAPIScope(c, config.DB, *tenantID)
}

func (sc *APIScopesController) ListAPIScopesAdmin(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.listAPIScopes(c, config.DB, *tenantID)
}

func (sc *APIScopesController) GetAPIScopeAdmin(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.getAPIScope(c, config.DB, *tenantID)
}

func (sc *APIScopesController) UpdateAPIScopeAdmin(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.updateAPIScope(c, config.DB, *tenantID)
}

func (sc *APIScopesController) DeleteAPIScopeAdmin(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.deleteAPIScope(c, config.DB, *tenantID)
}

func (sc *APIScopesController) CreateAPIScopeEndUser(c *gin.Context) {
	tenantDB, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.createAPIScope(c, tenantDB, tenantID)
}

func (sc *APIScopesController) ListAPIScopesEndUser(c *gin.Context) {
	tenantDB, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.listAPIScopes(c, tenantDB, tenantID)
}

func (sc *APIScopesController) GetAPIScopeEndUser(c *gin.Context) {
	tenantDB, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.getAPIScope(c, tenantDB, tenantID)
}

func (sc *APIScopesController) UpdateAPIScopeEndUser(c *gin.Context) {
	tenantDB, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.updateAPIScope(c, tenantDB, tenantID)
}

func (sc *APIScopesController) DeleteAPIScopeEndUser(c *gin.Context) {
	tenantDB, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.deleteAPIScope(c, tenantDB, tenantID)
}

func (sc *APIScopesController) createAPIScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	var req models.CreateAPIScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}
	if !strings.Contains(req.Name, ":") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scope name should be in format 'resource:action'"})
		return
	}

	usage, err := sc.service.normalizeUsage(req.Usage, models.ScopeUsageOAuth, []string{models.ScopeUsageOAuth, models.ScopeUsageBoth})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	permissionIDs, err := sc.service.resolvePermissionIDs(db, tenantID, req.PermissionIDs, req.MappedPermissionIDs, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := sc.service.createScope(db, tenantID, req.Name, req.Description, usage, permissionIDs)
	if err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "duplicate") || strings.Contains(errLower, "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "scope name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API scope: " + err.Error()})
		return
	}

	middlewares.Audit(c, "api_scope", resp.ID, "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"scope_id":          resp.ID,
			"name":              resp.Name,
			"usage":             resp.Usage,
			"permissions_count": resp.PermissionsLinked,
		},
	})
	c.JSON(http.StatusOK, resp)
}

func (sc *APIScopesController) listAPIScopes(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	resp, err := sc.service.listScopeItems(db, tenantID, []string{models.ScopeUsageOAuth, models.ScopeUsageBoth}, c.Query("name"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API scopes: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (sc *APIScopesController) getAPIScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scope ID format"})
		return
	}
	scope, err := sc.service.loadScopeByID(db, tenantID, scopeID, []string{models.ScopeUsageOAuth, models.ScopeUsageBoth})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "API scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get API scope: " + err.Error()})
		return
	}
	resp, err := sc.service.buildScopeResponse(db, *scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load API scope permissions: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (sc *APIScopesController) updateAPIScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scope ID format"})
		return
	}

	var req models.UpdateAPIScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}
	if req.Name != "" && !strings.Contains(req.Name, ":") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scope name should be in format 'resource:action'"})
		return
	}

	scope, err := sc.service.loadScopeByID(db, tenantID, scopeID, []string{models.ScopeUsageOAuth, models.ScopeUsageBoth})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "API scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load API scope: " + err.Error()})
		return
	}

	var usagePtr *string
	if strings.TrimSpace(req.Usage) != "" {
		usage, err := sc.service.normalizeUsage(req.Usage, scope.Usage, []string{models.ScopeUsageOAuth, models.ScopeUsageBoth})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		usagePtr = &usage
	}

	replacePermissions := req.PermissionIDs != nil || req.MappedPermissionIDs != nil
	permissionIDs := []uuid.UUID{}
	if replacePermissions {
		permissionIDs, err = sc.service.resolvePermissionIDs(db, tenantID, req.PermissionIDs, req.MappedPermissionIDs, nil)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	var namePtr *string
	if strings.TrimSpace(req.Name) != "" {
		name := strings.TrimSpace(req.Name)
		namePtr = &name
	}
	var descriptionPtr *string
	if req.Description != "" {
		description := req.Description
		descriptionPtr = &description
	}

	resp, err := sc.service.updateScope(db, scope, namePtr, descriptionPtr, usagePtr, permissionIDs, replacePermissions)
	if err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "duplicate") || strings.Contains(errLower, "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "scope name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update API scope: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (sc *APIScopesController) deleteAPIScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scope ID format"})
		return
	}
	scope, err := sc.service.loadScopeByID(db, tenantID, scopeID, []string{models.ScopeUsageOAuth, models.ScopeUsageBoth})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "API scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load API scope: " + err.Error()})
		return
	}
	if err := sc.service.deleteScope(db, scope); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API scope: " + err.Error()})
		return
	}
	middlewares.Audit(c, "api_scope", scope.ID.String(), "delete", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"name":  scope.Name,
			"usage": scope.Usage,
		},
	})
	c.JSON(http.StatusOK, gin.H{"message": "API scope deleted successfully"})
}

func scopeTenantDB(c *gin.Context) (*gorm.DB, uuid.UUID, bool) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in token"})
		return nil, uuid.Nil, false
	}

	tenantDB, err := middlewares.GetConnectionDynamically(config.DB, nil, &tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to tenant database"})
		return nil, uuid.Nil, false
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant ID format"})
		return nil, uuid.Nil, false
	}

	return tenantDB, tenantUUID, true
}
