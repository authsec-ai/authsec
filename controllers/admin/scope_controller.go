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

type ScopeController struct {
	service *scopeService
}

func NewScopeController() *ScopeController {
	return &ScopeController{service: newScopeService()}
}

type ScopeMapping = scopeMappingRecord

type AddScopeInput struct {
	ScopeName           string   `json:"scope_name" binding:"required"`
	Description         string   `json:"description"`
	Usage               string   `json:"usage,omitempty"`
	PermissionIDs       []string `json:"permission_ids,omitempty"`
	MappedPermissionIDs []string `json:"mapped_permission_ids,omitempty"`
	Resources           []string `json:"resources,omitempty"`
}

type EditScopeInput struct {
	Description         string   `json:"description,omitempty"`
	Usage               string   `json:"usage,omitempty"`
	PermissionIDs       []string `json:"permission_ids,omitempty"`
	MappedPermissionIDs []string `json:"mapped_permission_ids,omitempty"`
	Resources           []string `json:"resources,omitempty"`
}

func (sc *ScopeController) ListScopes(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.listScopes(c, config.DB, *tenantID)
}

func (sc *ScopeController) GetMappings(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.getMappings(c, config.DB, *tenantID)
}

func (sc *ScopeController) AddScope(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.addScope(c, config.DB, *tenantID)
}

func (sc *ScopeController) EditScope(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.editScope(c, config.DB, *tenantID)
}

func (sc *ScopeController) DeleteScope(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	sc.deleteScope(c, config.DB, *tenantID)
}

func (sc *ScopeController) ListUserScopes(c *gin.Context) {
	db, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.listScopes(c, db, tenantID)
}

func (sc *ScopeController) GetUserMappings(c *gin.Context) {
	db, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.getMappings(c, db, tenantID)
}

func (sc *ScopeController) AddUserScope(c *gin.Context) {
	db, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.addScope(c, db, tenantID)
}

func (sc *ScopeController) EditUserScope(c *gin.Context) {
	db, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.editScope(c, db, tenantID)
}

func (sc *ScopeController) DeleteUserScope(c *gin.Context) {
	db, tenantID, ok := scopeTenantDB(c)
	if !ok {
		return
	}
	sc.deleteScope(c, db, tenantID)
}

func (sc *ScopeController) listScopes(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	items, err := sc.service.listScopeItems(db, tenantID, []string{models.ScopeUsageInternal, models.ScopeUsageBoth}, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scopes: " + err.Error()})
		return
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	c.JSON(http.StatusOK, names)
}

func (sc *ScopeController) getMappings(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	resp, err := sc.service.listScopeMappings(db, tenantID, []string{models.ScopeUsageInternal, models.ScopeUsageBoth})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scope mappings: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (sc *ScopeController) addScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	var input AddScopeInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload: " + err.Error()})
		return
	}

	usage, err := sc.service.normalizeUsage(input.Usage, models.ScopeUsageInternal, []string{models.ScopeUsageInternal, models.ScopeUsageBoth})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	permissionIDs, err := sc.service.resolvePermissionIDs(db, tenantID, input.PermissionIDs, input.MappedPermissionIDs, input.Resources)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := sc.service.createScope(db, tenantID, input.ScopeName, input.Description, usage, permissionIDs)
	if err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "duplicate") || strings.Contains(errLower, "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "scope name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scope: " + err.Error()})
		return
	}

	middlewares.Audit(c, "scope", resp.ID, "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"scope_id":          resp.ID,
			"name":              resp.Name,
			"usage":             resp.Usage,
			"permissions_count": resp.PermissionsLinked,
		},
	})
	c.JSON(http.StatusCreated, gin.H{"message": "scope created successfully", "scope_id": resp.ID, "scope_name": resp.Name})
}

func (sc *ScopeController) editScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	scopeName := strings.TrimSpace(c.Param("scope_name"))
	if scopeName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scope_name is required"})
		return
	}

	var input EditScopeInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload: " + err.Error()})
		return
	}

	scope, err := sc.service.loadScopeByName(db, tenantID, scopeName, []string{models.ScopeUsageInternal, models.ScopeUsageBoth})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load scope: " + err.Error()})
		return
	}

	var usagePtr *string
	if strings.TrimSpace(input.Usage) != "" {
		usage, err := sc.service.normalizeUsage(input.Usage, scope.Usage, []string{models.ScopeUsageInternal, models.ScopeUsageBoth})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		usagePtr = &usage
	}

	replacePermissions := input.PermissionIDs != nil || input.MappedPermissionIDs != nil || input.Resources != nil
	permissionIDs := []uuid.UUID{}
	if replacePermissions {
		permissionIDs, err = sc.service.resolvePermissionIDs(db, tenantID, input.PermissionIDs, input.MappedPermissionIDs, input.Resources)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	var descriptionPtr *string
	if input.Description != "" {
		description := input.Description
		descriptionPtr = &description
	}

	resp, err := sc.service.updateScope(db, scope, nil, descriptionPtr, usagePtr, permissionIDs, replacePermissions)
	if err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "duplicate") || strings.Contains(errLower, "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "scope name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update scope: " + err.Error()})
		return
	}

	middlewares.Audit(c, "scope", resp.ID, "update", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"scope_id":          resp.ID,
			"name":              resp.Name,
			"usage":             resp.Usage,
			"permissions_count": resp.PermissionsLinked,
		},
	})
	c.JSON(http.StatusOK, gin.H{"message": "scope updated successfully", "scope_id": resp.ID, "scope_name": resp.Name})
}

func (sc *ScopeController) deleteScope(c *gin.Context, db *gorm.DB, tenantID uuid.UUID) {
	scopeName := strings.TrimSpace(c.Param("scope_name"))
	if scopeName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scope_name is required"})
		return
	}

	scope, err := sc.service.loadScopeByName(db, tenantID, scopeName, []string{models.ScopeUsageInternal, models.ScopeUsageBoth})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load scope: " + err.Error()})
		return
	}

	if err := sc.service.deleteScope(db, scope); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete scope: " + err.Error()})
		return
	}

	middlewares.Audit(c, "scope", scope.ID.String(), "delete", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"name":  scope.Name,
			"usage": scope.Usage,
		},
	})
	c.JSON(http.StatusOK, gin.H{"message": "scope deleted successfully"})
}
