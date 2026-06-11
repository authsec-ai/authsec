package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IdentityProvidersV2Controller serves the tenant-scoped IDP registry on the
// prod backport.
//
// Routes:
//
//	POST   /authsec/identity-providers
//	GET    /authsec/identity-providers
//	GET    /authsec/identity-providers/:id
//	PUT    /authsec/identity-providers/:id/status
//	DELETE /authsec/identity-providers/:id
type IdentityProvidersV2Controller struct {
	service *services.IdentityProviderV2Service
}

func NewIdentityProvidersV2Controller() *IdentityProvidersV2Controller {
	return &IdentityProvidersV2Controller{service: services.NewIdentityProviderV2Service()}
}

type createIDPRequest struct {
	ProviderType string          `json:"provider_type" binding:"required"`
	DisplayName  string          `json:"display_name" binding:"required"`
	Config       json.RawMessage `json:"config" binding:"required"`
}

type oidcCreateConfig struct {
	ProviderName string `json:"provider_name" binding:"required"`
	ConfigRef    string `json:"config_ref" binding:"required"`
}

type samlCreateConfig struct {
	ProviderName string `json:"provider_name" binding:"required"`
	ConfigRef    string `json:"config_ref" binding:"required"`
}

func (ctrl *IdentityProvidersV2Controller) Create(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	userIDStr, _ := middlewares.ResolveUserID(c)
	userID, _ := uuid.Parse(userIDStr)

	var req createIDPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	switch req.ProviderType {
	case models.IdentityProviderOIDC:
		var cfg oidcCreateConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oidc config: " + err.Error()})
			return
		}
		idp, err := ctrl.service.CreateOIDC(services.CreateOIDCIDPRequest{
			TenantID:        tenantID,
			CreatedByUserID: userID,
			DisplayName:     req.DisplayName,
			ProviderName:    cfg.ProviderName,
			ConfigRef:       cfg.ConfigRef,
		})
		if err != nil {
			if errors.Is(err, services.ErrIdentityProviderAlreadyExists) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, idp)
	case models.IdentityProviderSAML:
		var cfg samlCreateConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid saml config: " + err.Error()})
			return
		}
		idp, err := ctrl.service.CreateSAML(services.CreateSAMLIDPRequest{
			TenantID:        tenantID,
			CreatedByUserID: userID,
			DisplayName:     req.DisplayName,
			ProviderName:    cfg.ProviderName,
			ConfigRef:       cfg.ConfigRef,
		})
		if err != nil {
			if errors.Is(err, services.ErrIdentityProviderAlreadyExists) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, idp)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported provider_type; supported: 'oidc', 'saml'",
		})
	}
}

func (ctrl *IdentityProvidersV2Controller) List(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	rows, err := ctrl.service.List(tenantID, c.Query("provider_type"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (ctrl *IdentityProvidersV2Controller) Get(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	idp, err := ctrl.service.GetByID(tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
		return
	}
	c.JSON(http.StatusOK, idp)
}

func (ctrl *IdentityProvidersV2Controller) UpdateStatus(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := ctrl.service.UpdateStatus(tenantID, id, body.Status); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": body.Status})
}

func (ctrl *IdentityProvidersV2Controller) Delete(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	if err := ctrl.service.Delete(tenantID, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ──────────────────────────────────────────────────────────────────────────
// Application ↔ IDP policy endpoints
// ──────────────────────────────────────────────────────────────────────────

// PinIDP handles POST /authsec/applications/:id/identity-providers
func (ctrl *IdentityProvidersV2Controller) PinIDP(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	var body struct {
		IdentityProviderID string `json:"identity_provider_id" binding:"required"`
		Enabled            *bool  `json:"enabled,omitempty"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	idpID, err := uuid.Parse(body.IdentityProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_provider_id"})
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	row, err := ctrl.service.PinIDPToApplication(tenantID, applicationID, idpID, enabled)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

// UnpinIDP handles DELETE /authsec/applications/:id/identity-providers/:idp_id
func (ctrl *IdentityProvidersV2Controller) UnpinIDP(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	idpID, err := uuid.Parse(c.Param("idp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid idp_id"})
		return
	}
	if err := ctrl.service.UnpinIDPFromApplication(tenantID, applicationID, idpID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ListApplicationPolicies handles GET /authsec/applications/:id/identity-providers
func (ctrl *IdentityProvidersV2Controller) ListApplicationPolicies(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rows, err := ctrl.service.ListApplicationPolicies(tenantID, applicationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}
