package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/services"
)

// PKIAdminController handles PKI provisioning for tenants
type PKIAdminController struct {
	pkiService *services.PKIProvisioningService
	logger     *logrus.Entry
}

// NewPKIAdminController creates a new PKI admin controller
func NewPKIAdminController(pkiService *services.PKIProvisioningService, logger *logrus.Entry) *PKIAdminController {
	return &PKIAdminController{
		pkiService: pkiService,
		logger:     logger,
	}
}

// ProvisionPKI handles POST /spire/admin/pki/provision
func (ctrl *PKIAdminController) ProvisionPKI(c *gin.Context) {
	var req struct {
		WorkspaceID       string `json:"workspace_id"`
		CommonName     string `json:"common_name,omitempty"`
		Domain         string `json:"domain,omitempty"`
		TTL            string `json:"ttl,omitempty"`
		MaxTTL         string `json:"max_ttl,omitempty"`
		AllowedDomains string `json:"allowed_domains,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		ctrl.sendError(c, errors.NewBadRequestError("Invalid request body", err))
		return
	}

	if req.WorkspaceID == "" {
		ctrl.sendError(c, errors.NewBadRequestError("workspace_id is required", nil))
		return
	}

	// Map domain to allowed_domains if allowed_domains is empty
	allowedDomains := req.AllowedDomains
	if allowedDomains == "" && req.Domain != "" {
		allowedDomains = req.Domain
	}

	result, err := ctrl.pkiService.ProvisionPKI(c.Request.Context(), &services.ProvisionPKIRequest{
		WorkspaceID:       req.WorkspaceID,
		CommonName:     req.CommonName,
		TTL:            req.TTL,
		MaxTTL:         req.MaxTTL,
		AllowedDomains: allowedDomains,
	})
	if err != nil {
		ctrl.sendError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// ProvisionPKIForTenant handles POST /spire/admin/pki/provision/:workspace_id
func (ctrl *PKIAdminController) ProvisionPKIForTenant(c *gin.Context) {
	workspaceID := c.Param("workspace_id")

	if workspaceID == "" {
		ctrl.sendError(c, errors.NewBadRequestError("workspace_id is required", nil))
		return
	}

	// Parse optional request body
	var req struct {
		CommonName     string `json:"common_name,omitempty"`
		Domain         string `json:"domain,omitempty"`
		TTL            string `json:"ttl,omitempty"`
		MaxTTL         string `json:"max_ttl,omitempty"`
		AllowedDomains string `json:"allowed_domains,omitempty"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			ctrl.sendError(c, errors.NewBadRequestError("Invalid request body", err))
			return
		}
	}

	// Map domain to allowed_domains if allowed_domains is empty
	allowedDomains := req.AllowedDomains
	if allowedDomains == "" && req.Domain != "" {
		allowedDomains = req.Domain
	}

	result, err := ctrl.pkiService.ProvisionPKI(c.Request.Context(), &services.ProvisionPKIRequest{
		WorkspaceID:       workspaceID,
		CommonName:     req.CommonName,
		TTL:            req.TTL,
		MaxTTL:         req.MaxTTL,
		AllowedDomains: allowedDomains,
	})
	if err != nil {
		ctrl.sendError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// sendError sends an error response
func (ctrl *PKIAdminController) sendError(c *gin.Context, err error) {
	appErr, ok := err.(*errors.AppError)
	if !ok {
		appErr = errors.NewInternalError("Internal server error", err)
	}

	ctrl.logger.WithFields(logrus.Fields{
		"code":    appErr.Code,
		"message": appErr.Message,
	}).WithError(appErr.Err).Error("PKI admin request failed")

	c.JSON(appErr.Status, dto.ErrorResponse{
		Error: dto.ErrorDetail{
			Code:    appErr.Code,
			Message: appErr.Message,
		},
	})
}
