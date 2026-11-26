package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/services"
)

// PKIAdminController provisions the caller's workspace PKI
// (AuthMiddleware + owner/admin).
type PKIAdminController struct {
	pkiService    *services.PKIProvisioningService
	workspaceRepo repositories.WorkspaceRepository
	logger        *logrus.Entry
}

// NewPKIAdminController creates a new PKI admin controller
func NewPKIAdminController(pkiService *services.PKIProvisioningService, workspaceRepo repositories.WorkspaceRepository, logger *logrus.Entry) *PKIAdminController {
	return &PKIAdminController{pkiService: pkiService, workspaceRepo: workspaceRepo, logger: logger}
}

type provisionPKIBody struct {
	WorkspaceID    string `json:"workspace_id,omitempty"`
	CommonName     string `json:"common_name,omitempty"`
	Domain         string `json:"domain,omitempty"`
	TTL            string `json:"ttl,omitempty"`
	MaxTTL         string `json:"max_ttl,omitempty"`
	AllowedDomains string `json:"allowed_domains,omitempty"`
}

// ProvisionPKI handles POST /spiresvc/admin/pki/provision and
// /spiresvc/admin/pki/provision/:workspace_id. The workspace is the
// caller's (AuthMiddleware answers 404 for any other path/body workspace).
// The PKI mount and allowed domain derive from the workspace itself: a
// domain other than the workspace's own is refused, so one workspace cannot
// provision (or replace) the CA at another workspace's mount.
func (ctrl *PKIAdminController) ProvisionPKI(c *gin.Context) {
	var req provisionPKIBody
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
			return
		}
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if err := sameWorkspace(c, c.Param("workspace_id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	wsID, err := requestWorkspace(c)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	ws, err := ctrl.workspaceRepo.GetByID(c.Request.Context(), wsID)
	if err != nil {
		sendError(c, ctrl.logger, errors.NewNotFoundError("Workspace not found", err))
		return
	}

	own := ws.Domain
	if own == "" {
		own = ws.ID
	}
	asked := req.AllowedDomains
	if asked == "" {
		asked = req.Domain
	}
	if asked != "" && !strings.EqualFold(asked, own) {
		sendError(c, ctrl.logger, errors.NewBadRequestError("allowed_domains must be the workspace's own domain", nil))
		return
	}
	commonName := req.CommonName
	if commonName == "" {
		commonName = own
	}

	result, err := ctrl.pkiService.ProvisionPKI(c.Request.Context(), &services.ProvisionPKIRequest{
		WorkspaceID:    ws.ID,
		CommonName:     commonName,
		TTL:            req.TTL,
		MaxTTL:         req.MaxTTL,
		AllowedDomains: own,
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
