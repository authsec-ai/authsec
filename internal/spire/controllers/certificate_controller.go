package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/services"
)

// CertificateController handles certificate renewal and revocation (mTLS).
// The workspace is the client certificate's.
type CertificateController struct {
	renewalService    *services.RenewalService
	revocationService *services.RevocationService
	logger            *logrus.Entry
}

// NewCertificateController creates a new certificate controller
func NewCertificateController(renewalService *services.RenewalService, revocationService *services.RevocationService, logger *logrus.Entry) *CertificateController {
	return &CertificateController{renewalService: renewalService, revocationService: revocationService, logger: logger}
}

// Renew handles POST /spiresvc/v1/renew
func (ctrl *CertificateController) Renew(c *gin.Context) {
	var req dto.RenewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if req.CSR == "" || req.WorkloadID == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("csr and workload_id are required", nil))
		return
	}
	resp, err := ctrl.renewalService.Renew(c.Request.Context(), &services.RenewRequest{
		WorkloadID:     req.WorkloadID,
		CSR:            req.CSR,
		OldCertificate: req.OldCertificate,
		IPAddress:      c.ClientIP(),
		UserAgent:      c.Request.UserAgent(),
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, dto.RenewResponse{
		Certificate:  resp.Certificate,
		CAChain:      resp.CAChain,
		ExpiresAt:    resp.ExpiresAt,
		SerialNumber: resp.SerialNumber,
	})
}

// Revoke handles POST /spiresvc/v1/revoke
func (ctrl *CertificateController) Revoke(c *gin.Context) {
	var req dto.RevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if req.SerialNumber == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("serial_number is required", nil))
		return
	}
	if err := ctrl.revocationService.Revoke(c.Request.Context(), &services.RevokeRequest{
		SerialNumber: req.SerialNumber,
		Reason:       req.Reason,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	}); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Certificate revoked successfully", "serial_number": req.SerialNumber})
}
