package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/services"
)

// AttestationController handles direct workload attestation (mTLS).
type AttestationController struct {
	service *services.AttestationService
	logger  *logrus.Entry
}

// NewAttestationController creates a new attestation controller
func NewAttestationController(service *services.AttestationService, logger *logrus.Entry) *AttestationController {
	return &AttestationController{service: service, logger: logger}
}

// Attest handles POST /spiresvc/v1/attest. The workspace is the client
// certificate's; the PKI mount is the workspace's own.
func (ctrl *AttestationController) Attest(c *gin.Context) {
	var req dto.AttestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if req.CSR == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("csr is required", nil))
		return
	}
	if req.AttestationType == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("attestation_type is required", nil))
		return
	}
	resp, err := ctrl.service.Attest(c.Request.Context(), &services.AttestRequest{
		CSR:             req.CSR,
		AttestationType: req.AttestationType,
		Selectors:       req.Selectors,
		IPAddress:       c.ClientIP(),
		UserAgent:       c.Request.UserAgent(),
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, dto.AttestResponse{
		Certificate:  resp.Certificate,
		CAChain:      resp.CAChain,
		SpiffeID:     resp.SpiffeID,
		ExpiresAt:    resp.ExpiresAt,
		WorkloadID:   resp.WorkloadID,
		SerialNumber: resp.SerialNumber,
	})
}
