package controllers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// NodeAttestationController handles node attestation requests
type NodeAttestationController struct {
	service *services.NodeAttestationService
	logger  *logrus.Entry
}

// NewNodeAttestationController creates a new node attestation controller
func NewNodeAttestationController(service *services.NodeAttestationService, logger *logrus.Entry) *NodeAttestationController {
	return &NodeAttestationController{service: service, logger: logger}
}

// Attest handles POST /spiresvc/v1/node/attest. The caller is anonymous
// until its join token (body join_token, or Authorization: Bearer) is
// consumed; the token decides the workspace.
func (ctrl *NodeAttestationController) Attest(c *gin.Context) {
	var req dto.NodeAttestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if req.JoinToken == "" {
		if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
			req.JoinToken = strings.TrimPrefix(h, "Bearer ")
		}
	}
	switch {
	case req.JoinToken == "":
		sendError(c, ctrl.logger, errors.NewUnauthorizedError("join_token is required", nil))
		return
	case req.NodeID == "":
		sendError(c, ctrl.logger, errors.NewBadRequestError("node_id is required", nil))
		return
	case req.CSR == "":
		sendError(c, ctrl.logger, errors.NewBadRequestError("csr is required", nil))
		return
	case req.AttestationType == "":
		sendError(c, ctrl.logger, errors.NewBadRequestError("attestation_type is required", nil))
		return
	}

	resp, err := ctrl.service.Attest(c.Request.Context(), &services.NodeAttestRequest{
		JoinToken:           req.JoinToken,
		AssertedWorkspaceID: req.WorkspaceID,
		NodeID:              req.NodeID,
		AttestationType:     req.AttestationType,
		Evidence:            req.Evidence,
		CSR:                 req.CSR,
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}

	ttl := int(time.Until(resp.ExpiresAt).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	c.JSON(http.StatusOK, dto.NodeAttestResponse{
		AgentID:     resp.AgentID,
		SpiffeID:    resp.SpiffeID,
		WorkspaceID: resp.WorkspaceID,
		Certificate: resp.Certificate,
		CABundle:    strings.Join(resp.CAChain, "\n"),
		TTL:         ttl,
	})
}

// JoinTokenController mints, lists and revokes join tokens of the caller's
// workspace (AuthMiddleware + owner/admin).
type JoinTokenController struct {
	service *services.JoinTokenService
	logger  *logrus.Entry
}

// NewJoinTokenController creates the join token controller.
func NewJoinTokenController(service *services.JoinTokenService, logger *logrus.Entry) *JoinTokenController {
	return &JoinTokenController{service: service, logger: logger}
}

// Create handles POST /spiresvc/v1/join-tokens. The secret is in this
// response only.
func (ctrl *JoinTokenController) Create(c *gin.Context) {
	var req dto.CreateJoinTokenRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
			return
		}
	}
	if req.TTLSeconds < 0 {
		sendError(c, ctrl.logger, errors.NewBadRequestError("ttl_seconds must be positive", nil))
		return
	}
	createdBy := ""
	if tc, err := tenancy.From(c); err == nil {
		createdBy = tc.PrincipalID.String()
	}
	t, secret, err := ctrl.service.Mint(c.Request.Context(), req.Description, createdBy, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, dto.JoinTokenResponse{
		ID: t.ID, Token: secret, Description: t.Description, ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt,
	})
}

// List handles GET /spiresvc/v1/join-tokens (no secrets, no hashes).
func (ctrl *JoinTokenController) List(c *gin.Context) {
	tokens, err := ctrl.service.List(c.Request.Context())
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	out := make([]dto.JoinTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, dto.JoinTokenResponse{
			ID: t.ID, Description: t.Description, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt,
			UsedByNodeID: t.UsedByNodeID, RevokedAt: t.RevokedAt, CreatedAt: t.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"join_tokens": out, "count": len(out)})
}

// Revoke handles DELETE /spiresvc/v1/join-tokens/:id. Another workspace's
// token is 404.
func (ctrl *JoinTokenController) Revoke(c *gin.Context) {
	if err := ctrl.service.Revoke(c.Request.Context(), c.Param("id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Join token revoked", "id": c.Param("id")})
}
