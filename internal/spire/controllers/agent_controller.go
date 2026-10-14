package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/middleware"
	"github.com/authsec-ai/authsec/internal/spire/services"
)

// AgentController handles agent operations including listing and renewal
type AgentController struct {
	agentService   *services.AgentService
	renewalService *services.AgentRenewalService
	logger         *logrus.Entry
}

// NewAgentController creates a new agent controller
func NewAgentController(agentService *services.AgentService, renewalService *services.AgentRenewalService, logger *logrus.Entry) *AgentController {
	return &AgentController{agentService: agentService, renewalService: renewalService, logger: logger}
}

// ListAgents handles GET /spiresvc/v1/agents: the active agents of the
// caller's workspace (AuthMiddleware).
func (ctrl *AgentController) ListAgents(c *gin.Context) {
	agents, err := ctrl.agentService.ListAgents(c.Request.Context())
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	out := make([]*dto.AgentResponse, len(agents))
	for i, a := range agents {
		out[i] = &dto.AgentResponse{
			ID:              a.ID,
			SpiffeID:        a.SpiffeID,
			NodeID:          a.NodeID,
			AttestationType: a.AttestationType,
			Status:          a.Status,
			LastSeen:        a.LastSeen,
			CreatedAt:       a.CreatedAt,
		}
	}
	c.JSON(http.StatusOK, dto.ListAgentsResponse{Agents: out, Count: len(out)})
}

// RenewAgent handles POST /spiresvc/v1/agent/renew. The agent is the one
// whose certificate authenticated the request (agent certificate
// middleware); a body agent_id naming another agent is 404.
func (ctrl *AgentController) RenewAgent(c *gin.Context) {
	var req dto.AgentRenewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	agentID, ok := middleware.GetSpireAgentID(c)
	if !ok {
		sendError(c, ctrl.logger, errors.NewUnauthorizedError("Agent certificate required", nil))
		return
	}
	if req.AgentID != "" && req.AgentID != agentID {
		sendError(c, ctrl.logger, errors.NewNotFoundError("Agent not found", nil))
		return
	}
	if req.CSR == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("csr is required", nil))
		return
	}
	resp, err := ctrl.renewalService.Renew(c.Request.Context(), &services.AgentRenewRequest{AgentID: agentID, CSR: req.CSR})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, dto.AgentRenewResponse{
		SpiffeID:    resp.SpiffeID,
		Certificate: resp.Certificate,
		CABundle:    resp.CABundle,
		TTL:         resp.TTL,
		CAChain:     resp.CAChain,
		ExpiresAt:   resp.ExpiresAt,
	})
}
