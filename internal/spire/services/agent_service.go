package services

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
)

// AgentService lists the agents of the workspace carried by ctx.
type AgentService struct {
	agentRepo repositories.AgentRepository
	logger    *logrus.Entry
}

// NewAgentService creates the agent service.
func NewAgentService(agentRepo repositories.AgentRepository, logger *logrus.Entry) *AgentService {
	return &AgentService{agentRepo: agentRepo, logger: logger}
}

// ListAgents lists the active agents of ctx's workspace.
func (s *AgentService) ListAgents(ctx context.Context) ([]*models.Agent, error) {
	agents, err := s.agentRepo.List(ctx)
	if err != nil {
		return nil, errors.NewInternalError("Failed to list agents", err)
	}
	active := make([]*models.Agent, 0, len(agents))
	for _, a := range agents {
		if a.Status == models.AgentStatusActive {
			active = append(active, a)
		}
	}
	return active, nil
}
