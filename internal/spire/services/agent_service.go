package services

import (
	"context"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/database"
	infrarepos "github.com/authsec-ai/authsec/internal/spire/infrastructure/repositories"

	"github.com/sirupsen/logrus"
)

// AgentService handles agent operations
type AgentService struct {
	connManager *database.ConnectionManager
	workspaceRepo  repositories.WorkspaceRepository
	logger      *logrus.Entry
}

// NewAgentService creates a new agent service
func NewAgentService(
	connManager *database.ConnectionManager,
	workspaceRepo repositories.WorkspaceRepository,
	logger *logrus.Entry,
) *AgentService {
	return &AgentService{
		connManager: connManager,
		workspaceRepo:  workspaceRepo,
		logger:      logger,
	}
}

// ListAgentsByTenant lists all active agents for a tenant
func (s *AgentService) ListAgentsByTenant(ctx context.Context, workspaceID string) ([]*models.Agent, error) {
	s.logger.WithField("workspace_id", workspaceID).Info("Listing agents for tenant")

	// Get tenant-specific database connection
	db, err := s.connManager.GetWorkspaceDB(ctx, workspaceID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get tenant database connection")
		return nil, errors.NewNotFoundError("Tenant not found", err)
	}

	// Create agent repository
	agentRepo := infrarepos.NewPostgresAgentRepository(db, s.logger)

	// List all agents for the tenant
	agents, err := agentRepo.ListByTenant(ctx, workspaceID)
	if err != nil {
		s.logger.WithFields(logrus.Fields{"workspace_id": workspaceID}).WithError(err).Error("Failed to list agents")
		return nil, errors.NewInternalError("Failed to list agents", err)
	}

	// Filter to only active agents
	activeAgents := make([]*models.Agent, 0, len(agents))
	for _, agent := range agents {
		if agent.Status == models.AgentStatusActive {
			activeAgents = append(activeAgents, agent)
		}
	}

	s.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "count": len(activeAgents)}).Info("Successfully listed agents")

	return activeAgents, nil
}
