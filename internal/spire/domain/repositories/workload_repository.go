package repositories

import (
	"context"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
)

// WorkloadRepository defines the interface for workload data operations
type WorkloadRepository interface {
	GetByID(ctx context.Context, workspaceID, id string) (*models.Workload, error)
	GetBySpiffeID(ctx context.Context, workspaceID, spiffeID string) (*models.Workload, error)
	Create(ctx context.Context, workload *models.Workload) error
	Update(ctx context.Context, workload *models.Workload) error
	Delete(ctx context.Context, workspaceID, id string) error
	ListByTenant(ctx context.Context, workspaceID string) ([]*models.Workload, error)
	FindBySelectors(ctx context.Context, workspaceID string, selectors map[string]string) ([]*models.Workload, error)
}
