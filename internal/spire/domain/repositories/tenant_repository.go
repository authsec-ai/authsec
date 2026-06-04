package repositories

import (
	"context"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
)

// WorkspaceRepository defines the interface for tenant data operations
type WorkspaceRepository interface {
	GetByID(ctx context.Context, id string) (*models.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*models.Tenant, error)
	Create(ctx context.Context, tenant *models.Tenant) error
	Update(ctx context.Context, tenant *models.Tenant) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*models.Tenant, error)
}
