package repositories

import (
	"context"
	"time"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
)

// CertificateRepository defines the interface for certificate data operations
type CertificateRepository interface {
	GetByID(ctx context.Context, workspaceID, id string) (*models.Certificate, error)
	GetBySerialNumber(ctx context.Context, workspaceID, serialNumber string) (*models.Certificate, error)
	GetActiveByWorkload(ctx context.Context, workspaceID, workloadID string) (*models.Certificate, error)
	Create(ctx context.Context, cert *models.Certificate) error
	Update(ctx context.Context, cert *models.Certificate) error
	Revoke(ctx context.Context, workspaceID, id string) error
	ListByWorkload(ctx context.Context, workspaceID, workloadID string) ([]*models.Certificate, error)
	ListExpiring(ctx context.Context, workspaceID string, within time.Duration) ([]*models.Certificate, error)
}
