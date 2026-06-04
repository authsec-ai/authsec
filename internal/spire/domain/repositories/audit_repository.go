package repositories

import (
	"context"
	"time"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
)

// AuditRepository defines the interface for audit log operations
type AuditRepository interface {
	Create(ctx context.Context, log *models.AuditLog) error
	List(ctx context.Context, workspaceID string, limit, offset int) ([]*models.AuditLog, error)
	ListByWorkload(ctx context.Context, workspaceID, workloadID string, limit, offset int) ([]*models.AuditLog, error)
	ListByEventType(ctx context.Context, workspaceID string, eventType models.AuditEventType, limit, offset int) ([]*models.AuditLog, error)
	ListByDateRange(ctx context.Context, workspaceID string, from, to time.Time, limit, offset int) ([]*models.AuditLog, error)
}
