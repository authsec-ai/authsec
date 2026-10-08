package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresWorkloadRepository stores directly attested workloads
// (spire_attested_workloads) of the workspace carried by ctx.
type PostgresWorkloadRepository struct {
	db *sql.DB
}

// NewPostgresWorkloadRepository creates the attested workload repository.
func NewPostgresWorkloadRepository(db *sql.DB) repositories.WorkloadRepository {
	return &PostgresWorkloadRepository{db: db}
}

const workloadColumns = `id::text, workspace_id::text, spiffe_id, selectors, vault_role, status, attestation_type, created_at, updated_at`

// GetByID returns the workload with this id in ctx's workspace.
func (r *PostgresWorkloadRepository) GetByID(ctx context.Context, id string) (*models.Workload, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, errors.NewNotFoundError("Workload not found", nil)
	}
	return r.getOne(ctx, `SELECT `+workloadColumns+` FROM spire_attested_workloads WHERE workspace_id = $1 AND id = $2`, id)
}

// GetBySpiffeID returns the workload with this SPIFFE ID in ctx's workspace.
func (r *PostgresWorkloadRepository) GetBySpiffeID(ctx context.Context, spiffeID string) (*models.Workload, error) {
	return r.getOne(ctx, `SELECT `+workloadColumns+` FROM spire_attested_workloads WHERE workspace_id = $1 AND spiffe_id = $2`, spiffeID)
}

func (r *PostgresWorkloadRepository) getOne(ctx context.Context, query string, arg interface{}) (*models.Workload, error) {
	w := &models.Workload{}
	var selectors []byte
	err := tenancy.QueryRowContext(ctx, r.db, query, []interface{}{arg},
		&w.ID, &w.WorkspaceID, &w.SpiffeID, &selectors, &w.VaultRole, &w.Status,
		&w.AttestationType, &w.CreatedAt, &w.UpdatedAt)
	if stderrors.Is(err, tenancy.ErrNotFound) {
		return nil, errors.NewNotFoundError("Workload not found", err)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get workload", err)
	}
	if len(selectors) > 0 {
		if err := json.Unmarshal(selectors, &w.Selectors); err != nil {
			return nil, errors.NewInternalError("Failed to parse selectors", err)
		}
	}
	return w, nil
}

// Create inserts a workload for ctx's workspace.
func (r *PostgresWorkloadRepository) Create(ctx context.Context, w *models.Workload) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if w.ID == "" {
		w.ID = uuid.NewString()
	}
	w.WorkspaceID = ws.String()
	now := time.Now()
	w.CreatedAt, w.UpdatedAt = now, now
	selectors, err := json.Marshal(nonNilMap(w.Selectors))
	if err != nil {
		return errors.NewInternalError("Failed to marshal selectors", err)
	}
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_attested_workloads (
			workspace_id, id, spiffe_id, selectors, vault_role, status, attestation_type, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		w.ID, w.SpiffeID, selectors, w.VaultRole, w.Status, w.AttestationType, w.CreatedAt, w.UpdatedAt)
	if err != nil {
		return errors.NewInternalError("Failed to create workload", err)
	}
	return nil
}
