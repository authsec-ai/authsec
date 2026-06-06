package repositories

import (
	"context"
	"database/sql"
	"time"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
)

// PostgresWorkspaceRepository implements the WorkspaceRepository interface
// using the `workspaces` table (the canonical workspace identity table).
type PostgresWorkspaceRepository struct {
	db *sql.DB
}

func NewPostgresWorkspaceRepository(db *sql.DB) repositories.WorkspaceRepository {
	return &PostgresWorkspaceRepository{db: db}
}

func (r *PostgresWorkspaceRepository) GetByID(ctx context.Context, id string) (*models.Tenant, error) {
	query := `
		SELECT
			id::text,
			name,
			COALESCE(vault_mount, workspace_domain) as vault_mount,
			status,
			created_at,
			updated_at
		FROM workspaces
		WHERE id = $1::uuid AND status = 'active'
	`

	tenant := &models.Tenant{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.VaultMount,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NewNotFoundError("Workspace not found", err)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get workspace", err)
	}

	return tenant, nil
}

func (r *PostgresWorkspaceRepository) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	query := `
		SELECT
			id::text,
			name,
			COALESCE(vault_mount, workspace_domain) as vault_mount,
			status,
			created_at,
			updated_at
		FROM workspaces
		WHERE workspace_domain = $1 AND status = 'active'
	`

	tenant := &models.Tenant{}
	err := r.db.QueryRowContext(ctx, query, domain).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.VaultMount,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NewNotFoundError("Workspace not found", err)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get workspace", err)
	}

	return tenant, nil
}

func (r *PostgresWorkspaceRepository) Create(ctx context.Context, tenant *models.Tenant) error {
	query := `
		INSERT INTO workspaces (id, name, vault_mount, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now
	if tenant.Status == "" {
		tenant.Status = "active"
	}

	_, err := r.db.ExecContext(ctx, query,
		tenant.ID, tenant.Name, tenant.VaultMount, tenant.Status,
		tenant.CreatedAt, tenant.UpdatedAt,
	)
	if err != nil {
		return errors.NewInternalError("Failed to create workspace", err)
	}
	return nil
}

func (r *PostgresWorkspaceRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	query := `
		UPDATE workspaces
		SET name = $2, vault_mount = $3, status = $4, updated_at = $5
		WHERE id = $1
	`

	tenant.UpdatedAt = time.Now()

	result, err := r.db.ExecContext(ctx, query,
		tenant.ID, tenant.Name, tenant.VaultMount, tenant.Status, tenant.UpdatedAt,
	)
	if err != nil {
		return errors.NewInternalError("Failed to update workspace", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.NewInternalError("Failed to get affected rows", err)
	}
	if rows == 0 {
		return errors.NewNotFoundError("Workspace not found", nil)
	}
	return nil
}

func (r *PostgresWorkspaceRepository) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE workspaces
		SET status = 'deleted', updated_at = $2
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return errors.NewInternalError("Failed to delete workspace", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.NewInternalError("Failed to get affected rows", err)
	}
	if rows == 0 {
		return errors.NewNotFoundError("Workspace not found", nil)
	}
	return nil
}

func (r *PostgresWorkspaceRepository) List(ctx context.Context) ([]*models.Tenant, error) {
	query := `
		SELECT id, name, vault_mount, status, created_at, updated_at
		FROM workspaces
		WHERE status = 'active'
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewInternalError("Failed to list workspaces", err)
	}
	defer rows.Close()

	var tenants []*models.Tenant
	for rows.Next() {
		tenant := &models.Tenant{}
		err := rows.Scan(
			&tenant.ID, &tenant.Name, &tenant.VaultMount,
			&tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt,
		)
		if err != nil {
			return nil, errors.NewInternalError("Failed to scan workspace", err)
		}
		tenants = append(tenants, tenant)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.NewInternalError("Error iterating workspaces", err)
	}

	return tenants, nil
}
