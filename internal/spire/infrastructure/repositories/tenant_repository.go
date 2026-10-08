package repositories

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
)

// PostgresWorkspaceRepository reads the workspace registry (workspaces).
// workspaces is the tenant table itself, not tenant-owned data: each
// statement selects one workspace by its own id or domain, which the caller
// took from a verified credential (a token's claim, a certificate's trust
// domain, a join token's row) or from the authenticated request.
type PostgresWorkspaceRepository struct {
	db *sql.DB
}

// NewPostgresWorkspaceRepository creates the workspace registry reader.
func NewPostgresWorkspaceRepository(db *sql.DB) repositories.WorkspaceRepository {
	return &PostgresWorkspaceRepository{db: db}
}

func (r *PostgresWorkspaceRepository) get(ctx context.Context, query string, arg interface{}) (*models.Tenant, error) {
	t := &models.Tenant{}
	// TENANT-EXEMPT: workspace registry row selected by its own id or domain (see type comment).
	err := r.db.QueryRowContext(ctx, query, arg).Scan(&t.ID, &t.Name, &t.VaultMount, &t.Domain, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.NewNotFoundError("Workspace not found", err)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get workspace", err)
	}
	return t, nil
}

// GetByID returns the active workspace with this id.
func (r *PostgresWorkspaceRepository) GetByID(ctx context.Context, id string) (*models.Tenant, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, errors.NewNotFoundError("Workspace not found", nil)
	}
	// TENANT-EXEMPT: workspace registry row selected by its own id.
	return r.get(ctx, `SELECT id::text, COALESCE(name, ''), COALESCE(vault_mount, ''), COALESCE(workspace_domain, ''), COALESCE(status, ''), created_at, updated_at
		FROM workspaces WHERE id = $1::uuid AND status = 'active'`, id)
}

// GetByDomain returns the active workspace with this domain.
func (r *PostgresWorkspaceRepository) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	if domain == "" {
		return nil, errors.NewNotFoundError("Workspace not found", nil)
	}
	// TENANT-EXEMPT: workspace registry row selected by its own domain.
	return r.get(ctx, `SELECT id::text, COALESCE(name, ''), COALESCE(vault_mount, ''), COALESCE(workspace_domain, ''), COALESCE(status, ''), created_at, updated_at
		FROM workspaces WHERE lower(workspace_domain) = lower($1) AND status = 'active'`, domain)
}

// GetByTrustDomain maps a SPIFFE trust domain to an active workspace: the
// embedded control plane names a workspace's trust domain by its id
// (spiffe://<workspace_id>/...); a workspace domain is accepted too.
func (r *PostgresWorkspaceRepository) GetByTrustDomain(ctx context.Context, trustDomain string) (*models.Tenant, error) {
	if _, err := uuid.Parse(trustDomain); err == nil {
		return r.GetByID(ctx, trustDomain)
	}
	return r.GetByDomain(ctx, trustDomain)
}

// UpdateVaultMount records the workspace's PKI mount.
func (r *PostgresWorkspaceRepository) UpdateVaultMount(ctx context.Context, id, vaultMount string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.NewNotFoundError("Workspace not found", nil)
	}
	// TENANT-EXEMPT: writes the workspace registry row itself, selected by its own id.
	res, err := r.db.ExecContext(ctx, `UPDATE workspaces SET vault_mount = $2, updated_at = now() WHERE id = $1::uuid`, id, vaultMount)
	if err != nil {
		return errors.NewInternalError("Failed to update workspace", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Workspace not found", nil)
	}
	return nil
}
