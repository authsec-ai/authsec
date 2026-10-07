package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// WorkspaceRepository handles workspace identity database operations.
//
// Phase 6 collapse: the `tenants` table has been dropped. All queries here
// now target the `workspaces` table (which absorbed the legacy identity
// columns email/password_hash/provider/workspace_domain/status/source/vault_mount/ca_cert).
// The repository type name is retained for source-compatibility with existing
// callers; rename to WorkspaceRepository is tracked as Phase 9/10 cosmetic.
type WorkspaceRepository struct {
	db *DBConnection
}

// NewWorkspaceRepository creates a new workspace identity repository.
func NewWorkspaceRepository(db *DBConnection) *WorkspaceRepository {
	return &WorkspaceRepository{db: db}
}

// scanWorkspaceRow scans a workspaces row into a models.Tenant. Columns absent
// from the workspaces schema (username, provider_id, avatar, last_login, workspace_db)
// are left as zero-value on the struct.
func scanWorkspaceRow(row interface {
	Scan(dest ...interface{}) error
}, t *models.Tenant) error {
	var providerHolder sql.NullString
	var sourceHolder, statusHolder sql.NullString
	var domainHolder sql.NullString
	err := row.Scan(
		&t.ID,
		&t.Email,
		&t.PasswordHash,
		&providerHolder,
		&t.Name,
		&sourceHolder,
		&statusHolder,
		&t.CreatedAt,
		&t.UpdatedAt,
		&domainHolder,
	)
	if err != nil {
		return err
	}
	// workspace_id mirrors id (post-collapse, the workspace's own UUID IS the scope ID).
	t.WorkspaceID = t.ID
	if providerHolder.Valid {
		t.Provider = providerHolder.String
	}
	if sourceHolder.Valid {
		t.Source = sourceHolder.String
	}
	if statusHolder.Valid {
		t.Status = statusHolder.String
	}
	if domainHolder.Valid {
		t.WorkspaceDomain = domainHolder.String
	}
	return nil
}

const workspaceSelectCols = `id, COALESCE(email, ''), COALESCE(password_hash, ''), provider, COALESCE(name, ''), source, status, created_at, updated_at, workspace_domain`
const workspaceSelectColsFromAlias = `w.id, COALESCE(w.email, ''), COALESCE(w.password_hash, ''), w.provider, COALESCE(w.name, ''), w.source, w.status, w.created_at, w.updated_at, w.workspace_domain`

// CreateTenant inserts a workspace identity row.
func (tr *WorkspaceRepository) CreateTenant(t *models.Tenant) error {
	// TENANT-EXEMPT: workspaces is the tenant registry itself (no
	// workspace_id column); this creates a new tenant at sign-up.
	query := `
		INSERT INTO workspaces (id, name, email, password_hash, provider, source, status, workspace_domain, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	now := time.Now()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}
	_, err := tr.db.Exec(query,
		t.ID, t.Name, t.Email, t.PasswordHash, t.Provider, t.Source, t.Status, t.WorkspaceDomain, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// GetWorkspaceByEmail retrieves a workspace identity by email (case-insensitive).
func (tr *WorkspaceRepository) GetWorkspaceByEmail(email string) (*models.Tenant, error) {
	// TENANT-EXEMPT: pre-auth registry lookup (sign-up / sign-in by email).
	query := `SELECT ` + workspaceSelectCols + ` FROM workspaces WHERE LOWER(email) = LOWER($1)`
	t := &models.Tenant{}
	err := scanWorkspaceRow(tr.db.QueryRow(query, email), t)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workspace not found")
		}
		return nil, err
	}
	return t, nil
}

// GetWorkspaceByWorkspaceID retrieves a workspace by its ID (workspace_id == id).
func (tr *WorkspaceRepository) GetWorkspaceByWorkspaceID(workspaceID string) (*models.Tenant, error) {
	// TENANT-EXEMPT: registry row of a workspace the caller already resolved.
	query := `SELECT ` + workspaceSelectCols + ` FROM workspaces WHERE id = $1`
	t := &models.Tenant{}
	err := scanWorkspaceRow(tr.db.QueryRow(query, workspaceID), t)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workspace not found")
		}
		return nil, err
	}
	return t, nil
}

// TenantExists checks whether a workspace identity exists for the given email.
func (tr *WorkspaceRepository) TenantExists(email string) (bool, error) {
	if tr.db == nil || tr.db.DB == nil {
		return false, fmt.Errorf("database connection is not initialized")
	}
	if err := tr.db.DB.Ping(); err != nil {
		return false, fmt.Errorf("database connection failed: %w", err)
	}
	// TENANT-EXEMPT: pre-auth sign-up check across the tenant registry.
	query := `SELECT EXISTS(SELECT 1 FROM workspaces WHERE LOWER(email) = LOWER($1))`
	var exists bool
	err := tr.db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check workspace existence: %w", err)
	}
	return exists, nil
}

// DeleteTenant permanently deletes the workspace carried by ctx and its
// scoped rows, under row-level security for that workspace.
func (tr *WorkspaceRepository) DeleteTenant(ctx context.Context) (map[string]int64, error) {
	workspaceID, err := ctxWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	deletedCounts := make(map[string]int64)
	// deleted records the rows one scoped statement removed from table.
	deleted := func(table string) func(sql.Result, error) error {
		return func(result sql.Result, err error) error {
			if err != nil {
				return fmt.Errorf("failed to delete from %s: %w", table, err)
			}
			if rows, err := result.RowsAffected(); err == nil {
				deletedCounts[table] = rows
			}
			return nil
		}
	}
	err = tenancy.WithTx(ctx, tr.db.DB, workspaceID, func(tx *sql.Tx) error {
		// Memberships reference roles and users: they go first.
		if err := deleted("workspace_memberships")(tenancy.ExecContext(ctx, tx, "DELETE FROM workspace_memberships WHERE workspace_id = $1")); err != nil {
			return err
		}
		if err := deleted("role_bindings")(tenancy.ExecContext(ctx, tx, "DELETE FROM role_bindings WHERE workspace_id = $1")); err != nil {
			return err
		}
		if err := deleted("role_permissions")(tenancy.ExecContext(ctx, tx, "DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE workspace_id = $1)")); err != nil {
			return err
		}
		if err := deleted("roles")(tenancy.ExecContext(ctx, tx, "DELETE FROM roles WHERE workspace_id = $1")); err != nil {
			return err
		}
		if err := deleted("permissions")(tenancy.ExecContext(ctx, tx, "DELETE FROM permissions WHERE workspace_id = $1")); err != nil {
			return err
		}
		if err := deleted("oauth_scopes")(tenancy.ExecContext(ctx, tx, "DELETE FROM oauth_scopes WHERE workspace_id = $1")); err != nil {
			return err
		}
		if err := deleted("totp_secrets")(tenancy.ExecContext(ctx, tx, "DELETE FROM totp_secrets WHERE workspace_id = $1")); err != nil {
			return err
		}
		if err := deleted("user_groups")(tenancy.ExecContext(ctx, tx, "DELETE FROM user_groups WHERE user_id IN (SELECT id FROM users WHERE workspace_id = $1)")); err != nil {
			return err
		}
		if err := deleted("users")(tenancy.ExecContext(ctx, tx, "DELETE FROM users WHERE workspace_id = $1")); err != nil {
			return err
		}
		// TENANT-EXEMPT: workspaces is the tenant registry (no workspace_id
		// column); this removes the registry row of the scoped workspace.
		result, err := tx.ExecContext(ctx, `DELETE FROM workspaces WHERE id = $1`, workspaceID)
		if err != nil {
			return fmt.Errorf("failed to delete from workspaces: %w", err)
		}
		if rows, err := result.RowsAffected(); err == nil {
			deletedCounts["workspaces"] = rows
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return deletedCounts, nil
}
