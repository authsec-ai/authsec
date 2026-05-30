package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// TenantRepository handles workspace identity database operations.
//
// Phase 6 collapse: the `tenants` table has been dropped. All queries here
// now target the `workspaces` table (which absorbed the legacy identity
// columns email/password_hash/provider/workspace_domain/status/source/vault_mount/ca_cert).
// The repository type name is retained for source-compatibility with existing
// callers; rename to WorkspaceRepository is tracked as Phase 9/10 cosmetic.
type TenantRepository struct {
	db *DBConnection
}

// NewTenantRepository creates a new workspace identity repository.
func NewTenantRepository(db *DBConnection) *TenantRepository {
	return &TenantRepository{db: db}
}

// scanWorkspaceRow scans a workspaces row into a models.Tenant. Columns absent
// from the workspaces schema (username, provider_id, avatar, last_login, tenant_db)
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
		t.TenantDomain = domainHolder.String
	}
	return nil
}

const workspaceSelectCols = `id, COALESCE(email, ''), COALESCE(password_hash, ''), provider, COALESCE(name, ''), source, status, created_at, updated_at, workspace_domain`

// CreateTenant inserts a workspace identity row.
func (tr *TenantRepository) CreateTenant(t *models.Tenant) error {
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
		t.ID, t.Name, t.Email, t.PasswordHash, t.Provider, t.Source, t.Status, t.TenantDomain, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// GetTenantByEmail retrieves a workspace identity by email (case-insensitive).
func (tr *TenantRepository) GetTenantByEmail(email string) (*models.Tenant, error) {
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

// GetTenantByTenantID retrieves a workspace by its ID (workspace_id == id).
func (tr *TenantRepository) GetTenantByTenantID(workspaceID string) (*models.Tenant, error) {
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

// UpdateTenantDB is a no-op under the single-DB collapse (workspaces has no tenant_db column).
func (tr *TenantRepository) UpdateTenantDB(workspaceID uuid.UUID, dbName string) error {
	return nil
}

// UpdateTenantLogin is a no-op under the workspaces schema (no last_login column on workspaces yet).
// If last-login tracking is needed it should live on admin_users or a sessions row.
func (tr *TenantRepository) UpdateTenantLogin(workspaceID uuid.UUID) error {
	_, err := tr.db.Exec(`UPDATE workspaces SET updated_at = $1 WHERE id = $2`, time.Now(), workspaceID)
	return err
}

// TenantExists checks whether a workspace identity exists for the given email.
func (tr *TenantRepository) TenantExists(email string) (bool, error) {
	if tr.db == nil || tr.db.DB == nil {
		return false, fmt.Errorf("database connection is not initialized")
	}
	if err := tr.db.DB.Ping(); err != nil {
		return false, fmt.Errorf("database connection failed: %w", err)
	}
	query := `SELECT EXISTS(SELECT 1 FROM workspaces WHERE LOWER(email) = LOWER($1))`
	var exists bool
	err := tr.db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check workspace existence: %w", err)
	}
	return exists, nil
}

// TenantExistsByTenantID checks whether a workspace exists with the given ID.
func (tr *TenantRepository) TenantExistsByTenantID(workspaceID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1)`
	var exists bool
	err := tr.db.QueryRow(query, workspaceID).Scan(&exists)
	return exists, err
}

// CreateTenantTx inserts a workspace identity row within a transaction.
func (tr *TenantRepository) CreateTenantTx(tx *sql.Tx, t *models.Tenant) error {
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
	_, err := tx.Exec(query,
		t.ID, t.Name, t.Email, t.PasswordHash, t.Provider, t.Source, t.Status, t.TenantDomain, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// UpdateTenantDBTx is a no-op under the single-DB collapse.
func (tr *TenantRepository) UpdateTenantDBTx(tx *sql.Tx, workspaceID uuid.UUID, dbName string) error {
	return nil
}

// GetAllTenants retrieves every workspace identity row.
func (tr *TenantRepository) GetAllTenants() ([]*models.Tenant, error) {
	query := `SELECT ` + workspaceSelectCols + ` FROM workspaces ORDER BY created_at DESC`
	rows, err := tr.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query workspaces: %w", err)
	}
	defer rows.Close()

	var out []*models.Tenant
	for rows.Next() {
		t := &models.Tenant{}
		if err := scanWorkspaceRow(rows, t); err != nil {
			return nil, fmt.Errorf("failed to scan workspace row: %w", err)
		}
		out = append(out, t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating workspace rows: %w", err)
	}
	return out, nil
}

// UpdateTenantStatusTx updates a workspace's status within a transaction.
func (tr *TenantRepository) UpdateTenantStatusTx(tx *sql.Tx, workspaceID uuid.UUID, status string) error {
	query := `UPDATE workspaces SET status = $1, updated_at = $2 WHERE id = $3`
	result, err := tx.Exec(query, status, time.Now(), workspaceID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("workspace not found")
	}
	return nil
}

// DeleteTenant permanently deletes a workspace and all related scoped rows.
func (tr *TenantRepository) DeleteTenant(workspaceID uuid.UUID) (map[string]int64, error) {
	deletedCounts := make(map[string]int64)

	tx, err := tr.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	execDelete := func(table, query string, args ...interface{}) error {
		result, err := tx.Exec(query, args...)
		if err != nil {
			return fmt.Errorf("failed to delete from %s: %w", table, err)
		}
		if rows, err := result.RowsAffected(); err == nil {
			deletedCounts[table] = rows
		}
		return nil
	}

	if err := execDelete("role_bindings", "DELETE FROM role_bindings WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("role_permissions", "DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE workspace_id = $1)", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("roles", "DELETE FROM roles WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("permissions", "DELETE FROM permissions WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("oauth_scopes", "DELETE FROM oauth_scopes WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("totp_secrets", "DELETE FROM totp_secrets WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("user_groups", "DELETE FROM user_groups WHERE user_id IN (SELECT id FROM users WHERE workspace_id = $1)", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("users", "DELETE FROM users WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("workspace_memberships", "DELETE FROM workspace_memberships WHERE workspace_id = $1", workspaceID); err != nil {
		return nil, err
	}
	if err := execDelete("workspaces", "DELETE FROM workspaces WHERE id = $1", workspaceID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return deletedCounts, nil
}
