package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AdminSeedRepository handles per-tenant admin role/scopes/permissions seeding.
type AdminSeedRepository struct {
	db *DBConnection
}

type sqlExecutor interface {
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

func NewAdminSeedRepository(db *DBConnection) *AdminSeedRepository {
	return &AdminSeedRepository{db: db}
}

// EnsureAdminRoleAndPermissions creates admin role, default scopes, and permissions for a tenant and returns the role ID.
func (asr *AdminSeedRepository) EnsureAdminRoleAndPermissions(tenantID uuid.UUID) (uuid.UUID, error) {
	return asr.ensureAdminRoleAndPermissions(asr.db.DB, tenantID)
}

// EnsureAdminRoleAndPermissionsTx performs the same operation using an existing transaction.
func (asr *AdminSeedRepository) EnsureAdminRoleAndPermissionsTx(tx *sql.Tx, tenantID uuid.UUID) (uuid.UUID, error) {
	return asr.ensureAdminRoleAndPermissions(tx, tenantID)
}

func (asr *AdminSeedRepository) ensureAdminRoleAndPermissions(exec sqlExecutor, tenantID uuid.UUID) (uuid.UUID, error) {
	if asr == nil || asr.db == nil {
		return uuid.Nil, fmt.Errorf("admin seed repository not initialized")
	}
	if exec == nil {
		return uuid.Nil, fmt.Errorf("executor is nil")
	}

	now := time.Now()

	// Ensure admin role - use index name for ON CONFLICT (different DBs may have different constraint names)
	roleID := uuid.New()
	if err := exec.QueryRow(`
		INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at)
		VALUES ($1, $2, 'admin', 'Administrator with full access', $3, $3)
		ON CONFLICT (tenant_id, name) DO UPDATE SET updated_at = EXCLUDED.updated_at
		RETURNING id
	`, roleID, tenantID, now).Scan(&roleID); err != nil {
		return uuid.Nil, fmt.Errorf("ensure admin role: %w", err)
	}

	return roleID, nil
}
