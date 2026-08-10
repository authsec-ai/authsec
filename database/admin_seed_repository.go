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
func (asr *AdminSeedRepository) EnsureAdminRoleAndPermissions(workspaceID uuid.UUID) (uuid.UUID, error) {
	return asr.ensureAdminRoleAndPermissions(asr.db.DB, workspaceID)
}

// EnsureAdminRoleAndPermissionsTx performs the same operation using an existing transaction.
func (asr *AdminSeedRepository) EnsureAdminRoleAndPermissionsTx(tx *sql.Tx, workspaceID uuid.UUID) (uuid.UUID, error) {
	return asr.ensureAdminRoleAndPermissions(tx, workspaceID)
}

func (asr *AdminSeedRepository) ensureAdminRoleAndPermissions(exec sqlExecutor, workspaceID uuid.UUID) (uuid.UUID, error) {
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
		INSERT INTO roles (id, workspace_id, name, description, created_at, updated_at)
		VALUES ($1, $2, 'admin', 'Administrator with full access', $3, $3)
		ON CONFLICT (workspace_id, name) DO UPDATE SET updated_at = EXCLUDED.updated_at
		RETURNING id
	`, roleID, workspaceID, now).Scan(&roleID); err != nil {
		return uuid.Nil, fmt.Errorf("ensure admin role: %w", err)
	}

	// Bind the admin role to every globally-seeded permission (workspace_id
	// IS NULL). Permissions are defined once in the global catalog; a
	// workspace's admin role only has access to what it's explicitly bound
	// to via role_permissions — there is no RBAC bypass for role name
	// "admin" (see internal/authz/authz.go, "Admin claim bypass removed").
	// This was previously missing entirely: EnsureAdminRoleAndPermissions
	// created the role but never granted it any permission, so every new
	// workspace's admin had zero working access to anything until someone
	// manually inserted role_permissions rows for it.
	// Dynamic SELECT (not a hardcoded list) so permissions added to the
	// global catalog later are picked up for future workspaces automatically.
	if _, err := exec.Exec(`
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT $1, id FROM permissions WHERE workspace_id IS NULL
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`, roleID); err != nil {
		return uuid.Nil, fmt.Errorf("grant admin role permissions: %w", err)
	}

	return roleID, nil
}
