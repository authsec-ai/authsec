package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// AdminSeedRepository handles per-workspace admin role and permission seeding.
type AdminSeedRepository struct {
	db *DBConnection
}

func NewAdminSeedRepository(db *DBConnection) *AdminSeedRepository {
	return &AdminSeedRepository{db: db}
}

// EnsureAdminRoleAndPermissions creates the admin role of the workspace
// carried by ctx, binds it to the platform permission catalog, and returns
// its id. It runs under row-level security for that workspace.
func (asr *AdminSeedRepository) EnsureAdminRoleAndPermissions(ctx context.Context) (uuid.UUID, error) {
	if asr == nil || asr.db == nil {
		return uuid.Nil, fmt.Errorf("admin seed repository not initialized")
	}
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	var roleID uuid.UUID
	err = tenancy.WithTx(ctx, asr.db.DB, ws, func(tx *sql.Tx) error {
		var e error
		roleID, e = asr.ensureAdminRoleAndPermissions(ctx, tx)
		return e
	})
	return roleID, err
}

// EnsureAdminRoleAndPermissionsTx does the same inside the caller's
// transaction (sign-up creates the workspace and seeds it atomically).
func (asr *AdminSeedRepository) EnsureAdminRoleAndPermissionsTx(ctx context.Context, tx *sql.Tx) (uuid.UUID, error) {
	if asr == nil || asr.db == nil {
		return uuid.Nil, fmt.Errorf("admin seed repository not initialized")
	}
	if tx == nil {
		return uuid.Nil, fmt.Errorf("transaction is nil")
	}
	return asr.ensureAdminRoleAndPermissions(ctx, tx)
}

func (asr *AdminSeedRepository) ensureAdminRoleAndPermissions(ctx context.Context, q tenancy.Querier) (uuid.UUID, error) {
	if _, err := ctxWorkspace(ctx); err != nil {
		return uuid.Nil, err
	}
	now := time.Now()

	// The workspace's admin role; the row's workspace is the context's.
	roleID := uuid.New()
	if err := tenancy.QueryRowContext(ctx, q, `
		INSERT INTO roles (id, workspace_id, name, description, created_at, updated_at)
		VALUES ($2, $1, 'admin', 'Administrator with full access', $3, $3)
		ON CONFLICT (workspace_id, name) DO UPDATE SET updated_at = EXCLUDED.updated_at
		 WHERE roles.workspace_id = $1
		RETURNING id
	`, []interface{}{roleID, now}, &roleID); err != nil {
		return uuid.Nil, fmt.Errorf("ensure admin role: %w", err)
	}

	// Bind the admin role to every permission of the platform catalog
	// (workspace_id IS NULL). Permissions are defined once in the catalog; a
	// workspace's admin role only has access to what it is explicitly bound
	// to via role_permissions — there is no RBAC bypass for role name
	// "admin" (see internal/authz/authz.go). Dynamic SELECT (not a hardcoded
	// list) so permissions added to the catalog later are picked up for
	// future workspaces automatically. The role is re-checked to be this
	// workspace's.
	if _, err := tenancy.ExecContext(ctx, q, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id
		  FROM roles r
		  JOIN permissions p ON p.workspace_id IS NULL
		 WHERE r.workspace_id = $1 AND r.id = $2
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`, roleID); err != nil {
		return uuid.Nil, fmt.Errorf("grant admin role permissions: %w", err)
	}

	return roleID, nil
}
