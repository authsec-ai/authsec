package repositories

import (
	"context"
	"fmt"
	"log"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ClientsRBACRepository defines the interface for clients RBAC-related operations
type ClientsRBACRepository interface {
	GrantUserClientsAccess(ctx context.Context, userID, workspaceID uuid.UUID) error
}

// clientsRbacRepository implements ClientsRBACRepository
type clientsRbacRepository struct {
	db *gorm.DB
}

// NewClientsRBACRepository creates a new instance of ClientsRBACRepository
func NewClientsRBACRepository(db *gorm.DB) ClientsRBACRepository {
	return &clientsRbacRepository{db: db}
}

// clientsPermissions are the 'clients' permissions every workspace's admin
// role holds.
var clientsPermissions = []struct {
	Action      string
	Description string
}{
	{"create", "Create new clients"},
	{"read", "View client details"},
	{"update", "Modify client details"},
	{"delete", "Delete clients"},
	{"list", "List all clients"},
	{"activate", "Activate clients"},
	{"deactivate", "Deactivate clients"},
	{"admin", "Full administrative access to clients"},
}

// GrantUserClientsAccess ensures the workspace has the 'clients' permissions
// and an admin role holding them, and binds the user to that role. It runs in
// one transaction under row-level security for workspaceID, every statement
// bound to it: a user of another workspace is not bound (the call fails). A
// ctx that already carries a different workspace is refused.
func (r *clientsRbacRepository) GrantUserClientsAccess(ctx context.Context, userID, workspaceID uuid.UUID) error {
	if r.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	if tc, err := tenancy.FromContext(ctx); err == nil && tc.WorkspaceID != workspaceID {
		return tenancy.ErrNotFound
	} else if err != nil {
		ctx = tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: workspaceID})
	}

	return tenancy.Transaction(ctx, r.db, func(tx *gorm.DB) error {
		q := sqlConn(tx)
		for _, p := range clientsPermissions {
			if _, err := tenancy.ExecContext(ctx, q, `INSERT INTO permissions (id, workspace_id, resource, action, description, created_at, updated_at)
				SELECT gen_random_uuid(), $1, 'clients', $2::text, $3::text, NOW(), NOW()
				 WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE workspace_id = $1 AND resource = 'clients' AND action = $2::text)
				ON CONFLICT (workspace_id, resource, action) DO NOTHING`, p.Action, p.Description); err != nil {
				return fmt.Errorf("insert permission (clients:%s): %w", p.Action, err)
			}
		}

		if _, err := tenancy.ExecContext(ctx, q, `INSERT INTO roles (id, workspace_id, name, description, is_system, created_at, updated_at)
			SELECT gen_random_uuid(), $1, 'admin', 'Tenant admin', true, NOW(), NOW()
			 WHERE NOT EXISTS (SELECT 1 FROM roles WHERE workspace_id = $1 AND name = 'admin')
			ON CONFLICT (workspace_id, name) DO NOTHING`); err != nil {
			return fmt.Errorf("create admin role: %w", err)
		}
		var adminRoleID uuid.UUID
		if err := tenancy.QueryRowContext(ctx, q,
			`SELECT id FROM roles WHERE workspace_id = $1 AND name = 'admin' LIMIT 1`, nil, &adminRoleID); err != nil {
			return fmt.Errorf("fetch admin role: %w", err)
		}

		if _, err := tenancy.ExecContext(ctx, q, `
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT r.id, p.id
			  FROM roles r
			  JOIN permissions p ON p.workspace_id = r.workspace_id AND p.resource = 'clients'
			 WHERE r.workspace_id = $1 AND r.id = $2
			ON CONFLICT DO NOTHING`, adminRoleID); err != nil {
			return fmt.Errorf("bind clients permissions to admin role: %w", err)
		}

		res, err := tenancy.ExecContext(ctx, q, `INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, conditions, created_at, updated_at)
			SELECT gen_random_uuid(), u.workspace_id, u.id, $3, NULL, NULL, '{}'::jsonb, NOW(), NOW() FROM users u WHERE u.workspace_id = $1 AND u.id = $2 AND NOT EXISTS (
				SELECT 1 FROM role_bindings WHERE workspace_id = $1 AND user_id = $2 AND role_id = $3 AND scope_type IS NULL AND scope_id IS NULL)
			ON CONFLICT DO NOTHING`, userID, adminRoleID)
		if err != nil {
			return fmt.Errorf("bind user to admin role: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			var bound bool
			if err := tenancy.QueryRowContext(ctx, q,
				`SELECT EXISTS (SELECT 1 FROM role_bindings WHERE workspace_id = $1 AND user_id = $2 AND role_id = $3)`,
				[]interface{}{userID, adminRoleID}, &bound); err != nil {
				return fmt.Errorf("bind user to admin role: %w", err)
			}
			if !bound {
				return fmt.Errorf("bind user to admin role: %w", tenancy.ErrNotFound) // not a user of the workspace
			}
		}

		log.Printf("[ClientsRBAC] Granted clients access to user %s in workspace %s", userID, workspaceID)
		return nil
	})
}
