package database

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/google/uuid"
)

// AdminBootstrapper seeds per-tenant admin artifacts at service startup.
type AdminBootstrapper struct {
	db *DBConnection
}

// NewAdminBootstrapper constructs a bootstrapper.
func NewAdminBootstrapper(db *DBConnection) *AdminBootstrapper {
	return &AdminBootstrapper{db: db}
}

// SeedAllTenants ensures every tenant has the enforced admin role/permission
// surface and best-effort admin binding.
func (b *AdminBootstrapper) SeedAllTenants() error {
	if b == nil || b.db == nil {
		return fmt.Errorf("admin bootstrapper not initialized")
	}

	rows, err := b.db.Query(`SELECT COALESCE(tenant_id, id) AS tenant_id FROM tenants`)
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	seedRepo := NewAdminSeedRepository(b.db)
	count := 0

	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			log.Printf("Skipping tenant scan error: %v", err)
			continue
		}

		if tenantID == uuid.Nil {
			continue
		}
		count++

		roleID, err := seedRepo.EnsureAdminRoleAndPermissions(tenantID)
		if err != nil {
			log.Printf("Warning: failed to seed admin role/permissions for tenant %s: %v", tenantID, err)
			continue
		}

		if err := b.ensureTenantAdminBinding(tenantID, roleID); err != nil {
			log.Printf("Warning: failed to ensure admin binding for tenant %s: %v", tenantID, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate tenants: %w", err)
	}

	log.Printf("Seeded admin RBAC for %d tenants", count)

	return nil
}

func (b *AdminBootstrapper) ensureTenantAdminBinding(tenantID, roleID uuid.UUID) error {
	if b == nil || b.db == nil {
		return fmt.Errorf("admin bootstrapper not initialized")
	}

	var userID uuid.UUID
	err := b.db.QueryRow(`
		SELECT u.id
		FROM users u
		JOIN tenants t ON t.tenant_id::text = u.tenant_id::text
		WHERE u.tenant_id::text = $1
		  AND u.active = true
		  AND LOWER(u.email) = LOWER(t.email)
		LIMIT 1
	`, tenantID.String()).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			err = b.db.QueryRow(`
				SELECT id
				FROM users
				WHERE tenant_id::text = $1
				  AND active = true
				ORDER BY created_at ASC
				LIMIT 1
			`, tenantID.String()).Scan(&userID)
			if err == sql.ErrNoRows {
				return nil
			}
			if err != nil {
				return fmt.Errorf("find fallback admin user for tenant %s: %w", tenantID, err)
			}
		} else {
			return fmt.Errorf("find tenant admin user for tenant %s: %w", tenantID, err)
		}
	}

	_, err = b.db.Exec(`
		INSERT INTO role_bindings (id, tenant_id, user_id, role_id, scope_type, scope_id, created_at)
		SELECT $1, $2, $3, $4, NULL, NULL, NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM role_bindings
			WHERE tenant_id = $2
			  AND user_id = $3
			  AND role_id = $4
			  AND scope_type IS NULL
			  AND scope_id IS NULL
		)
	`, uuid.New(), tenantID, userID, roleID)
	if err != nil {
		return fmt.Errorf("create admin role binding: %w", err)
	}

	return nil
}
