package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// tenantAdminPermissionSeed is the minimal permission surface enforced by the
// current route middleware. Keep this list aligned with middlewares.Require(...)
// call sites rather than historical microservice permissions.
type tenantAdminPermissionSeed struct {
	Resource    string
	Action      string
	Description string
}

var tenantAdminPermissionSeeds = []tenantAdminPermissionSeed{
	{Resource: "admin", Action: "access", Description: "Administrative access gate"},
	{Resource: "admin", Action: "manage", Description: "Administrative management"},
	{Resource: "users", Action: "delete", Description: "Delete admin and end-user accounts"},
	{Resource: "tenants", Action: "delete", Description: "Delete tenant records"},
	{Resource: "external-service", Action: "create", Description: "Create external service entries"},
	{Resource: "external-service", Action: "read", Description: "Read external service entries"},
	{Resource: "external-service", Action: "update", Description: "Update external service entries"},
	{Resource: "external-service", Action: "delete", Description: "Delete external service entries"},
	{Resource: "external-service", Action: "credentials", Description: "Read external service credentials"},
	{Resource: "clients", Action: "admin", Description: "Administrative access to clients"},
}

// AdminSeedRepository handles per-tenant admin role/permissions seeding.
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

// EnsureAdminRoleAndPermissions creates the admin role and minimal enforced
// permissions for a tenant, then returns the role ID.
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
		ON CONFLICT (tenant_id, name) DO UPDATE
		SET description = EXCLUDED.description,
		    updated_at = EXCLUDED.updated_at
		RETURNING id
	`, roleID, tenantID, now).Scan(&roleID); err != nil {
		return uuid.Nil, fmt.Errorf("ensure admin role: %w", err)
	}

	for _, p := range tenantAdminPermissionSeeds {
		permID := uuid.New()
		if err := exec.QueryRow(`
			INSERT INTO permissions (id, tenant_id, resource, action, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6)
			ON CONFLICT (tenant_id, resource, action) DO UPDATE
			SET description = EXCLUDED.description,
			    updated_at = EXCLUDED.updated_at
			RETURNING id
		`, permID, tenantID, p.Resource, p.Action, fmt.Sprintf("%s %s", p.Resource, p.Action), now).Scan(&permID); err != nil {
			return uuid.Nil, fmt.Errorf("ensure permission %s:%s: %w", p.Resource, p.Action, err)
		}

		if _, err := exec.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`, roleID, permID); err != nil {
			return uuid.Nil, fmt.Errorf("bind permission %s:%s: %w", p.Resource, p.Action, err)
		}
	}

	return roleID, nil
}

// SeedTenantAdminRBAC seeds the minimal tenant RBAC surface used by the current
// clients and external-service routes.
func SeedTenantAdminRBAC(ctx context.Context, db *gorm.DB, tenantID uuid.UUID) error {
	if db == nil {
		return fmt.Errorf("db is required")
	}
	if tenantID == uuid.Nil {
		return fmt.Errorf("tenant_id is required")
	}

	tx := db.WithContext(ctx)
	now := time.Now()

	roleID := uuid.New()
	if err := tx.Raw(`
		INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at)
		VALUES (?, ?, 'admin', 'Tenant admin with full access', ?, ?)
		ON CONFLICT (tenant_id, name) DO UPDATE
		SET description = EXCLUDED.description,
		    updated_at = EXCLUDED.updated_at
		RETURNING id
	`, roleID, tenantID, now, now).Scan(&roleID).Error; err != nil {
		return fmt.Errorf("ensure admin role: %w", err)
	}

	for _, p := range tenantAdminPermissionSeeds {
		permID := uuid.New()
		if err := tx.Raw(`
			INSERT INTO permissions (id, tenant_id, resource, action, description, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, resource, action) DO UPDATE
			SET description = EXCLUDED.description,
			    updated_at = EXCLUDED.updated_at
			RETURNING id
		`, permID, tenantID, p.Resource, p.Action, p.Description, now, now).Scan(&permID).Error; err != nil {
			return fmt.Errorf("ensure permission %s:%s: %w", p.Resource, p.Action, err)
		}

		if err := tx.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			VALUES (?, ?)
			ON CONFLICT DO NOTHING
		`, roleID, permID).Error; err != nil {
			return fmt.Errorf("bind permission %s:%s: %w", p.Resource, p.Action, err)
		}
	}

	return nil
}
