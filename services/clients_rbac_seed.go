package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/database"
)

// SeedClientAdminRBAC ensures the tenant has the minimal enforced RBAC surface
// for the client and external-service routes.
//
// IMPORTANT: db should be the MAIN database connection (config.DB), NOT a tenant database.
func SeedClientAdminRBAC(ctx context.Context, db *gorm.DB, tenantID uuid.UUID) error {
	if db == nil {
		return fmt.Errorf("db is required")
	}
	if tenantID == uuid.Nil {
		return fmt.Errorf("tenant_id is required")
	}
	return database.SeedTenantAdminRBAC(ctx, db, tenantID)
}
