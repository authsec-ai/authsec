package sharedmodels

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// TenantDatabaseUtils provides utility functions for tenant database operations
// Note: This replaces the previous GORM hooks functionality
type TenantDatabaseUtils struct{}

// GenerateTenantDBName generates a tenant database name from tenant ID
func (TenantDatabaseUtils) GenerateTenantDBName(tenantID uuid.UUID) string {
	return fmt.Sprintf("tenant_%s", strings.ReplaceAll(tenantID.String(), "-", "_"))
}

// ValidateTenantDBName validates a tenant database name format
func (TenantDatabaseUtils) ValidateTenantDBName(dbName string) bool {
	return strings.HasPrefix(dbName, "tenant_") && len(dbName) > 7
}
