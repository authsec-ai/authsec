package sharedmodels

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// TenantDatabaseUtils provides utility functions for tenant database operations
// Note: This replaces the previous GORM hooks functionality
type TenantDatabaseUtils struct{}

// GenerateWorkspaceDBName generates a tenant database name from tenant ID
func (TenantDatabaseUtils) GenerateWorkspaceDBName(workspaceID uuid.UUID) string {
	return fmt.Sprintf("tenant_%s", strings.ReplaceAll(workspaceID.String(), "-", "_"))
}

// ValidateWorkspaceDBName validates a tenant database name format
func (TenantDatabaseUtils) ValidateWorkspaceDBName(dbName string) bool {
	return strings.HasPrefix(dbName, "tenant_") && len(dbName) > 7
}
