package middlewares

import (
	"github.com/authsec-ai/authsec/config"
	"gorm.io/gorm"
)

// GetConnectionDynamically is a compatibility shim for legacy callsites.
// Product runtime is single-DB now; tenant/workspace separation must be enforced
// by row-level predicates, not by opening a different database.
func GetConnectionDynamically(_ interface{}, _ *string, tenantID *string) (*gorm.DB, error) {
	return config.DB, nil
}

// ConnectToTenantDB is a deprecated alias for GetConnectionDynamically.
func ConnectToTenantDB(masterDB interface{}, userEmail *string, tenantID *string) (*gorm.DB, error) {
	return GetConnectionDynamically(masterDB, userEmail, tenantID)
}

// CloseTenantDB is a no-op retained for legacy callsites.
func CloseTenantDB(_ *gorm.DB) error {
	return nil
}
