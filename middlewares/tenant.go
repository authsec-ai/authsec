package middlewares

import (
	"github.com/authsec-ai/authsec/config"
	"gorm.io/gorm"
)

// GetConnectionDynamically returns the appropriate GORM DB for a given tenant.
//
// Single-tenant mode (MT_PLUGIN_GRPC_ADDR not set, or mt-plugin unreachable):
//   always returns the master DB — all data lives there.
//
// Multi-tenant mode (mt-plugin available):
//   looks up the tenant's dedicated database name from master and returns a
//   GORM instance pointed at that database. Falls back to master if the tenant
//   DB has not been provisioned yet.
//
// The tenantID parameter (pointer to string) is used for routing when non-nil.
// masterDB and userEmail are accepted for API compatibility but not used.
func GetConnectionDynamically(_ interface{}, _ *string, tenantID *string) (*gorm.DB, error) {
	if tenantID == nil || *tenantID == "" {
		return config.DB, nil
	}
	return config.GetTenantGORMDB(*tenantID)
}

// ConnectToTenantDB is a deprecated alias for GetConnectionDynamically.
func ConnectToTenantDB(masterDB interface{}, userEmail *string, tenantID *string) (*gorm.DB, error) {
	return GetConnectionDynamically(masterDB, userEmail, tenantID)
}

// CloseTenantDB is a no-op — tenant DB connections are cached globally in config.
func CloseTenantDB(_ *gorm.DB) error {
	return nil
}
