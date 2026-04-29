package database

import "fmt"

// TenantDBService is a stub in authsec (single-tenant mode).
// All tenant database provisioning is delegated to the mt-plugin microservice.
// Methods are no-ops or return descriptive errors.
type TenantDBService struct{}

func NewTenantDBService(db *DBConnection, host, user, password, port string) (*TenantDBService, error) {
	return &TenantDBService{}, nil
}

// CreateTenantDatabase is a no-op in single-tenant mode.
// Tenant DB provisioning is handled by mt-plugin via NotifyAdminRegistered.
func (s *TenantDBService) CreateTenantDatabase(tenantID string) (string, error) {
	return "", fmt.Errorf("tenant database creation is handled by mt-plugin; configure MT_PLUGIN_GRPC_ADDR")
}

// DropTenantDatabase is a no-op in single-tenant mode.
// Tenant DB deletion is handled by mt-plugin via DeleteTenant.
func (s *TenantDBService) DropTenantDatabase(dbName string) error {
	return fmt.Errorf("tenant database deletion is handled by mt-plugin; configure MT_PLUGIN_GRPC_ADDR")
}

// HealthCheck returns nil — tenant DB health checks are not applicable in single-tenant mode.
func (s *TenantDBService) HealthCheck(dbName string) error {
	return nil
}

func (s *TenantDBService) Close() error {
	return nil
}
