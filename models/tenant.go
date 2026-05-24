package models

import (
	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"gorm.io/gorm"
)

// TenantWithHooks extends the sharedmodels.Tenant with GORM hooks.
//
// Single-tenant collapse: tenant database provisioning has moved out of the
// model layer entirely. There is no per-tenant DB to create or drop, so the
// hooks are no-ops kept only for GORM lifecycle compatibility.
type TenantWithHooks struct {
	sharedmodels.Tenant
}

// BeforeDelete is a no-op under the single-DB model.
func (t *TenantWithHooks) BeforeDelete(tx *gorm.DB) error {
	return nil
}

// TableName ensures the model uses the correct table name
func (TenantWithHooks) TableName() string {
	return "tenants"
}
