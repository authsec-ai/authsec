package models

import (
	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"gorm.io/gorm"
)

// TenantWithHooks extends sharedmodels.Tenant with GORM hooks.
//
// Phase 6 collapse: the `tenants` table is gone. Everywhere this type used
// to back is now the `workspaces` table. The struct stays only so existing
// GORM-flavoured callers keep compiling; the hooks are no-ops.
type TenantWithHooks struct {
	sharedmodels.Tenant
}

// BeforeDelete is a no-op under the single-DB / workspace-only model.
func (t *TenantWithHooks) BeforeDelete(tx *gorm.DB) error {
	return nil
}

// TableName points at the workspaces table (post-Phase-6).
func (TenantWithHooks) TableName() string {
	return "workspaces"
}
