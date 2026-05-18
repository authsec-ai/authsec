package sharedmodels

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Permission represents the many-to-many relationship between roles, scopes, and resources
type Permission struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid();uniqueIndex:idx_permissions_tenant_resource_action"`
	TenantID    uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Resource    string    `json:"resource" gorm:"type:text;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Action      string    `json:"action" gorm:"type:text;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Description string    `json:"description" gorm:"type:text"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

// ResourceMethod maps HTTP methods and path patterns to resources
type ResourceMethod struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ResourceID    uuid.UUID `gorm:"type:uuid;not null"`
	Method        string    `gorm:"size:10;not null"` // GET, POST, PUT, DELETE, etc.
	PathPattern   string    `gorm:"size:255;not null"`
	RequiresAdmin bool      `gorm:"default:false"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
}

// RolePermission links roles to permissions
type RolePermission struct {
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// ScopePermission links scopes to permissions
type ScopePermission struct {
	ScopeID      uuid.UUID `json:"scope_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// ServiceAccount represents a non-human identity
type ServiceAccount struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid();uniqueIndex:idx_sa_tenant_id"`
	TenantID    uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;uniqueIndex:idx_sa_tenant_id"`
	Name        string    `json:"name" gorm:"type:text;not null"`
	Description string    `json:"description" gorm:"type:text"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

// RoleBinding represents assignment of a Role to a User or Service Account
type RoleBinding struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID         uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index"`
	UserID           *uuid.UUID     `json:"user_id" gorm:"type:uuid;index"`
	ServiceAccountID *uuid.UUID     `json:"service_account_id" gorm:"type:uuid;index"`
	RoleID           uuid.UUID      `json:"role_id" gorm:"type:uuid;not null;index"`
	ScopeType        *string        `json:"scope_type" gorm:"type:text"`
	ScopeID          *uuid.UUID     `json:"scope_id" gorm:"type:uuid"`
	Conditions       datatypes.JSON `json:"conditions" gorm:"type:jsonb;default:'{}'"`
	ExpiresAt        *time.Time     `json:"expires_at"`
	CreatedBy        *uuid.UUID     `json:"created_by" gorm:"type:uuid"`
	CreatedAt        time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt        time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	Role             Role           `json:"role" gorm:"foreignKey:RoleID,TenantID;references:ID,TenantID"`
}

// GrantAudit captures changes to role bindings
type GrantAudit struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID    uuid.UUID      `json:"tenant_id" gorm:"type:uuid"`
	ActorUserID *uuid.UUID     `json:"actor_user_id" gorm:"type:uuid"`
	Action      string         `json:"action" gorm:"type:text"`
	TargetType  string         `json:"target_type" gorm:"type:text"`
	TargetID    *uuid.UUID     `json:"target_id" gorm:"type:uuid"`
	Before      datatypes.JSON `json:"before" gorm:"type:jsonb"`
	After       datatypes.JSON `json:"after" gorm:"type:jsonb"`
	CreatedAt   time.Time      `json:"created_at" gorm:"autoCreateTime"`
}

// TableName specifies the table name for GrantAudit
func (GrantAudit) TableName() string {
	return "grant_audit"
}

// TableName specifies the table name for Permission
func (Permission) TableName() string {
	return "permissions"
}

// TableName specifies the table name for ResourceMethod
func (ResourceMethod) TableName() string {
	return "resource_methods"
}

// HasPermission checks if a user with given roles has permission for a specific resource and scope
func HasPermission(db *gorm.DB, userRoles []string, resourceName, action string, tenantID *uuid.UUID) (bool, error) {
	var count int64

	query := db.Table("permissions p").
		Joins("JOIN role_permissions rp ON rp.permission_id = p.id").
		Joins("JOIN roles r ON rp.role_id = r.id").
		Where("r.name IN ?", userRoles).
		Where("p.resource = ?", resourceName).
		Where("p.action = ?", action)

	if tenantID != nil {
		query = query.Where("p.tenant_id = ?", tenantID).Where("r.tenant_id = ?", tenantID)
	}

	err := query.Count(&count).Error
	return count > 0, err
}

// CheckResourceMethodAccess checks if a user has access to a specific HTTP method and path
func CheckResourceMethodAccess(db *gorm.DB, userRoles []string, method, path string, tenantID *uuid.UUID) (bool, error) {
	var result struct {
		ResourceMethod ResourceMethod
		ResourceName   string
	}

	// First, find the resource method that matches the path pattern and join with resources
	query := db.Table("resource_methods").
		Select("resource_methods.*, resources.name as resource_name").
		Joins("JOIN resources ON resource_methods.resource_id = resources.id").
		Where("resource_methods.method = ?", method)

	// Add tenant filter if tenantID is provided
	if tenantID != nil {
		query = query.Where("(resources.tenant_id = ? OR resources.tenant_id IS NULL)", tenantID)
	}

	// Find the most specific matching path pattern
	// This is a simplified pattern matching - in production, you might want more sophisticated routing
	err := query.Where("path_pattern = ?", path).
		Or("? LIKE REPLACE(REPLACE(path_pattern, '*', '%'), '?', '_')", path).
		Scan(&result).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// No specific rule found - check if this is an admin path
			if strings.HasPrefix(path, "/admin") && !containsString(userRoles, "admin") {
				return false, nil
			}
			// Allow access by default for non-admin paths
			return true, nil
		}
		return false, err
	}

	// If the method requires admin and user doesn't have admin role, deny access
	if result.ResourceMethod.RequiresAdmin && !containsString(userRoles, "admin") {
		return false, nil
	}

	// Check if user has permission for the associated resource
	return HasPermission(db, userRoles, result.ResourceName, "read", tenantID)
}

// containsString checks if a slice contains a string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
