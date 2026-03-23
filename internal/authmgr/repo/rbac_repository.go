// Package authmgrrepo provides RBAC repository operations for the authmgr sub-service.
package authmgrrepo

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	authmgrmodels "github.com/authsec-ai/authsec/internal/authmgr/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Perm struct {
	R string   `json:"r"`
	A []string `json:"a"`
}

func FromScopes(scopeNames []string) []Perm {
	type key struct{ r string }
	m := map[key]map[string]struct{}{}
	for _, sc := range scopeNames {
		parts := strings.SplitN(sc, ":", 2)
		if len(parts) != 2 {
			continue
		}
		r, a := parts[0], parts[1]
		k := key{r: r}
		if _, ok := m[k]; !ok {
			m[k] = map[string]struct{}{}
		}
		m[k][a] = struct{}{}
	}
	out := make([]Perm, 0, len(m))
	for k, acts := range m {
		as := make([]string, 0, len(acts))
		for a := range acts {
			as = append(as, a)
		}
		out = append(out, Perm{R: k.r, A: as})
	}
	return out
}

type PrimaryDBProvider func() *gorm.DB
type TenantDBProvider func(tenantID string) (*gorm.DB, error)

type RBACRepository interface {
	CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error)
	CheckPermissionWithScope(ctx context.Context, tenantID, userID uuid.UUID, resource, action string, scopeType string, scopeID *uuid.UUID) (bool, error)
	CheckOAuthScope(ctx context.Context, tenantID uuid.UUID, scopeName, resource, action string) (bool, error)
	CheckRole(ctx context.Context, tenantID, userID uuid.UUID, roleName string) (bool, error)
	CheckRoleResource(ctx context.Context, tenantID, userID uuid.UUID, roleName, scopeType string, scopeID uuid.UUID) (bool, error)
	GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]authmgrmodels.Permission, error)
	GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]authmgrmodels.Role, error)
}

type rbacRepository struct {
	primaryProvider PrimaryDBProvider
	tenantProvider  TenantDBProvider
}

func NewRBACRepository(primaryProvider PrimaryDBProvider, tenantProvider TenantDBProvider) RBACRepository {
	return &rbacRepository{
		primaryProvider: primaryProvider,
		tenantProvider:  tenantProvider,
	}
}

func (r *rbacRepository) candidateDBs(tenantID string) ([]*gorm.DB, error) {
	dbs := make([]*gorm.DB, 0, 2)
	if r.primaryProvider != nil {
		if db := r.primaryProvider(); db != nil {
			dbs = append(dbs, db)
		}
	}

	if r.tenantProvider != nil {
		tenantDB, err := r.tenantProvider(tenantID)
		if err != nil {
			if len(dbs) == 0 {
				return nil, err
			}
			return dbs, nil
		}
		if tenantDB != nil {
			dbs = append(dbs, tenantDB)
		}
	}

	if len(dbs) == 0 {
		return nil, errors.New("no database providers configured")
	}
	return dbs, nil
}

func (r *rbacRepository) checkAny(ctx context.Context, tenantID uuid.UUID, query string, args ...interface{}) (bool, error) {
	dbs, err := r.candidateDBs(tenantID.String())
	if err != nil {
		return false, err
	}

	var lastErr error
	for _, db := range dbs {
		var count int64
		if err := db.WithContext(ctx).Raw(query, args...).Scan(&count).Error; err != nil {
			lastErr = err
			continue
		}
		if count > 0 {
			return true, nil
		}
	}

	return false, lastErr
}

func (r *rbacRepository) CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error) {
	return r.checkAny(ctx, tenantID, `
		SELECT COUNT(*) FROM (
			SELECT 1
			FROM role_bindings rb
			JOIN role_permissions rp ON rb.role_id = rp.role_id
			JOIN permissions p ON rp.permission_id = p.id
			WHERE rb.tenant_id = ?
			  AND rb.user_id = ?
			  AND p.tenant_id = ?
			  AND p.resource = ?
			  AND p.action = ?
			  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
			UNION
			SELECT 1
			FROM role_bindings rb
			JOIN role_scopes rs ON rb.role_id = rs.role_id
			JOIN scope_permissions sp ON rs.scope_id = sp.scope_id
			JOIN permissions p ON sp.permission_id = p.id
			WHERE rb.tenant_id = ?
			  AND rb.user_id = ?
			  AND p.tenant_id = ?
			  AND p.resource = ?
			  AND p.action = ?
			  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
		) effective
	`, tenantID, userID, tenantID, resource, action, time.Now().UTC(), tenantID, userID, tenantID, resource, action, time.Now().UTC())
}

func (r *rbacRepository) CheckPermissionWithScope(ctx context.Context, tenantID, userID uuid.UUID, resource, action string, scopeType string, scopeID *uuid.UUID) (bool, error) {
	var (
		query string
		args  []interface{}
	)
	if scopeID == nil {
		query = `
			SELECT COUNT(*) FROM (
				SELECT 1
				FROM role_bindings rb
				JOIN role_permissions rp ON rb.role_id = rp.role_id
				JOIN permissions p ON rp.permission_id = p.id
				WHERE rb.tenant_id = ?
				  AND rb.user_id = ?
				  AND p.tenant_id = ?
				  AND p.resource = ?
				  AND p.action = ?
				  AND rb.scope_id IS NULL
				  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
				UNION
				SELECT 1
				FROM role_bindings rb
				JOIN role_scopes rs ON rb.role_id = rs.role_id
				JOIN scope_permissions sp ON rs.scope_id = sp.scope_id
				JOIN permissions p ON sp.permission_id = p.id
				WHERE rb.tenant_id = ?
				  AND rb.user_id = ?
				  AND p.tenant_id = ?
				  AND p.resource = ?
				  AND p.action = ?
				  AND rb.scope_id IS NULL
				  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
			) effective`
		args = []interface{}{tenantID, userID, tenantID, resource, action, time.Now().UTC(), tenantID, userID, tenantID, resource, action, time.Now().UTC()}
	} else {
		query = `
			SELECT COUNT(*) FROM (
				SELECT 1
				FROM role_bindings rb
				JOIN role_permissions rp ON rb.role_id = rp.role_id
				JOIN permissions p ON rp.permission_id = p.id
				WHERE rb.tenant_id = ?
				  AND rb.user_id = ?
				  AND p.tenant_id = ?
				  AND p.resource = ?
				  AND p.action = ?
				  AND (rb.scope_id IS NULL OR (rb.scope_id = ? AND rb.scope_type = ?))
				  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
				UNION
				SELECT 1
				FROM role_bindings rb
				JOIN role_scopes rs ON rb.role_id = rs.role_id
				JOIN scope_permissions sp ON rs.scope_id = sp.scope_id
				JOIN permissions p ON sp.permission_id = p.id
				WHERE rb.tenant_id = ?
				  AND rb.user_id = ?
				  AND p.tenant_id = ?
				  AND p.resource = ?
				  AND p.action = ?
				  AND (rb.scope_id IS NULL OR (rb.scope_id = ? AND rb.scope_type = ?))
				  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
			) effective`
		args = []interface{}{
			tenantID, userID, tenantID, resource, action, *scopeID, scopeType, time.Now().UTC(),
			tenantID, userID, tenantID, resource, action, *scopeID, scopeType, time.Now().UTC(),
		}
	}

	return r.checkAny(ctx, tenantID, query, args...)
}

func (r *rbacRepository) CheckOAuthScope(ctx context.Context, tenantID uuid.UUID, scopeName, resource, action string) (bool, error) {
	return r.checkAny(ctx, tenantID, `
		SELECT COUNT(*)
		FROM scopes s
		JOIN scope_permissions sp ON s.id = sp.scope_id
		JOIN permissions p ON sp.permission_id = p.id
		WHERE s.tenant_id = ?
		  AND s.name = ?
		  AND s.usage IN ('oauth', 'both')
		  AND p.tenant_id = ?
		  AND p.resource = ?
		  AND p.action = ?
	`, tenantID, scopeName, tenantID, resource, action)
}

func (r *rbacRepository) CheckRole(ctx context.Context, tenantID, userID uuid.UUID, roleName string) (bool, error) {
	return r.checkAny(ctx, tenantID, `
		SELECT COUNT(*)
		FROM role_bindings
		JOIN roles ON role_bindings.role_id = roles.id AND role_bindings.tenant_id = roles.tenant_id
		WHERE role_bindings.tenant_id = ?
		  AND role_bindings.user_id = ?
		  AND roles.name = ?
		  AND (role_bindings.expires_at IS NULL OR role_bindings.expires_at > ?)
	`, tenantID, userID, roleName, time.Now().UTC())
}

func (r *rbacRepository) CheckRoleResource(ctx context.Context, tenantID, userID uuid.UUID, roleName, scopeType string, scopeID uuid.UUID) (bool, error) {
	return r.checkAny(ctx, tenantID, `
		SELECT COUNT(*)
		FROM role_bindings
		JOIN roles ON role_bindings.role_id = roles.id AND role_bindings.tenant_id = roles.tenant_id
		WHERE role_bindings.tenant_id = ?
		  AND role_bindings.user_id = ?
		  AND roles.name = ?
		  AND role_bindings.scope_type = ?
		  AND role_bindings.scope_id = ?
		  AND (role_bindings.expires_at IS NULL OR role_bindings.expires_at > ?)
	`, tenantID, userID, roleName, scopeType, scopeID, time.Now().UTC())
}

func (r *rbacRepository) GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]authmgrmodels.Permission, error) {
	dbs, err := r.candidateDBs(tenantID.String())
	if err != nil {
		return nil, err
	}

	permissionsByID := make(map[uuid.UUID]authmgrmodels.Permission)
	var lastErr error
	for _, db := range dbs {
		var permissions []authmgrmodels.Permission
		if err := db.WithContext(ctx).Raw(`
			SELECT DISTINCT p.id, p.tenant_id, p.resource, p.action, p.description, p.created_at, p.updated_at
			FROM permissions p
			JOIN (
				SELECT rp.permission_id
				FROM role_bindings rb
				JOIN role_permissions rp ON rb.role_id = rp.role_id
				WHERE rb.tenant_id = ?
				  AND rb.user_id = ?
				  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
				UNION
				SELECT sp.permission_id
				FROM role_bindings rb
				JOIN role_scopes rs ON rb.role_id = rs.role_id
				JOIN scope_permissions sp ON rs.scope_id = sp.scope_id
				WHERE rb.tenant_id = ?
				  AND rb.user_id = ?
				  AND (rb.expires_at IS NULL OR rb.expires_at > ?)
			) effective ON effective.permission_id = p.id
			WHERE p.tenant_id = ?
			ORDER BY p.resource, p.action
		`, tenantID, userID, time.Now().UTC(), tenantID, userID, time.Now().UTC(), tenantID).Scan(&permissions).Error; err != nil {
			lastErr = err
			continue
		}
		for _, permission := range permissions {
			permissionsByID[permission.ID] = permission
		}
	}

	merged := make([]authmgrmodels.Permission, 0, len(permissionsByID))
	for _, permission := range permissionsByID {
		merged = append(merged, permission)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Resource == merged[j].Resource {
			return merged[i].Action < merged[j].Action
		}
		return merged[i].Resource < merged[j].Resource
	})
	if len(merged) == 0 {
		return merged, lastErr
	}
	return merged, nil
}

func (r *rbacRepository) GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]authmgrmodels.Role, error) {
	dbs, err := r.candidateDBs(tenantID.String())
	if err != nil {
		return nil, err
	}

	rolesByID := make(map[uuid.UUID]authmgrmodels.Role)
	var lastErr error
	for _, db := range dbs {
		var roles []authmgrmodels.Role
		if err := db.WithContext(ctx).
			Table("roles").
			Distinct("roles.*").
			Joins("JOIN role_bindings ON roles.id = role_bindings.role_id AND roles.tenant_id = role_bindings.tenant_id").
			Where("role_bindings.tenant_id = ?", tenantID).
			Where("role_bindings.user_id = ?", userID).
			Where("role_bindings.expires_at IS NULL OR role_bindings.expires_at > ?", time.Now().UTC()).
			Find(&roles).Error; err != nil {
			lastErr = err
			continue
		}
		for _, role := range roles {
			rolesByID[role.ID] = role
		}
	}

	merged := make([]authmgrmodels.Role, 0, len(rolesByID))
	for _, role := range rolesByID {
		merged = append(merged, role)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Name == merged[j].Name {
			return merged[i].ID.String() < merged[j].ID.String()
		}
		return merged[i].Name < merged[j].Name
	})
	if len(merged) == 0 {
		return merged, lastErr
	}
	return merged, nil
}
