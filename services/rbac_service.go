package services

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RBACService struct {
	db *gorm.DB
}

func NewRBACService(db *gorm.DB) *RBACService {
	return &RBACService{db: db}
}

// ListPermissions lists permissions filtering by resource and optionally by tenant (nil for global)
// Note: In the atomic model, we might list all.
func (s *RBACService) ListPermissions(resource string) ([]models.RBACPermission, error) {
	var permissions []models.RBACPermission
	query := s.db
	if resource != "" {
		query = query.Where("resource = ?", resource)
	}
	// This implementation assumes listing all permissions the context has access to.
	// If needed, we can add WorkspaceID filter as an argument.
	if err := query.Find(&permissions).Error; err != nil {
		return nil, err
	}
	return permissions, nil
}

func (s *RBACService) DeletePermission(permID uuid.UUID) error {
	return s.db.Delete(&models.RBACPermission{}, "id = ?", permID).Error
}

func (s *RBACService) DeleteRole(roleID uuid.UUID) error {
	return s.db.Delete(&models.RBACRole{}, "id = ?", roleID).Error
}

func (s *RBACService) GetRole(roleID uuid.UUID) (*models.RBACRole, error) {
	var role models.RBACRole
	if err := s.db.Preload("Permissions").First(&role, "id = ?", roleID).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// CreateRoleComposite creates a Role and links Permissions in a single transaction.
func (s *RBACService) CreateRoleComposite(role *models.RBACRole, permissionIDs []uuid.UUID) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// 1. Insert into 'roles'
		if err := tx.Create(role).Error; err != nil {
			return err
		}

		// 2. Insert into 'role_permissions' for each ID in array
		if len(permissionIDs) > 0 {
			var rolePermissions []models.RolePermission
			for _, permID := range permissionIDs {
				rolePermissions = append(rolePermissions, models.RolePermission{
					RoleID:       role.ID,
					PermissionID: permID,
				})
			}
			if err := tx.Create(&rolePermissions).Error; err != nil {
				return err
			}
		}

		// Reload role with count if needed, but the caller usually handles response
		return nil
	})
}

// AssignRoleScoped grants access by binding a User to a Role within a specific Scope.
func (s *RBACService) AssignRoleScoped(binding *models.RoleBinding) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Validates that 'user' and 'role' belong to the same tenant.
		// Note: The DB Foreign Key constraints (tenant_id, user_id) already enforce this.
		// We can add an explicit check here if we want friendlier error messages,
		// but standard DB constraints are robust.

		// Insert into 'role_bindings'
		if err := tx.Create(binding).Error; err != nil {
			// Retry omitting optional denormalized columns when schema lacks them
			// Check for PostgreSQL error codes and column name errors
			errStr := strings.ToLower(err.Error())
			if strings.Contains(errStr, "username") ||
				strings.Contains(errStr, "role_name") ||
				strings.Contains(errStr, "42703") { // PostgreSQL error code for "column does not exist"
				log.Printf("[RBACService] Schema missing username/role_name columns, retrying with Omit: %v", err)
				if retryErr := tx.Omit("Username", "RoleName").Create(binding).Error; retryErr == nil {
					log.Printf("[RBACService] Successfully created role binding without denormalized columns")
					return nil
				} else {
					log.Printf("[RBACService] Retry with Omit failed: %v", retryErr)
					return retryErr
				}
			}
			return err
		}
		return nil
	})
}

// RegisterAtomicPermission defines a new capability in the system.
func (s *RBACService) RegisterAtomicPermission(perm *models.RBACPermission) error {
	// Insert into 'permissions'. Failure if resource+action pair exists (handled by DB unique constraint).
	return s.db.Create(perm).Error
}

// PolicyDecisionPointCheck verifies if a user can perform an action on a specific resource.
//
// Documentation:
// This function implements the Core Authorization Engine (Policy Decision Point).
// It verifies if a Principal (User or Service Account) has permission to perform an Action on a Resource.
//
// Logic:
// 1. Identifies all Role Bindings for the Principal.
// 2. Filters Bindings based on Scope:
//   - If scopeID is provided (e.g. Project UUID), checks for bindings with that scopeID OR Tenant-Wide bindings (scope_id IS NULL).
//   - If scopeID is nil (Tenant-Level check), checks only for Tenant-Wide bindings.
//
// 3. Joins Bindings -> Roles -> RolePermissions -> Permissions.
// 4. Checks if any Permission matches the requested Resource and Action.
//
// Usage for External Services:
// External services (e.g. OIDC Provider, API Gateway) should call the `/uflow/policy/check` endpoint
// which wraps this function.
// - Payload: { "principal_id": "...", "resource": "project", "action": "write", "scope_id": "..." }
// - Response: { "allowed": true, "trace": "..." }
type PolicyCheckResult struct {
	Allowed bool
	Trace   string
}

type PrincipalType string

const (
	PrincipalOperator    PrincipalType = "operator"
	PrincipalEndUser     PrincipalType = "end_user"
	PrincipalApplication PrincipalType = "application"
)

type PDPRequest struct {
	WorkspaceID uuid.UUID

	PrincipalType PrincipalType
	PrincipalID   uuid.UUID

	Resource string
	Action   string

	ApplicationID  *uuid.UUID
	ScopeType      *string
	ScopeID        *uuid.UUID
	OAuthScopeName *string
}

func (s *RBACService) Check(ctx context.Context, req PDPRequest) (*PolicyCheckResult, error) {
	if req.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("workspace_id required; migrate caller to PDPRequest")
	}
	if req.PrincipalID == uuid.Nil {
		return nil, fmt.Errorf("principal_id is required")
	}
	if req.PrincipalType == "" {
		return nil, fmt.Errorf("principal_type is required")
	}
	if strings.TrimSpace(req.Resource) == "" || strings.TrimSpace(req.Action) == "" {
		return nil, fmt.Errorf("resource and action are required")
	}

	if err := s.CheckPrincipalActiveInWorkspace(req.WorkspaceID, req.PrincipalID); err != nil {
		return &PolicyCheckResult{
			Allowed: false,
			Trace:   fmt.Sprintf("Principal precheck failed: %s", err.Error()),
		}, nil
	}

	var results []struct {
		RoleName  string
		BindingID uuid.UUID
		Subject   string
	}

	principalGroups := s.db.WithContext(ctx).
		Table("user_groups").
		Select("group_id").
		Where("user_id = ?", req.PrincipalID).
		Where("workspace_id = ?", req.WorkspaceID)

	query := s.db.WithContext(ctx).Table("role_bindings rb").
		Select(`r.name as role_name, rb.id as binding_id,
			CASE
				WHEN rb.user_id IS NOT NULL THEN 'user'
				WHEN rb.group_id IS NOT NULL THEN 'group'
				WHEN rb.service_account_id IS NOT NULL THEN 'service_account'
				ELSE 'unknown'
			END as subject`).
		Joins("JOIN roles r ON rb.role_id = r.id").
		Joins("JOIN role_permissions rp ON r.id = rp.role_id").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Where("rb.workspace_id = ?", req.WorkspaceID).
		Where("(r.workspace_id = ? OR r.workspace_id IS NULL)", req.WorkspaceID).
		Where("(p.workspace_id = ? OR p.workspace_id IS NULL)", req.WorkspaceID).
		Where("(rb.user_id = ? OR rb.service_account_id = ? OR rb.group_id IN (?))", req.PrincipalID, req.PrincipalID, principalGroups).
		Where("p.resource = ? AND p.action = ?", req.Resource, req.Action).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())")

	if req.ScopeID != nil {
		query = query.Where("(rb.scope_id = ? OR rb.scope_id IS NULL)", *req.ScopeID)
	} else {
		query = query.Where("rb.scope_id IS NULL")
	}
	if req.ScopeType != nil && *req.ScopeType != "" {
		query = query.Where("(rb.scope_type = ? OR rb.scope_type IS NULL)", *req.ScopeType)
	}
	if req.ApplicationID != nil {
		query = query.Where("(rb.scope_id = ? OR rb.scope_id IS NULL)", *req.ApplicationID)
	}

	if err := query.Scan(&results).Error; err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return &PolicyCheckResult{
			Allowed: true,
			Trace:   fmt.Sprintf("Granted by Binding [%s] via Role [%s] subject=%s workspace=%s", results[0].BindingID, results[0].RoleName, results[0].Subject, req.WorkspaceID),
		}, nil
	}

	return &PolicyCheckResult{
		Allowed: false,
		Trace:   "No matching workspace-scoped binding found",
	}, nil
}

// PolicyDecisionPointCheck is the legacy PDP signature. All callers must move
// to Check(ctx, PDPRequest{...}) which requires an explicit workspace_id; the
// old signature has no workspace input and would silently authorize against
// the global binding set, which is the cross-workspace leak pattern the v4
// migration removes.
//
// Kept as a hard-fail stub for one release so any stragglers fail loudly in
// CI/runtime rather than silently. Remove once no references exist anywhere
// in the source tree.
func (s *RBACService) PolicyDecisionPointCheck(_ uuid.UUID, _, _ string, _ *uuid.UUID) (*PolicyCheckResult, error) {
	return nil, fmt.Errorf("PolicyDecisionPointCheck is removed; migrate caller to RBACService.Check(ctx, PDPRequest{...}) with an explicit workspace_id")
}

// CheckPrincipalActive enforces the membership-status precheck.
//
// Rules (Phase A):
//   - If the principal has a tenant_memberships row, it must be status='active'.
//     Suspended/left/invited members fail closed.
//   - If the principal has a workspace_end_user_states row, it must be status='active'.
//     Suspended end users fail closed.
//   - Service accounts have no membership/end-user-state rows; pass through.
//   - Users with neither row (legacy / unbackfilled) pass through with a log
//     warning — Phase A backfill (migration 112) should have populated them.
//
// Returns nil on pass, error describing the failure otherwise.
func (s *RBACService) CheckPrincipalActive(principalID uuid.UUID) error {
	// Check tenant_memberships — at most one row per (tenant, user) but a user
	// may belong to multiple tenants in future. For Phase A we treat a single
	// suspended row anywhere as a hard fail.
	var membershipStatus string
	row := s.db.Table("workspace_user_memberships").
		Select("status").
		Where("user_id = ?", principalID).
		Limit(1).
		Row()
	if err := row.Scan(&membershipStatus); err == nil {
		if membershipStatus != models.MembershipStatusActive {
			return fmt.Errorf("membership not active (status=%s)", membershipStatus)
		}
	} else if err.Error() != "sql: no rows in result set" {
		log.Printf("[RBACService] membership status lookup failed for %s: %v", principalID, err)
	}

	// Check workspace_end_user_states — same approach, fail closed on suspended.
	var eusStatus string
	row2 := s.db.Table("workspace_end_user_states").
		Select("status").
		Where("user_id = ?", principalID).
		Limit(1).
		Row()
	if err := row2.Scan(&eusStatus); err == nil {
		if eusStatus != models.EndUserStatusActive {
			return fmt.Errorf("end-user state not active (status=%s)", eusStatus)
		}
	} else if err.Error() != "sql: no rows in result set" {
		log.Printf("[RBACService] end-user-state lookup failed for %s: %v", principalID, err)
	}

	return nil
}

// CheckPrincipalActiveInWorkspace is the workspace-scoped version used by the
// new PDP surface. During the workspace rollout, workspace_id maps to the
// existing tenant_id storage column.
func (s *RBACService) CheckPrincipalActiveInWorkspace(workspaceID, principalID uuid.UUID) error {
	var membershipStatus string
	row := s.db.Table("workspace_user_memberships").
		Select("status").
		Where("workspace_id = ? AND user_id = ?", workspaceID, principalID).
		Limit(1).
		Row()
	if err := row.Scan(&membershipStatus); err == nil {
		if membershipStatus != models.MembershipStatusActive {
			return fmt.Errorf("membership not active (status=%s)", membershipStatus)
		}
	} else if err.Error() != "sql: no rows in result set" {
		log.Printf("[RBACService] workspace membership lookup failed for workspace=%s principal=%s: %v", workspaceID, principalID, err)
	}

	var eusStatus string
	row2 := s.db.Table("workspace_end_user_states").
		Select("status").
		Where("workspace_id = ? AND user_id = ?", workspaceID, principalID).
		Limit(1).
		Row()
	if err := row2.Scan(&eusStatus); err == nil {
		if eusStatus != models.EndUserStatusActive {
			return fmt.Errorf("end-user state not active (status=%s)", eusStatus)
		}
	} else if err.Error() != "sql: no rows in result set" {
		log.Printf("[RBACService] workspace end-user-state lookup failed for workspace=%s principal=%s: %v", workspaceID, principalID, err)
	}

	return nil
}

// EffectiveBinding is one row in the materialised list of role_bindings that
// affect a given user — direct + via group + via service-account proxy. Used
// by the Effective Access Explorer admin page.
type EffectiveBinding struct {
	BindingID uuid.UUID  `json:"binding_id"`
	RoleID    uuid.UUID  `json:"role_id"`
	RoleName  string     `json:"role_name"`
	Subject   string     `json:"subject"` // user | group | service_account
	SubjectID uuid.UUID  `json:"subject_id"`
	ScopeType *string    `json:"scope_type"`
	ScopeID   *uuid.UUID `json:"scope_id"`
	ExpiresAt *string    `json:"expires_at,omitempty"`
}

// ListEffectiveBindings returns every role binding currently affecting a user.
// Includes direct user bindings AND bindings on any group the user belongs to.
// Expired bindings are excluded.
func (s *RBACService) ListEffectiveBindings(userID uuid.UUID) ([]EffectiveBinding, error) {
	var out []EffectiveBinding

	principalGroups := s.db.Table("user_groups").Select("group_id").Where("user_id = ?", userID)

	if err := s.db.Table("role_bindings rb").
		Select(`rb.id as binding_id, rb.role_id, r.name as role_name,
			CASE
				WHEN rb.user_id IS NOT NULL THEN 'user'
				WHEN rb.group_id IS NOT NULL THEN 'group'
				WHEN rb.service_account_id IS NOT NULL THEN 'service_account'
			END as subject,
			COALESCE(rb.user_id, rb.group_id, rb.service_account_id) as subject_id,
			rb.scope_type, rb.scope_id,
			TO_CHAR(rb.expires_at, 'YYYY-MM-DD"T"HH24:MI:SSZ') as expires_at`).
		Joins("JOIN roles r ON rb.role_id = r.id").
		Where("rb.user_id = ? OR rb.group_id IN (?)", userID, principalGroups).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Scan(&out).Error; err != nil {
		return nil, err
	}

	return out, nil
}
