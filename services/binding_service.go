package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BindingService manages user ↔ role bindings on a per-Application basis,
// and surfaces the read views the admin UI needs:
//
//   - List/Create/Delete bindings
//   - List eligible users (users who could be bound; not yet bound)
//   - List access users (users currently bound, with their roles)
//   - Get a single user's effective access (resolved scopes)
//
// Effective-scope resolution is the load-bearing query: bindings → roles
// → role_scope_grants → oauth_scopes. Done as one JOIN so adding/removing
// bindings is reflected immediately on the next read.
type BindingService struct{}

func NewBindingService() *BindingService { return &BindingService{} }

var (
	ErrBindingNotFound      = errors.New("binding not found")
	ErrBindingAlreadyExists = errors.New("user is already bound to this role for this application")
	ErrUserNotInTenant      = errors.New("user not found in this tenant")
)

// CreateBindingInput is the body of POST /:id/bindings.
type CreateBindingInput struct {
	UserID string `json:"user_id" binding:"required"`
	RoleID string `json:"role_id" binding:"required"`
}

// BindingView is the read shape — adds resolved user + role display data
// so the admin UI doesn't need a separate hydrate pass per row.
type BindingView struct {
	models.ApplicationRoleBinding
	UserEmail string `json:"user_email,omitempty"`
	UserName  string `json:"user_name,omitempty"`
	RoleName  string `json:"role_name,omitempty"`
}

// ListBindings returns every binding for an Application, hydrated with
// user email/name and role name.
func (s *BindingService) ListBindings(tenantID string, applicationID uuid.UUID) ([]BindingView, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	type row struct {
		ID            uuid.UUID
		TenantID      string
		ApplicationID uuid.UUID
		RoleID        uuid.UUID
		UserID        uuid.UUID
		GrantedAt     time.Time
		GrantedBy     *uuid.UUID
		UserEmail     string
		UserName      string
		RoleName      string
	}
	var rows []row
	err = tenantDB.Table("application_role_bindings AS b").
		Select(`b.id, b.tenant_id, b.application_id, b.role_id, b.user_id,
		        b.granted_at, b.granted_by,
		        u.email AS user_email, u.name AS user_name,
		        r.name AS role_name`).
		Joins("JOIN users u ON u.id = b.user_id").
		Joins("JOIN application_roles r ON r.id = b.role_id").
		Where("b.application_id = ? AND b.tenant_id = ?", applicationID, tenantID).
		Order("b.granted_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	out := make([]BindingView, 0, len(rows))
	for _, r := range rows {
		out = append(out, BindingView{
			ApplicationRoleBinding: models.ApplicationRoleBinding{
				ID:            r.ID,
				TenantID:      r.TenantID,
				ApplicationID: r.ApplicationID,
				RoleID:        r.RoleID,
				UserID:        r.UserID,
				GrantedAt:     r.GrantedAt,
				GrantedBy:     r.GrantedBy,
			},
			UserEmail: r.UserEmail,
			UserName:  r.UserName,
			RoleName:  r.RoleName,
		})
	}
	return out, nil
}

// CreateBinding binds a user to a role for an Application. Validates that
// both the role and the user belong to this tenant + application.
func (s *BindingService) CreateBinding(
	tenantID string,
	applicationID uuid.UUID,
	in CreateBindingInput,
	grantedBy uuid.UUID,
) (*BindingView, error) {
	userID, err := uuid.Parse(strings.TrimSpace(in.UserID))
	if err != nil {
		return nil, fmt.Errorf("invalid user_id: %w", err)
	}
	roleID, err := uuid.Parse(strings.TrimSpace(in.RoleID))
	if err != nil {
		return nil, fmt.Errorf("invalid role_id: %w", err)
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var binding models.ApplicationRoleBinding
	var view BindingView
	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		// Validate the role belongs to this application + tenant.
		var role models.ApplicationRole
		if err := tx.Where("id = ? AND application_id = ? AND tenant_id = ?",
			roleID, applicationID, tenantID).First(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrRoleNotFound
			}
			return err
		}
		// Validate the user exists in this tenant. The users table uses
		// `tenant_id` as a uuid (master schema convention), so we cast
		// the tenant string to compare. If the cast fails, treat as no
		// match — the tenant_id in the JWT was validated upstream.
		var u struct {
			ID     uuid.UUID
			Email  string
			Name   string
			Active bool
		}
		if err := tx.Table("users").
			Select("id, email, COALESCE(name,'') AS name, active").
			Where("id = ?", userID).
			First(&u).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserNotInTenant
			}
			return err
		}

		binding = models.ApplicationRoleBinding{
			TenantID:      tenantID,
			ApplicationID: applicationID,
			RoleID:        roleID,
			UserID:        userID,
		}
		if grantedBy != uuid.Nil {
			binding.GrantedBy = &grantedBy
		}
		if err := tx.Create(&binding).Error; err != nil {
			if isUniqueViolation(err) {
				return ErrBindingAlreadyExists
			}
			return fmt.Errorf("insert binding: %w", err)
		}
		view = BindingView{
			ApplicationRoleBinding: binding,
			UserEmail:              u.Email,
			UserName:               u.Name,
			RoleName:               role.Name,
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &view, nil
}

// DeleteBinding removes a binding by its id. Returns ErrBindingNotFound
// if the binding doesn't exist OR belongs to a different application
// (defence — same scoping pattern as everywhere else in this backport).
func (s *BindingService) DeleteBinding(tenantID string, applicationID, bindingID uuid.UUID) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	res := tenantDB.Where("id = ? AND application_id = ? AND tenant_id = ?",
		bindingID, applicationID, tenantID).
		Delete(&models.ApplicationRoleBinding{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrBindingNotFound
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// User access reads
// ─────────────────────────────────────────────────────────────────────────

// EligibleUser is one row of /eligible-users — a user in the tenant who
// could be bound (i.e. not already bound to any role on this Application).
type EligibleUser struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
	Name   string    `json:"name,omitempty"`
	Active bool      `json:"active"`
}

// ListEligibleUsers returns users in the tenant who have NO existing binding
// to this Application. Useful for the admin UI's "grant access to user"
// picker. Supports `?search=` for prefix matching on email or name.
func (s *BindingService) ListEligibleUsers(
	tenantID string,
	applicationID uuid.UUID,
	search string,
	limit int,
) ([]EligibleUser, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	q := tenantDB.Table("users AS u").
		Select("u.id AS user_id, u.email, COALESCE(u.name,'') AS name, u.active").
		Where("u.deleted_at IS NULL").
		Where(`u.id NOT IN (
            SELECT user_id FROM application_role_bindings
             WHERE application_id = ? AND tenant_id = ?
        )`, applicationID, tenantID)
	if search = strings.TrimSpace(search); search != "" {
		needle := "%" + strings.ToLower(search) + "%"
		q = q.Where("LOWER(u.email) LIKE ? OR LOWER(u.name) LIKE ?", needle, needle)
	}
	q = q.Order("u.email ASC").Limit(limit)

	var rows []EligibleUser
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list eligible users: %w", err)
	}
	return rows, nil
}

// AccessUser is one row of /access/users — a user currently bound to one
// or more roles on this Application, with the aggregated role names and
// scope strings they've earned.
type AccessUser struct {
	UserID       uuid.UUID `json:"user_id"`
	Email        string    `json:"email"`
	Name         string    `json:"name,omitempty"`
	Active       bool      `json:"active"`
	RoleNames    []string  `json:"role_names"`
	ScopeStrings []string  `json:"scope_strings"`
}

// ListAccessUsers returns every user with at least one binding on this
// Application, aggregating their role names and the union of scope
// strings they've earned across all their bindings.
func (s *BindingService) ListAccessUsers(tenantID string, applicationID uuid.UUID) ([]AccessUser, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// Single query that aggregates by user. The trick: array_agg(DISTINCT ...)
	// for roles and scopes, joined via the bindings→roles→grants→scopes chain.
	type row struct {
		UserID       uuid.UUID
		Email        string
		Name         string
		Active       bool
		RoleNames    []string `gorm:"type:text[]"`
		ScopeStrings []string `gorm:"type:text[]"`
	}
	var rows []row
	err = tenantDB.Raw(`
        SELECT
            u.id AS user_id,
            u.email,
            COALESCE(u.name,'') AS name,
            u.active,
            COALESCE(array_remove(array_agg(DISTINCT r.name), NULL), '{}') AS role_names,
            COALESCE(array_remove(array_agg(DISTINCT s.scope_string), NULL), '{}') AS scope_strings
          FROM application_role_bindings b
          JOIN users u ON u.id = b.user_id
          JOIN application_roles r ON r.id = b.role_id
          LEFT JOIN application_role_scope_grants g ON g.role_id = r.id
          LEFT JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE b.application_id = ? AND b.tenant_id = ?
         GROUP BY u.id, u.email, u.name, u.active
         ORDER BY u.email ASC
    `, applicationID, tenantID).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list access users: %w", err)
	}
	out := make([]AccessUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, AccessUser{
			UserID:       r.UserID,
			Email:        r.Email,
			Name:         r.Name,
			Active:       r.Active,
			RoleNames:    r.RoleNames,
			ScopeStrings: r.ScopeStrings,
		})
	}
	return out, nil
}

// EffectiveScopesForSubject is the introspection-time RBAC filter resolver.
// Given an Application and a token's `sub` claim, it returns the user's
// current effective scope strings — the same set used by the admin UI's
// /users/:user_id/effective-access endpoint, but designed for the hot
// path on every /oauth/v2/introspect call.
//
// Semantics:
//
//   - subject parses as a uuid → look up bindings → roles → scope_grants
//     → scopes for that user on this Application. Return the deduplicated
//     set.
//   - subject doesn't parse as a uuid → it's a non-end-user token
//     (client_credentials, SPIRE workload, etc.). Return (nil, true) so
//     the caller skips the filter and passes through Hydra's scope claim.
//   - user exists but has no bindings → return empty slice, not nil.
//     The caller intersects with the token's claimed scope; empty
//     intersection means deny-all, which is correct.
//   - user doesn't exist in the tenant → return empty slice + false.
//     Fail-closed — we can't confirm the user, so we don't trust the
//     token's claimed scope.
//   - DB error → propagated as an error. Caller decides; the recommended
//     posture is fail-closed (treat as empty scope) to avoid leaking
//     access on infra hiccups.
//
// Returns (scopes, isUserSubject). isUserSubject=false means "subject
// wasn't a user — don't filter."
func (s *BindingService) EffectiveScopesForSubject(
	tenantID string,
	applicationID uuid.UUID,
	subject string,
) ([]string, bool, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, false, nil
	}
	userID, err := uuid.Parse(subject)
	if err != nil {
		// Not a UUID — non-user token. Skip the filter.
		return nil, false, nil
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, true, fmt.Errorf("get tenant db: %w", err)
	}

	// Confirm the user exists in this tenant. If not, fail closed.
	var exists int64
	if err := tenantDB.Table("users").
		Where("id = ? AND deleted_at IS NULL", userID).
		Count(&exists).Error; err != nil {
		return nil, true, fmt.Errorf("verify user: %w", err)
	}
	if exists == 0 {
		// Treat unknown users as having zero effective scopes — the
		// intersection will be empty, blocking the call.
		return []string{}, true, nil
	}

	// Same resolver as /users/:user_id/effective-access but returns the
	// flat scope-string list directly (no per-role view needed here).
	var scopes []string
	err = tenantDB.Raw(`
        SELECT DISTINCT s.scope_string
          FROM application_role_bindings b
          JOIN application_role_scope_grants g ON g.role_id = b.role_id
          JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE b.application_id = ?
           AND b.tenant_id = ?
           AND b.user_id = ?
         ORDER BY s.scope_string ASC
    `, applicationID, tenantID, userID).Scan(&scopes).Error
	if err != nil {
		return nil, true, fmt.Errorf("resolve effective scopes: %w", err)
	}
	if scopes == nil {
		scopes = []string{}
	}
	return scopes, true, nil
}

// EffectiveAccessRole is one role contributing to a user's effective access.
type EffectiveAccessRole struct {
	RoleID       uuid.UUID `json:"role_id"`
	RoleName     string    `json:"role_name"`
	GrantedAt    time.Time `json:"granted_at"`
	ScopeStrings []string  `json:"scope_strings"`
}

// EffectiveAccessResponse is what /users/:user_id/effective-access returns.
// Lists the user's bindings on this Application + the union of scope
// strings they've earned. EffectiveScopes is the deduplicated union of
// every role's scope_strings — this is the "what can this user do?" set.
type EffectiveAccessResponse struct {
	UserID          uuid.UUID             `json:"user_id"`
	Email           string                `json:"email"`
	Name            string                `json:"name,omitempty"`
	Active          bool                  `json:"active"`
	Roles           []EffectiveAccessRole `json:"roles"`
	EffectiveScopes []string              `json:"effective_scopes"`
}

// GetEffectiveAccess resolves the full per-role + aggregated-scope view
// for one user on one Application. Returns ErrUserNotInTenant if the user
// doesn't exist; returns a response with empty Roles + EffectiveScopes
// if the user exists but has no bindings.
func (s *BindingService) GetEffectiveAccess(
	tenantID string,
	applicationID, userID uuid.UUID,
) (*EffectiveAccessResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// 1. User exists?
	var u struct {
		ID     uuid.UUID
		Email  string
		Name   string
		Active bool
	}
	if err := tenantDB.Table("users").
		Select("id, email, COALESCE(name,'') AS name, active").
		Where("id = ?", userID).
		First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotInTenant
		}
		return nil, err
	}

	// 2. Bindings + role names + role scopes (one query, grouped by role).
	type roleRow struct {
		RoleID       uuid.UUID
		RoleName     string
		GrantedAt    time.Time
		ScopeStrings []string `gorm:"type:text[]"`
	}
	var rows []roleRow
	err = tenantDB.Raw(`
        SELECT
            r.id AS role_id,
            r.name AS role_name,
            b.granted_at,
            COALESCE(array_remove(array_agg(DISTINCT s.scope_string), NULL), '{}') AS scope_strings
          FROM application_role_bindings b
          JOIN application_roles r ON r.id = b.role_id
          LEFT JOIN application_role_scope_grants g ON g.role_id = r.id
          LEFT JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE b.application_id = ? AND b.tenant_id = ? AND b.user_id = ?
         GROUP BY r.id, r.name, b.granted_at
         ORDER BY b.granted_at DESC
    `, applicationID, tenantID, userID).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("resolve effective access: %w", err)
	}

	// 3. Aggregate the union of scopes.
	scopeSet := map[string]struct{}{}
	roles := make([]EffectiveAccessRole, 0, len(rows))
	for _, r := range rows {
		roles = append(roles, EffectiveAccessRole{
			RoleID:       r.RoleID,
			RoleName:     r.RoleName,
			GrantedAt:    r.GrantedAt,
			ScopeStrings: r.ScopeStrings,
		})
		for _, s := range r.ScopeStrings {
			scopeSet[s] = struct{}{}
		}
	}
	effective := make([]string, 0, len(scopeSet))
	for s := range scopeSet {
		effective = append(effective, s)
	}
	// Sort for stable output.
	for i := 0; i < len(effective); i++ {
		for j := i + 1; j < len(effective); j++ {
			if effective[j] < effective[i] {
				effective[i], effective[j] = effective[j], effective[i]
			}
		}
	}

	return &EffectiveAccessResponse{
		UserID:          u.ID,
		Email:           u.Email,
		Name:            u.Name,
		Active:          u.Active,
		Roles:           roles,
		EffectiveScopes: effective,
	}, nil
}
