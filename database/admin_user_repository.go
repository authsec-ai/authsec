package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var ErrAdminUserNotFound = errors.New("admin user not found")

// ErrAmbiguousAdminEmail means an email is a console admin in more than one
// workspace and the caller did not say which (AS-038).
var ErrAmbiguousAdminEmail = errors.New("email is an admin in more than one workspace")

// AdminUserRepository handles admin user database operations on global DB
type AdminUserRepository struct {
	db *DBConnection
}

// NewAdminUserRepository creates a new admin user repository
func NewAdminUserRepository(db *DBConnection) *AdminUserRepository {
	return &AdminUserRepository{db: db}
}

// EnsureAdminRole returns the admin role id for the given tenant, creating it if needed.
// This now uses the full seeding function to ensure permissions are also created.
func (aur *AdminUserRepository) EnsureAdminRole(workspaceID uuid.UUID) (uuid.UUID, error) {
	return NewAdminSeedRepository(aur.db).EnsureAdminRoleAndPermissions(workspaceID)
}

// adminUserColumns is the column list scanAdminUserRow expects.
const adminUserColumns = `
		       u.id, u.email, u.username, u.password_hash, u.name,
		       u.client_id, u.workspace_id, u.project_id, u.workspace_domain, u.provider,
		       COALESCE(u.provider_id, '') AS provider_id,
		       COALESCE(u.provider_data, '{}'::jsonb) AS provider_data,
		       COALESCE(u.avatar_url, '') AS avatar_url, u.active, u.mfa_enabled,
		       u.mfa_method, COALESCE(u.mfa_default_method, '') AS mfa_default_method,
		       u.mfa_enrolled_at, u.mfa_verified,
		       COALESCE(u.external_id, '') AS external_id,
		       COALESCE(u.sync_source, '') AS sync_source,
		       u.last_sync_at, u.is_synced_user,
		       u.last_login, u.created_at, u.updated_at,
		       COALESCE(u.temporary_password, false) AS temporary_password,
		       u.temporary_password_expires_at,
		       COALESCE(u.is_primary_admin, false) AS is_primary_admin`

func scanAdminUserRow(row interface{ Scan(...interface{}) error }) (models.AdminUser, error) {
	var user models.AdminUser
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.Name,
		&user.ClientID,
		&user.WorkspaceID,
		&user.ProjectID,
		&user.WorkspaceDomain,
		&user.Provider,
		&user.ProviderID,
		&user.ProviderData,
		&user.AvatarURL,
		&user.Active,
		&user.MFAEnabled,
		pq.Array(&user.MFAMethod),
		&user.MFADefaultMethod,
		&user.MFAEnrolledAt,
		&user.MFAVerified,
		&user.ExternalID,
		&user.SyncSource,
		&user.LastSyncAt,
		&user.IsSyncedUser,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.TemporaryPassword,
		&user.TemporaryPasswordExpiresAt,
		&user.IsPrimaryAdmin,
	)
	return user, err
}

// adminInWorkspace restricts u to users holding the admin role in the
// workspace bound to $1.
const adminInWorkspace = `
		  AND EXISTS (
		        SELECT 1 FROM role_bindings rb
		        JOIN roles r ON r.id = rb.role_id AND r.workspace_id = rb.workspace_id
		        WHERE rb.workspace_id = $1 AND rb.user_id = u.id
		          AND LOWER(r.name) IN ('admin', 'administrator', 'super_admin'))`

// ListAdminUsersInWorkspace returns the active admin users of the workspace
// carried by ctx, optionally filtered by provider.
func (aur *AdminUserRepository) ListAdminUsersInWorkspace(ctx context.Context, provider string) ([]models.AdminUser, error) {
	query := `SELECT ` + adminUserColumns + `
		FROM users u
		WHERE u.workspace_id = $1 AND u.active = true` + adminInWorkspace
	args := []interface{}{}
	if provider != "" {
		query += ` AND u.provider = $2`
		args = append(args, provider)
	}
	query += ` ORDER BY u.created_at DESC`

	rows, err := tenancy.QueryContext(ctx, aur.db.DB, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin users: %w", err)
	}
	defer rows.Close()

	var users []models.AdminUser
	for rows.Next() {
		user, err := scanAdminUserRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("admin user query error: %w", err)
	}
	return users, nil
}

// GetAdminUserInWorkspace returns the admin user with this id in the
// workspace carried by ctx, active or not. A user of another workspace, or
// one without the admin role here, is tenancy.ErrNotFound.
func (aur *AdminUserRepository) GetAdminUserInWorkspace(ctx context.Context, id uuid.UUID) (*models.AdminUser, error) {
	query := `SELECT ` + adminUserColumns + `
		FROM users u
		WHERE u.workspace_id = $1 AND u.id = $2 AND u.deleted_at IS NULL` + adminInWorkspace
	rows, err := tenancy.QueryContext(ctx, aur.db.DB, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin user: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("failed to get admin user: %w", err)
		}
		return nil, tenancy.ErrNotFound
	}
	user, err := scanAdminUserRow(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to scan admin user: %w", err)
	}
	return &user, nil
}

// SetAdminUserActiveInWorkspace sets the active flag of a user of the
// workspace carried by ctx. Another workspace's user is tenancy.ErrNotFound.
func (aur *AdminUserRepository) SetAdminUserActiveInWorkspace(ctx context.Context, id uuid.UUID, active bool) error {
	res, err := tenancy.ExecContext(ctx, aur.db.DB, `
		UPDATE users SET active = $3, updated_at = NOW()
		WHERE workspace_id = $1 AND id = $2`, id, active)
	if err != nil {
		return fmt.Errorf("failed to update admin user active flag: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return tenancy.ErrNotFound
	}
	return nil
}

// UpdateAdminUserInWorkspace updates columns of a user of the workspace
// carried by ctx. Column names come from the caller's code, never the request.
func (aur *AdminUserRepository) UpdateAdminUserInWorkspace(ctx context.Context, id uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}
	cols := make([]string, 0, len(updates))
	for col := range updates {
		cols = append(cols, col)
	}
	sort.Strings(cols)
	args := []interface{}{id}
	set := make([]string, 0, len(cols)+1)
	for _, col := range cols {
		args = append(args, updates[col])
		set = append(set, fmt.Sprintf("%s = $%d", col, len(args)+1))
	}
	set = append(set, "updated_at = NOW()")
	query := "UPDATE users SET " + strings.Join(set, ", ") + " WHERE workspace_id = $1 AND id = $2"
	res, err := tenancy.ExecContext(ctx, aur.db.DB, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update admin user: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return tenancy.ErrNotFound
	}
	return nil
}

// UserRole represents a role assigned to a user
type UserRole struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// GetUserRoles returns all roles assigned to a user for a specific tenant
func (aur *AdminUserRepository) GetUserRoles(userID, workspaceID uuid.UUID) ([]UserRole, error) {
	query := `
		SELECT DISTINCT r.id, r.name
		FROM roles r
		JOIN role_bindings rb ON r.id = rb.role_id
		WHERE rb.user_id = $1 AND rb.workspace_id = $2
		ORDER BY r.name
	`

	rows, err := aur.db.Query(query, userID, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []UserRole
	for rows.Next() {
		var role UserRole
		if err := rows.Scan(&role.ID, &role.Name); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if roles == nil {
		roles = []UserRole{}
	}

	return roles, rows.Err()
}

// HasPendingRegistrationInWorkspace reports whether the workspace carried by
// ctx has an unexpired pending registration for this email.
func (aur *AdminUserRepository) HasPendingRegistrationInWorkspace(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := tenancy.QueryRowContext(ctx, aur.db.DB, `
		SELECT EXISTS(
			SELECT 1 FROM pending_registrations
			WHERE workspace_id = $1 AND LOWER(email) = LOWER($2) AND expires_at > NOW()
		)`, []interface{}{email}, &exists)
	if err != nil {
		return false, fmt.Errorf("failed to check pending registration: %w", err)
	}
	return exists, nil
}

// EnsureTenantAdminRoleAssignment makes sure the tenant's primary admin user is mapped to the admin role.
func (aur *AdminUserRepository) EnsureTenantAdminRoleAssignment(workspaceID uuid.UUID) error {
	// Seed admin role, scopes, and permissions per tenant
	adminRoleID, err := NewAdminSeedRepository(aur.db).EnsureAdminRoleAndPermissions(workspaceID)
	if err != nil {
		log.Printf("Warning: Could not ensure admin role/permissions for tenant %s: %v", workspaceID, err)
		return nil
	}

	// Try to find admin users for this tenant by:
	// 1. Matching workspace_id and email with tenants table
	// 2. Or just by workspace_id if the join fails (for OIDC users)
	var adminUserID uuid.UUID
	query := `
		SELECT u.id
		FROM users u
		JOIN workspaces t ON t.workspace_id::text = u.workspace_id::text
		WHERE u.workspace_id::text = $1
		  AND LOWER(u.email) = LOWER(t.email)
		LIMIT 1
	`
	err = aur.db.QueryRow(query, workspaceID.String()).Scan(&adminUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Fallback: try to find any user with this workspace_id (for OIDC registered users)
			fallbackQuery := `
				SELECT id
				FROM users
				WHERE workspace_id::text = $1
				  AND active = true
				ORDER BY created_at ASC
				LIMIT 1
			`
			if err := aur.db.QueryRow(fallbackQuery, workspaceID.String()).Scan(&adminUserID); err != nil {
				if err == sql.ErrNoRows {
					// No users found for this tenant yet, that's okay
					// This is normal for new tenants
					return nil
				}
				// Log error but don't fail - role assignment might have been done during registration
				log.Printf("Warning: Could not locate tenant admin user for tenant %s: %v", workspaceID, err)
				return nil
			}
		} else {
			// Log error but don't fail - role assignment might have been done during registration
			log.Printf("Warning: Error finding tenant admin user for tenant %s: %v", workspaceID, err)
			return nil
		}
	}

	// Assign admin role via role_bindings (user_roles is deprecated)
	// This is now the primary mechanism for role assignment
	if err := aur.ensureAdminRoleBinding(adminUserID, workspaceID, adminRoleID); err != nil {
		// Log warning but don't fail the reconciliation
		log.Printf("Warning: Could not ensure admin role binding for user %s tenant %s: %v", adminUserID, workspaceID, err)
	}

	return nil
}

// ensureAdminRoleBinding creates a tenant-wide role binding for the admin user if missing.
func (aur *AdminUserRepository) ensureAdminRoleBinding(userID, workspaceID, roleID uuid.UUID) error {
	if aur == nil || aur.db == nil {
		return fmt.Errorf("admin user repository not initialized")
	}

	insertQuery := `
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at)
		SELECT $1, $2, $3, $4, NULL, NULL, NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM role_bindings
			WHERE workspace_id = $2
			  AND user_id = $3
			  AND role_id = $4
			  AND scope_type IS NULL
			  AND scope_id IS NULL
		)
	`

	_, err := aur.db.Exec(insertQuery, uuid.New(), workspaceID, userID, roleID)
	if err != nil {
		return fmt.Errorf("create admin role binding: %w", err)
	}

	return nil
}

// CreateAdminUser creates a new admin user in global database
func (aur *AdminUserRepository) CreateAdminUser(user *models.AdminUser) error {
	// Validate that password hash is set for non-synced users
	// Synced users (from AD/Entra ID) authenticate via their provider, so password hash can be empty
	if user.PasswordHash == "" && !user.IsSyncedUser && user.Provider != "ad_sync" && user.Provider != "entra_id" {
		return fmt.Errorf("password hash must be set before creating admin user")
	}

	query := `
		INSERT INTO users (id, email, username, password_hash, name,
			provider, active, temporary_password, temporary_password_expires_at,
			created_at, updated_at, client_id, workspace_id, project_id, workspace_domain)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	now := time.Now()
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	_, err := aur.db.Exec(query,
		user.ID,
		user.Email,
		user.Username,
		user.PasswordHash,
		user.Name,
		user.Provider,
		user.Active,
		user.TemporaryPassword,
		user.TemporaryPasswordExpiresAt,
		user.CreatedAt,
		user.UpdatedAt,
		user.ClientID,
		user.WorkspaceID,
		user.ProjectID,
		user.WorkspaceDomain,
	)

	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	workspaceID := uuid.Nil
	if user.WorkspaceID != nil {
		workspaceID = *user.WorkspaceID
	}

	roleID, err := aur.EnsureAdminRole(workspaceID)
	if err != nil {
		fmt.Printf("WARNING: Failed to ensure admin role for tenant %s: %v\n", workspaceID, err)
		fmt.Printf("WARNING: User created but without admin role - they will not be able to login via /admin/login\n")
		return nil
	}

	// Use role_bindings (user_roles is deprecated)
	bindingID := uuid.New()
	result, err := aur.db.Exec(`
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at, updated_at)
		SELECT $1, $2, $3, $4, NULL, NULL, NOW(), NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM role_bindings WHERE workspace_id = $2 AND user_id = $3 AND role_id = $4 AND scope_type IS NULL
		)
	`, bindingID, workspaceID, user.ID, roleID)
	if err != nil {
		fmt.Printf("WARNING: Failed to assign admin role to user %s: %v\n", user.ID, err)
		fmt.Printf("WARNING: User created but without admin role - they will not be able to login via /admin/login\n")
	} else {
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			fmt.Printf("WARNING: Admin role not assigned to user %s - admin role may already exist\n", user.ID)
		} else {
			fmt.Printf("INFO: Admin role successfully assigned to user %s\n", user.ID)
		}
	}

	return nil
}

// ResolveAdminForPasswordReset finds the one admin account a pre-auth
// password reset applies to. Emails are unique per workspace, not globally,
// so the first match by email could be another workspace's admin (AS-038):
// with a workspace domain the lookup is (domain, email); without one it
// succeeds only when the email is an admin in exactly one workspace and
// returns ErrAmbiguousAdminEmail otherwise.
func (aur *AdminUserRepository) ResolveAdminForPasswordReset(email, workspaceDomain string) (*models.AdminUser, error) {
	if strings.TrimSpace(workspaceDomain) != "" {
		return aur.GetAdminUserByEmailAndWorkspaceDomain(email, workspaceDomain)
	}
	// TENANT-EXEMPT: pre-auth flow with no workspace yet; it only counts
	// the accounts this email has, to refuse an ambiguous reset.
	var n int
	if err := aur.db.QueryRow(`
		SELECT COUNT(DISTINCT u.id)
		  FROM users u
		  JOIN role_bindings rb ON rb.user_id = u.id AND rb.workspace_id = u.workspace_id
		  JOIN roles r ON r.id = rb.role_id
		  JOIN workspace_memberships wm ON wm.user_id = u.id AND wm.workspace_id = u.workspace_id
		  JOIN roles workspace_role ON workspace_role.id = wm.role_id
		 WHERE LOWER(u.email) = LOWER($1)
		   AND u.active = true
		   AND u.deleted_at IS NULL
		   AND LOWER(r.name) = 'admin'
		   AND wm.status = 'active'
		   AND LOWER(workspace_role.name) = 'admin'`, email).Scan(&n); err != nil {
		return nil, fmt.Errorf("failed to count admin accounts: %w", err)
	}
	switch n {
	case 0:
		return nil, sql.ErrNoRows
	case 1:
		return aur.GetAdminUserByEmail(email)
	default:
		return nil, ErrAmbiguousAdminEmail
	}
}

// GetAdminUserByEmail retrieves an admin user by email (case-insensitive).
// TENANT-EXEMPT: the first match across workspaces. Kept for the pre-auth
// admin login without a workspace domain; anything that changes an account
// must use a (workspace, email) lookup (AS-038).
// Uses role_bindings for role assignments (user_roles is deprecated)
func (aur *AdminUserRepository) GetAdminUserByEmail(email string) (*models.AdminUser, error) {
	query := `
		SELECT u.id, u.email, u.username, u.password_hash, COALESCE(u.name, '') AS name,
			u.client_id, u.workspace_id, u.project_id, COALESCE(u.workspace_domain, '') AS workspace_domain, COALESCE(u.provider, '') AS provider,
			u.provider_id, COALESCE(u.provider_data::text, '{}') AS provider_data,
			u.avatar_url, u.active, u.mfa_enabled,
			COALESCE(u.mfa_method, ARRAY[]::text[]) AS mfa_method, u.mfa_default_method,
			u.mfa_enrolled_at, u.mfa_verified,
			u.external_id, u.sync_source,
			u.last_sync_at, u.is_synced_user,
			u.last_login, u.temporary_password, u.temporary_password_expires_at,
			u.created_at, u.updated_at
		FROM users u
		JOIN role_bindings rb ON u.id = rb.user_id
		JOIN roles r ON rb.role_id = r.id
		JOIN workspace_memberships wm ON wm.user_id = u.id AND wm.workspace_id = u.workspace_id
		JOIN roles workspace_role ON workspace_role.id = wm.role_id
		WHERE LOWER(u.email) = LOWER($1)
		  AND u.active = true
		  AND u.deleted_at IS NULL
		  AND LOWER(r.name) = 'admin'
		  AND wm.status = 'active'
		  AND LOWER(workspace_role.name) = 'admin'
	`

	fmt.Printf("UserFlow:Debug:: Query to get user for email %s: %s\n", email, strings.ReplaceAll(query, "\n", " "))
	var (
		username              sql.NullString
		name                  sql.NullString
		clientIDStr           sql.NullString
		workspaceIDStr           sql.NullString
		projectIDStr          sql.NullString
		workspaceDomain          sql.NullString
		provider              sql.NullString
		providerID            sql.NullString
		providerData          sql.NullString
		avatarURL             sql.NullString
		mfaDefaultMethod      sql.NullString
		mfaEnrolledAt         sql.NullTime
		externalID            sql.NullString
		syncSource            sql.NullString
		lastSyncAt            sql.NullTime
		lastLogin             sql.NullTime
		tempPasswordExpiresAt sql.NullTime
		mfaMethodRaw          interface{} // Scan as interface{} to handle NULL and array
	)
	var (
		clientID    *uuid.UUID
		workspaceID *uuid.UUID
		projectID   *uuid.UUID
	)
	var user models.AdminUser

	err := aur.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&username,
		&user.PasswordHash,
		&name,
		&clientIDStr,
		&workspaceIDStr,
		&projectIDStr,
		&workspaceDomain,
		&provider,
		&providerID,
		&providerData,
		&avatarURL,
		&user.Active,
		&user.MFAEnabled,
		&mfaMethodRaw,
		&mfaDefaultMethod,
		&mfaEnrolledAt,
		&user.MFAVerified,
		&externalID,
		&syncSource,
		&lastSyncAt,
		&user.IsSyncedUser,
		&lastLogin,
		&user.TemporaryPassword,
		&tempPasswordExpiresAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get admin user by email: %w", err)
	}

	// Parse mfa_method array
	user.MFAMethod = []string{}
	if mfaMethodRaw != nil {
		// Try to use pq.Array to scan the value
		var mfaArray pq.StringArray
		if err := mfaArray.Scan(mfaMethodRaw); err == nil {
			user.MFAMethod = []string(mfaArray)
		} else {
			// Fallback: if it's a string representation, parse it manually
			if strVal, ok := mfaMethodRaw.(string); ok && strVal != "" && strVal != "{}" {
				// Remove braces and split by comma
				strVal = strings.Trim(strVal, "{}")
				if strVal != "" {
					user.MFAMethod = strings.Split(strVal, ",")
				}
			}
		}
	}

	// Assign nullable fields
	if username.Valid {
		user.Username = username.String
	}
	if name.Valid {
		user.Name = name.String
	}
	if workspaceDomain.Valid {
		user.WorkspaceDomain = workspaceDomain.String
	}
	if provider.Valid {
		user.Provider = provider.String
	}
	if providerID.Valid {
		user.ProviderID = providerID.String
	}
	// ProviderData is stored as JSONB; use raw bytes when available
	if providerData.Valid {
		user.ProviderData = []byte(providerData.String)
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if mfaDefaultMethod.Valid {
		user.MFADefaultMethod = mfaDefaultMethod.String
	}
	if externalID.Valid {
		user.ExternalID = externalID.String
	}
	if syncSource.Valid {
		user.SyncSource = syncSource.String
	}
	if mfaEnrolledAt.Valid {
		ts := mfaEnrolledAt.Time
		user.MFAEnrolledAt = &ts
	}
	if lastSyncAt.Valid {
		ts := lastSyncAt.Time
		user.LastSyncAt = &ts
	}
	if lastLogin.Valid {
		ts := lastLogin.Time
		user.LastLogin = &ts
	}
	if tempPasswordExpiresAt.Valid {
		ts := tempPasswordExpiresAt.Time
		user.TemporaryPasswordExpiresAt = &ts
	}

	if clientIDStr.Valid && strings.TrimSpace(clientIDStr.String) != "" {
		if parsed, err := uuid.Parse(clientIDStr.String); err == nil {
			clientID = &parsed
		}
	}
	if workspaceIDStr.Valid && strings.TrimSpace(workspaceIDStr.String) != "" {
		if parsed, err := uuid.Parse(workspaceIDStr.String); err == nil {
			workspaceID = &parsed
		}
	}
	if projectIDStr.Valid && strings.TrimSpace(projectIDStr.String) != "" {
		if parsed, err := uuid.Parse(projectIDStr.String); err == nil {
			projectID = &parsed
		}
	}

	user.ClientID = clientID
	user.WorkspaceID = workspaceID
	user.ProjectID = projectID

	return &user, nil
}

// GetAdminUserByEmailAndWorkspaceDomain retrieves an admin user by email and workspace_domain (case-insensitive)
// This method enforces tenant isolation by requiring the user's workspace_domain to match
// Uses role_bindings for role assignments (user_roles is deprecated)
// Only active workspace admins may enter the console. Invited users become
// eligible after their membership and admin binding are active.
func (aur *AdminUserRepository) GetAdminUserByEmailAndWorkspaceDomain(email, workspaceDomain string) (*models.AdminUser, error) {
	query := `
		SELECT u.id, u.email, u.username, u.password_hash, COALESCE(u.name, '') AS name,
			u.client_id, u.workspace_id, u.project_id, COALESCE(u.workspace_domain, '') AS workspace_domain, COALESCE(u.provider, '') AS provider,
			u.provider_id, COALESCE(u.provider_data::text, '{}') AS provider_data,
			u.avatar_url, u.active, u.mfa_enabled,
			COALESCE(u.mfa_method, ARRAY[]::text[]) AS mfa_method, u.mfa_default_method,
			u.mfa_enrolled_at, u.mfa_verified,
			u.external_id, u.sync_source,
			u.last_sync_at, u.is_synced_user,
			u.last_login, u.temporary_password, u.temporary_password_expires_at,
			u.created_at, u.updated_at
		FROM users u
		JOIN role_bindings rb ON u.id = rb.user_id
		JOIN roles r ON rb.role_id = r.id
		JOIN workspace_memberships wm ON wm.user_id = u.id AND wm.workspace_id = u.workspace_id
		JOIN roles workspace_role ON workspace_role.id = wm.role_id
		WHERE LOWER(u.email) = LOWER($1)
		  AND LOWER(u.workspace_domain) = LOWER($2)
		  AND u.active = true
		  AND u.deleted_at IS NULL
		  AND LOWER(r.name) = 'admin'
		  AND wm.status = 'active'
		  AND LOWER(workspace_role.name) = 'admin'
	`

	fmt.Printf("UserFlow:Debug:: Query to get workspace admin for email %s, workspace_domain %s\n", email, workspaceDomain)
	return aur.scanAdminUserFromQuery(query, email, workspaceDomain)
}

// scanAdminUserFromQuery is a helper to scan admin user from a query
func (aur *AdminUserRepository) scanAdminUserFromQuery(query string, args ...interface{}) (*models.AdminUser, error) {
	var (
		username              sql.NullString
		name                  sql.NullString
		clientIDStr           sql.NullString
		workspaceIDStr           sql.NullString
		projectIDStr          sql.NullString
		workspaceDomain          sql.NullString
		provider              sql.NullString
		providerID            sql.NullString
		providerData          sql.NullString
		avatarURL             sql.NullString
		mfaDefaultMethod      sql.NullString
		mfaEnrolledAt         sql.NullTime
		externalID            sql.NullString
		syncSource            sql.NullString
		lastSyncAt            sql.NullTime
		lastLogin             sql.NullTime
		tempPasswordExpiresAt sql.NullTime
		mfaMethodRaw          interface{}
	)
	var (
		clientID    *uuid.UUID
		workspaceID *uuid.UUID
		projectID   *uuid.UUID
	)
	var user models.AdminUser

	err := aur.db.QueryRow(query, args...).Scan(
		&user.ID,
		&user.Email,
		&username,
		&user.PasswordHash,
		&name,
		&clientIDStr,
		&workspaceIDStr,
		&projectIDStr,
		&workspaceDomain,
		&provider,
		&providerID,
		&providerData,
		&avatarURL,
		&user.Active,
		&user.MFAEnabled,
		&mfaMethodRaw,
		&mfaDefaultMethod,
		&mfaEnrolledAt,
		&user.MFAVerified,
		&externalID,
		&syncSource,
		&lastSyncAt,
		&user.IsSyncedUser,
		&lastLogin,
		&user.TemporaryPassword,
		&tempPasswordExpiresAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get admin user: %w", err)
	}

	// Parse mfa_method array
	user.MFAMethod = []string{}
	if mfaMethodRaw != nil {
		var mfaArray pq.StringArray
		if err := mfaArray.Scan(mfaMethodRaw); err == nil {
			user.MFAMethod = []string(mfaArray)
		} else if strVal, ok := mfaMethodRaw.(string); ok && strVal != "" && strVal != "{}" {
			strVal = strings.Trim(strVal, "{}")
			if strVal != "" {
				user.MFAMethod = strings.Split(strVal, ",")
			}
		}
	}

	// Assign nullable fields
	if username.Valid {
		user.Username = username.String
	}
	if name.Valid {
		user.Name = name.String
	}
	if workspaceDomain.Valid {
		user.WorkspaceDomain = workspaceDomain.String
	}
	if provider.Valid {
		user.Provider = provider.String
	}
	if providerID.Valid {
		user.ProviderID = providerID.String
	}
	if providerData.Valid {
		user.ProviderData = []byte(providerData.String)
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if mfaDefaultMethod.Valid {
		user.MFADefaultMethod = mfaDefaultMethod.String
	}
	if externalID.Valid {
		user.ExternalID = externalID.String
	}
	if syncSource.Valid {
		user.SyncSource = syncSource.String
	}
	if mfaEnrolledAt.Valid {
		ts := mfaEnrolledAt.Time
		user.MFAEnrolledAt = &ts
	}
	if lastSyncAt.Valid {
		ts := lastSyncAt.Time
		user.LastSyncAt = &ts
	}
	if lastLogin.Valid {
		ts := lastLogin.Time
		user.LastLogin = &ts
	}
	if tempPasswordExpiresAt.Valid {
		ts := tempPasswordExpiresAt.Time
		user.TemporaryPasswordExpiresAt = &ts
	}

	if clientIDStr.Valid && strings.TrimSpace(clientIDStr.String) != "" {
		if parsed, err := uuid.Parse(clientIDStr.String); err == nil {
			clientID = &parsed
		}
	}
	if workspaceIDStr.Valid && strings.TrimSpace(workspaceIDStr.String) != "" {
		if parsed, err := uuid.Parse(workspaceIDStr.String); err == nil {
			workspaceID = &parsed
		}
	}
	if projectIDStr.Valid && strings.TrimSpace(projectIDStr.String) != "" {
		if parsed, err := uuid.Parse(projectIDStr.String); err == nil {
			projectID = &parsed
		}
	}

	user.ClientID = clientID
	user.WorkspaceID = workspaceID
	user.ProjectID = projectID

	return &user, nil
}

// UpdateAdminUser updates an admin user by id.
// TENANT-EXEMPT: pre-auth flows (login bookkeeping, password reset) that
// already resolved the account; request handlers use UpdateAdminUserInWorkspace.
func (aur *AdminUserRepository) UpdateAdminUser(id uuid.UUID, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}

	query := "UPDATE users SET "
	args := []interface{}{}
	argCount := 1

	for field, value := range updates {
		query += field + " = $" + fmt.Sprintf("%d", argCount) + ", "
		args = append(args, value)
		argCount++
	}

	query += "updated_at = $" + fmt.Sprintf("%d", argCount)
	args = append(args, time.Now())
	argCount++

	query += " WHERE id = $" + fmt.Sprintf("%d", argCount)
	args = append(args, id)

	_, err := aur.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update admin user: %w", err)
	}

	return nil
}

// UpdateLastLogin updates the last login time for an admin user
func (aur *AdminUserRepository) UpdateLastLogin(id uuid.UUID) error {
	query := "UPDATE users SET last_login = $1, updated_at = $1 WHERE id = $2"

	_, err := aur.db.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// VerifyPassword verifies an admin user's password
func (aur *AdminUserRepository) VerifyPassword(email, password string) (*models.AdminUser, error) {
	user, err := aur.GetAdminUserByEmail(email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// GetAdminUserByEmailAndTenant retrieves an admin user by email and tenant ID (case-insensitive)
// This method respects the new composite unique constraint (email, workspace_id)
// Uses role_bindings for role assignments (user_roles is deprecated)
func (aur *AdminUserRepository) GetAdminUserByEmailAndTenant(email string, workspaceID uuid.UUID) (*models.AdminUser, error) {
	query := `
		SELECT u.id, u.email, u.username, u.password_hash, COALESCE(u.name, '') AS name,
			u.client_id, u.workspace_id, u.project_id, COALESCE(u.workspace_domain, '') AS workspace_domain, COALESCE(u.provider, '') AS provider,
			u.provider_id, COALESCE(u.provider_data::text, '{}') AS provider_data,
			u.avatar_url, u.active, u.mfa_enabled,
			COALESCE(u.mfa_method, ARRAY[]::text[]) AS mfa_method, u.mfa_default_method,
			u.mfa_enrolled_at, u.mfa_verified,
			u.external_id, u.sync_source,
			u.last_sync_at, u.is_synced_user,
			u.last_login, u.temporary_password, u.temporary_password_expires_at,
			u.created_at, u.updated_at
		FROM users u
		JOIN role_bindings rb ON u.id = rb.user_id
		JOIN roles r ON rb.role_id = r.id
		JOIN workspace_memberships wm ON wm.user_id = u.id AND wm.workspace_id = u.workspace_id
		JOIN roles workspace_role ON workspace_role.id = wm.role_id
		WHERE LOWER(u.email) = LOWER($1)
		  AND u.workspace_id = $2
		  AND u.active = true
		  AND u.deleted_at IS NULL
		  AND LOWER(r.name) = 'admin'
		  AND wm.status = 'active'
		  AND LOWER(workspace_role.name) = 'admin'
	`

	var (
		username              sql.NullString
		name                  sql.NullString
		clientIDStr           sql.NullString
		workspaceIDStr           sql.NullString
		projectIDStr          sql.NullString
		workspaceDomain          sql.NullString
		provider              sql.NullString
		providerID            sql.NullString
		providerData          sql.NullString
		avatarURL             sql.NullString
		mfaDefaultMethod      sql.NullString
		mfaEnrolledAt         sql.NullTime
		externalID            sql.NullString
		syncSource            sql.NullString
		lastSyncAt            sql.NullTime
		lastLogin             sql.NullTime
		tempPasswordExpiresAt sql.NullTime
		mfaMethodRaw          interface{}
	)
	var (
		clientID       *uuid.UUID
		workspaceIDParsed *uuid.UUID
		projectID      *uuid.UUID
	)
	var user models.AdminUser

	err := aur.db.QueryRow(query, email, workspaceID).Scan(
		&user.ID,
		&user.Email,
		&username,
		&user.PasswordHash,
		&name,
		&clientIDStr,
		&workspaceIDStr,
		&projectIDStr,
		&workspaceDomain,
		&provider,
		&providerID,
		&providerData,
		&avatarURL,
		&user.Active,
		&user.MFAEnabled,
		&mfaMethodRaw,
		&mfaDefaultMethod,
		&mfaEnrolledAt,
		&user.MFAVerified,
		&externalID,
		&syncSource,
		&lastSyncAt,
		&user.IsSyncedUser,
		&lastLogin,
		&user.TemporaryPassword,
		&tempPasswordExpiresAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get admin user by email and tenant: %w", err)
	}

	// Parse mfa_method array
	user.MFAMethod = []string{}
	if mfaMethodRaw != nil {
		var mfaArray pq.StringArray
		if err := mfaArray.Scan(mfaMethodRaw); err == nil {
			user.MFAMethod = []string(mfaArray)
		} else {
			if strVal, ok := mfaMethodRaw.(string); ok && strVal != "" && strVal != "{}" {
				strVal = strings.Trim(strVal, "{}")
				if strVal != "" {
					user.MFAMethod = strings.Split(strVal, ",")
				}
			}
		}
	}

	// Assign nullable fields
	if username.Valid {
		user.Username = username.String
	}
	if name.Valid {
		user.Name = name.String
	}
	if workspaceDomain.Valid {
		user.WorkspaceDomain = workspaceDomain.String
	}
	if provider.Valid {
		user.Provider = provider.String
	}
	if providerID.Valid {
		user.ProviderID = providerID.String
	}
	if providerData.Valid {
		user.ProviderData = []byte(providerData.String)
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if mfaDefaultMethod.Valid {
		user.MFADefaultMethod = mfaDefaultMethod.String
	}
	if externalID.Valid {
		user.ExternalID = externalID.String
	}
	if syncSource.Valid {
		user.SyncSource = syncSource.String
	}
	if mfaEnrolledAt.Valid {
		ts := mfaEnrolledAt.Time
		user.MFAEnrolledAt = &ts
	}
	if lastSyncAt.Valid {
		ts := lastSyncAt.Time
		user.LastSyncAt = &ts
	}
	if lastLogin.Valid {
		ts := lastLogin.Time
		user.LastLogin = &ts
	}
	if tempPasswordExpiresAt.Valid {
		ts := tempPasswordExpiresAt.Time
		user.TemporaryPasswordExpiresAt = &ts
	}

	if clientIDStr.Valid && strings.TrimSpace(clientIDStr.String) != "" {
		if parsed, err := uuid.Parse(clientIDStr.String); err == nil {
			clientID = &parsed
		}
	}
	if workspaceIDStr.Valid && strings.TrimSpace(workspaceIDStr.String) != "" {
		if parsed, err := uuid.Parse(workspaceIDStr.String); err == nil {
			workspaceIDParsed = &parsed
		}
	}
	if projectIDStr.Valid && strings.TrimSpace(projectIDStr.String) != "" {
		if parsed, err := uuid.Parse(projectIDStr.String); err == nil {
			projectID = &parsed
		}
	}

	user.ClientID = clientID
	user.WorkspaceID = workspaceIDParsed
	user.ProjectID = projectID

	return &user, nil
}

// GetAdminUserWithProviders retrieves an admin user by email with available auth providers
// Returns user info and list of configured providers (email, google, etc.)
func (aur *AdminUserRepository) GetAdminUserWithProviders(email string) (*models.AdminUser, []string, error) {
	query := `
		SELECT u.id, u.email, u.username, u.password_hash, COALESCE(u.name, '') AS name,
			u.client_id, u.workspace_id, u.project_id, COALESCE(u.workspace_domain, '') AS workspace_domain, COALESCE(u.provider, '') AS provider,
			u.provider_id, COALESCE(u.provider_data::text, '{}') AS provider_data,
			u.avatar_url, u.active, u.mfa_enabled,
			COALESCE(u.mfa_method, ARRAY[]::text[]) AS mfa_method, u.mfa_default_method,
			u.mfa_enrolled_at, u.mfa_verified,
			u.external_id, u.sync_source,
			u.last_sync_at, u.is_synced_user,
			u.last_login, u.temporary_password, u.temporary_password_expires_at,
			u.created_at, u.updated_at
		FROM users u
		JOIN role_bindings rb ON u.id = rb.user_id
		JOIN roles r ON rb.role_id = r.id
		JOIN workspace_memberships wm ON wm.user_id = u.id AND wm.workspace_id = u.workspace_id
		JOIN roles workspace_role ON workspace_role.id = wm.role_id
		WHERE LOWER(u.email) = LOWER($1)
		  AND u.active = true
		  AND u.deleted_at IS NULL
		  AND LOWER(r.name) = 'admin'
		  AND wm.status = 'active'
		  AND LOWER(workspace_role.name) = 'admin'
	`

	var (
		username              sql.NullString
		name                  sql.NullString
		clientIDStr           sql.NullString
		workspaceIDStr           sql.NullString
		projectIDStr          sql.NullString
		workspaceDomain          sql.NullString
		provider              sql.NullString
		providerID            sql.NullString
		providerData          sql.NullString
		avatarURL             sql.NullString
		mfaDefaultMethod      sql.NullString
		mfaEnrolledAt         sql.NullTime
		externalID            sql.NullString
		syncSource            sql.NullString
		lastSyncAt            sql.NullTime
		lastLogin             sql.NullTime
		tempPasswordExpiresAt sql.NullTime
		mfaMethodRaw          interface{}
	)
	var (
		clientID    *uuid.UUID
		workspaceID *uuid.UUID
		projectID   *uuid.UUID
	)
	var user models.AdminUser

	err := aur.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&username,
		&user.PasswordHash,
		&name,
		&clientIDStr,
		&workspaceIDStr,
		&projectIDStr,
		&workspaceDomain,
		&provider,
		&providerID,
		&providerData,
		&avatarURL,
		&user.Active,
		&user.MFAEnabled,
		&mfaMethodRaw,
		&mfaDefaultMethod,
		&mfaEnrolledAt,
		&user.MFAVerified,
		&externalID,
		&syncSource,
		&lastSyncAt,
		&user.IsSyncedUser,
		&lastLogin,
		&user.TemporaryPassword,
		&tempPasswordExpiresAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// User doesn't exist, return empty
			return nil, []string{"email"}, nil
		}
		return nil, nil, fmt.Errorf("failed to get admin user: %w", err)
	}

	// Parse mfa_method array
	user.MFAMethod = []string{}
	if mfaMethodRaw != nil {
		var mfaArray pq.StringArray
		if err := mfaArray.Scan(mfaMethodRaw); err == nil {
			user.MFAMethod = []string(mfaArray)
		} else {
			if strVal, ok := mfaMethodRaw.(string); ok && strVal != "" && strVal != "{}" {
				strVal = strings.Trim(strVal, "{}")
				if strVal != "" {
					user.MFAMethod = strings.Split(strVal, ",")
				}
			}
		}
	}

	// Assign nullable fields
	if username.Valid {
		user.Username = username.String
	}
	if name.Valid {
		user.Name = name.String
	}
	if workspaceDomain.Valid {
		user.WorkspaceDomain = workspaceDomain.String
	}
	if provider.Valid {
		user.Provider = provider.String
	}
	if providerID.Valid {
		user.ProviderID = providerID.String
	}
	if providerData.Valid {
		user.ProviderData = []byte(providerData.String)
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	if mfaDefaultMethod.Valid {
		user.MFADefaultMethod = mfaDefaultMethod.String
	}
	if externalID.Valid {
		user.ExternalID = externalID.String
	}
	if syncSource.Valid {
		user.SyncSource = syncSource.String
	}
	if mfaEnrolledAt.Valid {
		ts := mfaEnrolledAt.Time
		user.MFAEnrolledAt = &ts
	}
	if lastSyncAt.Valid {
		ts := lastSyncAt.Time
		user.LastSyncAt = &ts
	}
	if lastLogin.Valid {
		ts := lastLogin.Time
		user.LastLogin = &ts
	}
	if tempPasswordExpiresAt.Valid {
		ts := tempPasswordExpiresAt.Time
		user.TemporaryPasswordExpiresAt = &ts
	}

	if clientIDStr.Valid && strings.TrimSpace(clientIDStr.String) != "" {
		if parsed, err := uuid.Parse(clientIDStr.String); err == nil {
			clientID = &parsed
		}
	}
	if workspaceIDStr.Valid && strings.TrimSpace(workspaceIDStr.String) != "" {
		if parsed, err := uuid.Parse(workspaceIDStr.String); err == nil {
			workspaceID = &parsed
		}
	}
	if projectIDStr.Valid && strings.TrimSpace(projectIDStr.String) != "" {
		if parsed, err := uuid.Parse(projectIDStr.String); err == nil {
			projectID = &parsed
		}
	}

	user.ClientID = clientID
	user.WorkspaceID = workspaceID
	user.ProjectID = projectID

	// Get configured providers for this tenant/client
	providers := []string{"email"} // Email is always available

	// Check if user has OAuth providers configured
	if user.Provider != "" && user.Provider != "email" {
		providers = append(providers, user.Provider)
	}

	// Query tenant configuration for available providers
	if user.WorkspaceID != nil {
		providerQuery := `
			SELECT DISTINCT provider_name
			FROM oauth_configs
			WHERE workspace_id = $1 AND enabled = true
		`
		rows, err := aur.db.Query(providerQuery, user.WorkspaceID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var providerName string
				if err := rows.Scan(&providerName); err == nil {
					// Add provider if not already in list
					found := false
					for _, p := range providers {
						if p == providerName {
							found = true
							break
						}
					}
					if !found {
						providers = append(providers, providerName)
					}
				}
			}
		}
	}

	return &user, providers, nil
}

// GetAdminRoles fetches the role names for an admin user in a specific tenant
// Queries role_bindings -> roles to get role names
func (aur *AdminUserRepository) GetAdminRoles(userID uuid.UUID, workspaceID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT r.name
		FROM role_bindings rb
		JOIN roles r ON rb.role_id = r.id
		WHERE rb.user_id = $1 
		  AND rb.workspace_id = $2
		ORDER BY r.name
	`

	rows, err := aur.db.Query(query, userID, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query admin roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			return nil, fmt.Errorf("failed to scan role name: %w", err)
		}
		roles = append(roles, roleName)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}
