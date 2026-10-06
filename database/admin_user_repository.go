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

// GetUserRoles returns the roles a user holds in the workspace carried by ctx.
func (aur *AdminUserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]UserRole, error) {
	rows, err := tenancy.QueryContext(ctx, aur.db.DB, `
		SELECT DISTINCT r.id, r.name
		FROM roles r
		JOIN role_bindings rb ON r.id = rb.role_id
		WHERE rb.workspace_id = $1 AND rb.user_id = $2
		ORDER BY r.name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	roles := []UserRole{}
	for rows.Next() {
		var role UserRole
		if err := rows.Scan(&role.ID, &role.Name); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
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

// EnsureTenantAdminRoleAssignment makes sure the workspace carried by ctx has
// its admin role (bound to the permission catalog) and that the workspace's
// owner holds it. It runs under row-level security for that workspace.
//
// This used to look the owner up through a workspaces.workspace_id column
// that does not exist, so the lookup always failed and the binding was never
// reconciled; and its fallback would have made the oldest active user an
// admin. The owner is now workspaces.owner_user_id, and nobody else.
func (aur *AdminUserRepository) EnsureTenantAdminRoleAssignment(ctx context.Context) error {
	adminRoleID, err := NewAdminSeedRepository(aur.db).EnsureAdminRoleAndPermissions(ctx)
	if err != nil {
		log.Printf("Warning: Could not ensure admin role/permissions: %v", err)
		return nil
	}
	// workspaces is the tenant registry (no workspace_id column); the owner
	// must also be a user of the same workspace.
	if _, err := tenancy.ExecContext(ctx, aur.db.DB, `
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at)
		SELECT $2, $1, u.id, $3, NULL, NULL, NOW()
		  FROM workspaces w
		  JOIN users u ON u.id = w.owner_user_id AND u.workspace_id = w.id
		 WHERE w.id = $1 AND u.workspace_id = $1 AND u.active = true
		   AND NOT EXISTS (
			SELECT 1 FROM role_bindings
			 WHERE workspace_id = $1 AND user_id = u.id AND role_id = $3
			   AND scope_type IS NULL AND scope_id IS NULL)
	`, uuid.New(), adminRoleID); err != nil {
		log.Printf("Warning: Could not ensure admin role binding for the workspace owner: %v", err)
	}
	return nil
}

// CreateAdminUser creates an admin user in the workspace carried by ctx and
// binds it to that workspace's admin role. The user's workspace must be the
// context's.
func (aur *AdminUserRepository) CreateAdminUser(ctx context.Context, user *models.AdminUser) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	if user.WorkspaceID == nil || *user.WorkspaceID != ws {
		return fmt.Errorf("admin user must belong to the caller's workspace")
	}
	// Validate that password hash is set for non-synced users
	// Synced users (from AD/Entra ID) authenticate via their provider, so password hash can be empty
	if user.PasswordHash == "" && !user.IsSyncedUser && user.Provider != "ad_sync" && user.Provider != "entra_id" {
		return fmt.Errorf("password hash must be set before creating admin user")
	}

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

	// $1 is the context's workspace; row-level security checks the row.
	err = tenancy.WithTx(ctx, aur.db.DB, ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
		INSERT INTO users (workspace_id, id, email, username, password_hash, name,
			provider, active, temporary_password, temporary_password_expires_at,
			created_at, updated_at, client_id, project_id, workspace_domain)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`,
			ws,
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
			user.ProjectID,
			user.WorkspaceDomain,
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	roleID, err := NewAdminSeedRepository(aur.db).EnsureAdminRoleAndPermissions(ctx)
	if err != nil {
		log.Printf("WARNING: Failed to ensure admin role for workspace %s: %v", ws, err)
		log.Printf("WARNING: User created but without admin role - they will not be able to login via /admin/login")
		return nil
	}

	// Use role_bindings (user_roles is deprecated)
	result, err := tenancy.ExecContext(ctx, aur.db.DB, `
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at, updated_at)
		SELECT $2, $1, $3, $4, NULL, NULL, NOW(), NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM role_bindings WHERE workspace_id = $1 AND user_id = $3 AND role_id = $4 AND scope_type IS NULL
		)
	`, uuid.New(), user.ID, roleID)
	if err != nil {
		log.Printf("WARNING: Failed to assign admin role to user %s: %v", user.ID, err)
		log.Printf("WARNING: User created but without admin role - they will not be able to login via /admin/login")
	} else if n, _ := result.RowsAffected(); n == 0 {
		log.Printf("WARNING: Admin role not assigned to user %s - admin role may already exist", user.ID)
	} else {
		log.Printf("INFO: Admin role successfully assigned to user %s", user.ID)
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

// adminLoginColumns is the column list scanAdminUser expects.
const adminLoginColumns = `
		SELECT u.id, u.email, u.username, u.password_hash, COALESCE(u.name, '') AS name,
			u.client_id, u.workspace_id, u.project_id, COALESCE(u.workspace_domain, '') AS workspace_domain, COALESCE(u.provider, '') AS provider,
			u.provider_id, COALESCE(u.provider_data::text, '{}') AS provider_data,
			u.avatar_url, u.active, u.mfa_enabled,
			COALESCE(u.mfa_method, ARRAY[]::text[]) AS mfa_method, u.mfa_default_method,
			u.mfa_enrolled_at, u.mfa_verified,
			u.external_id, u.sync_source,
			u.last_sync_at, u.is_synced_user,
			u.last_login, u.temporary_password, u.temporary_password_expires_at,
			u.created_at, u.updated_at`

// activeConsoleAdmin joins and filters u to active console admins: an admin
// role binding and an active admin membership in the user's own workspace.
const activeConsoleAdmin = `
		FROM users u
		JOIN role_bindings rb ON u.id = rb.user_id
		JOIN roles r ON rb.role_id = r.id
		JOIN workspace_memberships wm ON wm.user_id = u.id AND wm.workspace_id = u.workspace_id
		JOIN roles workspace_role ON workspace_role.id = wm.role_id
		WHERE u.active = true
		  AND u.deleted_at IS NULL
		  AND LOWER(r.name) = 'admin'
		  AND wm.status = 'active'
		  AND LOWER(workspace_role.name) = 'admin'`

// GetAdminUserByEmail retrieves an active console admin by email
// (case-insensitive): the first match across workspaces. It serves the
// pre-auth admin login without a workspace domain; anything that changes an
// account must use a (workspace, email) lookup (AS-038).
func (aur *AdminUserRepository) GetAdminUserByEmail(email string) (*models.AdminUser, error) {
	// TENANT-EXEMPT: pre-auth sign-in, no workspace is known yet.
	query := adminLoginColumns + activeConsoleAdmin + `
		  AND LOWER(u.email) = LOWER($1)`
	return scanAdminUser(func(dest ...interface{}) error {
		return aur.db.QueryRow(query, email).Scan(dest...)
	})
}

// GetAdminUserByEmailAndWorkspaceDomain retrieves an active console admin by
// email within the workspace that owns workspaceDomain (case-insensitive).
func (aur *AdminUserRepository) GetAdminUserByEmailAndWorkspaceDomain(email, workspaceDomain string) (*models.AdminUser, error) {
	// TENANT-EXEMPT: pre-auth sign-in; the workspace is chosen by its domain.
	query := adminLoginColumns + activeConsoleAdmin + `
		  AND LOWER(u.email) = LOWER($1)
		  AND LOWER(u.workspace_domain) = LOWER($2)`
	return scanAdminUser(func(dest ...interface{}) error {
		return aur.db.QueryRow(query, email, workspaceDomain).Scan(dest...)
	})
}

// GetAdminUserByEmailAndTenant retrieves an active console admin by email in
// the workspace carried by ctx. No such admin is sql.ErrNoRows.
func (aur *AdminUserRepository) GetAdminUserByEmailAndTenant(ctx context.Context, email string) (*models.AdminUser, error) {
	query := adminLoginColumns + activeConsoleAdmin + `
		  AND u.workspace_id = $1
		  AND LOWER(u.email) = LOWER($2)`
	user, err := scanAdminUser(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, aur.db.DB, query, []interface{}{email}, dest...)
	})
	if errors.Is(err, tenancy.ErrNotFound) {
		return nil, sql.ErrNoRows
	}
	return user, err
}

// scanAdminUser scans one adminLoginColumns row through scan.
func scanAdminUser(scan func(dest ...interface{}) error) (*models.AdminUser, error) {
	var (
		username              sql.NullString
		name                  sql.NullString
		clientIDStr           sql.NullString
		workspaceIDStr        sql.NullString
		projectIDStr          sql.NullString
		workspaceDomain       sql.NullString
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
	var user models.AdminUser

	err := scan(
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
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, tenancy.ErrNotFound) {
			return nil, err
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

	user.Username = username.String
	user.Name = name.String
	user.WorkspaceDomain = workspaceDomain.String
	user.Provider = provider.String
	user.ProviderID = providerID.String
	if providerData.Valid {
		user.ProviderData = []byte(providerData.String)
	}
	user.AvatarURL = avatarURL.String
	user.MFADefaultMethod = mfaDefaultMethod.String
	user.ExternalID = externalID.String
	user.SyncSource = syncSource.String
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
	user.ClientID = parseNullUUID(clientIDStr)
	user.WorkspaceID = parseNullUUID(workspaceIDStr)
	user.ProjectID = parseNullUUID(projectIDStr)

	return &user, nil
}

func parseNullUUID(s sql.NullString) *uuid.UUID {
	if !s.Valid || strings.TrimSpace(s.String) == "" {
		return nil
	}
	parsed, err := uuid.Parse(s.String)
	if err != nil {
		return nil
	}
	return &parsed
}

// UpdateAdminUser updates an admin user by id, for the pre-auth sign-in and
// password-reset flows that already resolved the account. Request handlers
// use UpdateAdminUserInWorkspace. Column names come from the caller's code.
func (aur *AdminUserRepository) UpdateAdminUser(id uuid.UUID, updates map[string]interface{}) error {
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
		set = append(set, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	set = append(set, "updated_at = NOW()")
	// TENANT-EXEMPT: pre-auth flows on an account resolved by sign-in.
	query := "UPDATE users SET " + strings.Join(set, ", ") + " WHERE id = $1"
	if _, err := aur.db.Exec(query, args...); err != nil {
		return fmt.Errorf("failed to update admin user: %w", err)
	}
	return nil
}

// UpdateLastLogin updates the last login time for an admin user.
func (aur *AdminUserRepository) UpdateLastLogin(id uuid.UUID) error {
	// TENANT-EXEMPT: sign-in bookkeeping on the account that just signed in.
	query := "UPDATE users SET last_login = $1, updated_at = $1 WHERE id = $2"
	if _, err := aur.db.Exec(query, time.Now(), id); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// GetAdminUserWithProviders retrieves an active console admin by email with
// the sign-in providers available to them. No such admin returns a nil user
// and ["email"].
func (aur *AdminUserRepository) GetAdminUserWithProviders(email string) (*models.AdminUser, []string, error) {
	// TENANT-EXEMPT: pre-auth provider discovery, no workspace is known yet.
	query := adminLoginColumns + activeConsoleAdmin + `
		  AND LOWER(u.email) = LOWER($1)`
	user, err := scanAdminUser(func(dest ...interface{}) error {
		return aur.db.QueryRow(query, email).Scan(dest...)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, []string{"email"}, nil
		}
		return nil, nil, err
	}

	providers := []string{"email"} // Email is always available
	if user.Provider != "" && user.Provider != "email" {
		providers = append(providers, user.Provider)
	}

	// The OAuth providers enabled in the user's own workspace.
	if user.WorkspaceID != nil {
		ctx := WithWorkspace(context.Background(), *user.WorkspaceID)
		rows, err := tenancy.QueryContext(ctx, aur.db.DB, `
			SELECT DISTINCT provider_name
			FROM oauth_configs
			WHERE workspace_id = $1 AND enabled = true
		`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var providerName string
				if err := rows.Scan(&providerName); err != nil {
					continue
				}
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

	return user, providers, nil
}

// GetAdminRoles returns the names of the roles a user holds in the workspace
// carried by ctx.
func (aur *AdminUserRepository) GetAdminRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := tenancy.QueryContext(ctx, aur.db.DB, `
		SELECT DISTINCT r.name
		FROM role_bindings rb
		JOIN roles r ON rb.role_id = r.id
		WHERE rb.workspace_id = $1 AND rb.user_id = $2
		ORDER BY r.name
	`, userID)
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
