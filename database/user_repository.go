package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserRepository handles user database operations without GORM
type UserRepository struct {
	db *DBConnection
}

var ErrUserNotFound = errors.New("user not found")

// IsUserNotFound reports whether a repository lookup did not find an active record.
func IsUserNotFound(err error) bool {
	return errors.Is(err, ErrUserNotFound)
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *DBConnection) *UserRepository {
	return &UserRepository{db: db}
}

// extendedUserColumns is the column list scanExtendedUser expects.
const extendedUserColumns = `id, client_id, workspace_id, project_id, name, username, email,
			COALESCE(password_hash, '') AS password_hash, workspace_domain, provider, provider_id, provider_data,
			avatar_url, active, mfa_enabled, mfa_method, mfa_default_method,
			mfa_enrolled_at, mfa_verified, last_login,
			created_at, updated_at`

// scanExtendedUser scans one extendedUserColumns row through scan.
func scanExtendedUser(scan func(dest ...interface{}) error) (*models.ExtendedUser, error) {
	user := &models.ExtendedUser{}
	var username, providerID, avatarURL, mfaDefaultMethod sql.NullString
	var mfaEnrolledAt, lastLoginAt sql.NullTime
	var mfaMethod pq.StringArray

	err := scan(
		&user.ID,
		&user.ClientID,
		&user.WorkspaceID,
		&user.ProjectID,
		&user.Name,
		&username,
		&user.Email,
		&user.PasswordHash,
		&user.WorkspaceDomain,
		&user.Provider,
		&providerID,
		&user.ProviderData,
		&avatarURL,
		&user.Active,
		&user.MFAEnabled,
		&mfaMethod,
		&mfaDefaultMethod,
		&mfaEnrolledAt,
		&user.MFAVerified,
		&lastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, tenancy.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if username.Valid {
		user.Username = &username.String
	}
	if providerID.Valid {
		user.ProviderID = providerID.String
	}
	if avatarURL.Valid {
		user.AvatarURL = &avatarURL.String
	}
	if mfaDefaultMethod.Valid {
		user.MFADefaultMethod = &mfaDefaultMethod.String
	}
	if mfaEnrolledAt.Valid {
		user.MFAEnrolledAt = &mfaEnrolledAt.Time
	}
	if lastLoginAt.Valid {
		user.LastLogin = &lastLoginAt.Time
	}
	user.MFAMethod = mfaMethod
	return user, nil
}

// CreateOIDCEndUser creates a consumer identity in the workspace carried by
// ctx for a first federated application login. It deliberately does not
// create a workspace_memberships row or an admin role binding.
func (ur *UserRepository) CreateOIDCEndUser(ctx context.Context, providerName string, userInfo *models.OIDCUserInfo) (*models.ExtendedUser, error) {
	workspaceID, err := ctxWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	email := strings.ToLower(strings.TrimSpace(userInfo.Email))
	if email == "" || userInfo.Sub == "" {
		return nil, fmt.Errorf("email and provider subject are required")
	}

	name := strings.TrimSpace(userInfo.Name)
	if name == "" {
		name = email
	}
	username := email
	profileData, err := json.Marshal(map[string]interface{}{
		"name":        userInfo.Name,
		"given_name":  userInfo.GivenName,
		"family_name": userInfo.FamilyName,
		"picture":     userInfo.Picture,
		"locale":      userInfo.Locale,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal OIDC profile: %w", err)
	}

	userID := uuid.New()
	now := time.Now().UTC()
	domainSuffix := os.Getenv("TENANT_DOMAIN_SUFFIX")
	if domainSuffix == "" {
		domainSuffix = "authsec.dev"
	}
	// $1 is the context's workspace; row-level security checks the row.
	err = tenancy.WithTx(ctx, ur.db.DB, workspaceID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
		INSERT INTO users (
			workspace_id, id, name, username, email, password_hash, workspace_domain,
			provider, provider_id, provider_data, avatar_url, active,
			last_login, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, '', $11,
		        $6, $7, $8, $9, true, $10, $10, $10)
		ON CONFLICT (workspace_id, LOWER(email)) WHERE deleted_at IS NULL
		DO UPDATE SET updated_at = users.updated_at
		RETURNING id
	`,
			workspaceID,
			userID,
			name,
			username,
			email,
			providerName,
			userInfo.Sub,
			profileData,
			userInfo.Picture,
			now,
			domainSuffix,
		).Scan(&userID)
	})
	if err != nil {
		return nil, fmt.Errorf("create workspace OIDC end user: %w", err)
	}

	return ur.GetUserByID(ctx, userID)
}

// UpdateLastLogin records successful consumer authentication.
func (ur *UserRepository) UpdateLastLogin(userID uuid.UUID) error {
	// TENANT-EXEMPT: sign-in bookkeeping on the account that just signed in.
	_, err := ur.db.Exec(
		"UPDATE users SET last_login = $1, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL",
		time.Now().UTC(),
		userID,
	)
	return err
}

// GetUserByEmail retrieves a user by email (case-insensitive): the first
// match across workspaces, for the pre-auth flows that have no workspace yet.
func (ur *UserRepository) GetUserByEmail(email string) (*models.ExtendedUser, error) {
	// TENANT-EXEMPT: pre-auth lookup by email before a workspace is known.
	query := `SELECT ` + extendedUserColumns + `
		FROM users
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`
	return scanExtendedUser(func(dest ...interface{}) error {
		return ur.db.QueryRow(query, email).Scan(dest...)
	})
}

// GetUserByEmailAndTenant retrieves a user by email (case-insensitive) in the
// workspace carried by ctx.
func (ur *UserRepository) GetUserByEmailAndTenant(ctx context.Context, email string) (*models.ExtendedUser, error) {
	query := `SELECT ` + extendedUserColumns + `
		FROM users
		WHERE workspace_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL`
	return scanExtendedUser(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, ur.db.DB, query, []interface{}{email}, dest...)
	})
}

// GetUserByID retrieves a user by id in the workspace carried by ctx. A user
// of another workspace is ErrUserNotFound.
func (ur *UserRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.ExtendedUser, error) {
	query := `SELECT ` + extendedUserColumns + `
		FROM users
		WHERE workspace_id = $1 AND id = $2 AND deleted_at IS NULL`
	return scanExtendedUser(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, ur.db.DB, query, []interface{}{userID}, dest...)
	})
}

// UpdateUserLogin records a sign-in for a user.
func (ur *UserRepository) UpdateUserLogin(userID uuid.UUID) error {
	now := time.Now()
	// TENANT-EXEMPT: sign-in bookkeeping on the account that just signed in.
	result, err := ur.db.Exec(`UPDATE users SET last_login = $1, updated_at = $2 WHERE id = $3`, now, now, userID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdateUserMFA updates the MFA fields of a user of the workspace carried by
// ctx. Another workspace's user is "user not found".
func (ur *UserRepository) UpdateUserMFA(ctx context.Context, userID uuid.UUID, mfaEnabled bool, mfaMethods []byte) error {
	result, err := tenancy.ExecContext(ctx, ur.db.DB, `
		UPDATE users
		SET mfa_enabled = $3, mfa_method = $4, updated_at = $5
		WHERE workspace_id = $1 AND id = $2
	`, userID, mfaEnabled, mfaMethods, time.Now())
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// GetUsersByWorkspaceID lists the users of the workspace carried by ctx,
// newest first.
func (ur *UserRepository) GetUsersByWorkspaceID(ctx context.Context, limit, offset int) ([]*models.ExtendedUser, error) {
	rows, err := tenancy.QueryContext(ctx, ur.db.DB, `SELECT `+extendedUserColumns+`
		FROM users
		WHERE workspace_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.ExtendedUser
	for rows.Next() {
		user, err := scanExtendedUser(rows.Scan)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// CreateUserTx creates a user of the workspace carried by ctx inside the
// caller's transaction (sign-up creates the workspace and its first user
// atomically). The user's workspace must be the context's.
func (ur *UserRepository) CreateUserTx(ctx context.Context, tx *sql.Tx, user *models.ExtendedUser) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	if user.WorkspaceID != ws {
		return fmt.Errorf("user validation failed: user must belong to the caller's workspace")
	}
	if err := ur.validateUserForCreation(ctx, tx, user); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
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

	var mfaMethodArray interface{}
	if user.MFAMethod != nil {
		mfaMethodArray = user.MFAMethod
	}

	// $1 is the context's workspace.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (workspace_id, id, client_id, project_id, name, username, email,
			password_hash, workspace_domain, provider, provider_id, provider_data,
			avatar_url, active, mfa_enabled, mfa_method, mfa_default_method,
			mfa_enrolled_at, mfa_verified, last_login,
			created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
	`,
		ws,
		user.ID,
		user.ClientID,
		user.ProjectID,
		user.Name,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.WorkspaceDomain,
		user.Provider,
		user.ProviderID,
		user.ProviderData,
		user.AvatarURL,
		user.Active,
		user.MFAEnabled,
		mfaMethodArray,
		user.MFADefaultMethod,
		user.MFAEnrolledAt,
		user.MFAVerified,
		user.LastLogin,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

var emailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// validateUserForCreation validates a new user of the workspace carried by
// ctx, checking uniqueness inside the caller's transaction.
func (ur *UserRepository) validateUserForCreation(ctx context.Context, tx *sql.Tx, user *models.ExtendedUser) error {
	if user.ClientID == uuid.Nil {
		return fmt.Errorf("client_id is required")
	}
	// Note: project_id is optional and can be nil for admin users
	if strings.TrimSpace(user.Email) == "" {
		return fmt.Errorf("email is required")
	}
	if strings.TrimSpace(user.WorkspaceDomain) == "" {
		return fmt.Errorf("workspace_domain is required")
	}
	if strings.TrimSpace(user.Provider) == "" {
		return fmt.Errorf("provider is required")
	}
	if strings.TrimSpace(user.ProviderID) == "" {
		return fmt.Errorf("provider_id is required")
	}
	if !emailPattern.MatchString(user.Email) {
		return fmt.Errorf("invalid email format: %s", user.Email)
	}
	if len(user.ProviderData) > 0 {
		var jsonTest interface{}
		if err := json.Unmarshal(user.ProviderData, &jsonTest); err != nil {
			return fmt.Errorf("invalid JSON in provider_data: %w", err)
		}
	}

	// The same email for the same client in this workspace.
	var existingID uuid.UUID
	err := tenancy.QueryRowContext(ctx, tx, `
		SELECT id FROM users
		 WHERE workspace_id = $1 AND LOWER(email) = LOWER($2) AND client_id = $3 AND deleted_at IS NULL`,
		[]interface{}{user.Email, user.ClientID}, &existingID)
	if err == nil {
		return fmt.Errorf("user with email %s already exists for this client", user.Email)
	} else if !errors.Is(err, tenancy.ErrNotFound) {
		return fmt.Errorf("failed to check existing user email: %w", err)
	}

	// The same provider identity in this workspace.
	err = tenancy.QueryRowContext(ctx, tx, `
		SELECT id FROM users
		 WHERE workspace_id = $1 AND provider = $2 AND provider_id = $3 AND deleted_at IS NULL AND id <> $4`,
		[]interface{}{user.Provider, user.ProviderID, user.ID}, &existingID)
	if err == nil {
		return fmt.Errorf("user with provider '%s' and provider_id '%s' already exists", user.Provider, user.ProviderID)
	} else if !errors.Is(err, tenancy.ErrNotFound) {
		return fmt.Errorf("error checking provider uniqueness: %w", err)
	}
	return nil
}
