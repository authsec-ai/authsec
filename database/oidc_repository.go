package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// The OIDC repositories' workspace-owned statements run through
// internal/tenancy under row-level security, for the workspace the caller
// names (callers predate a ctx-carried tenant and pass the workspace id).
// Platform provider rows (workspace_id IS NULL) and the pre-auth state rows,
// which are looked up by a random state token before any workspace is known,
// are read without a workspace and say so.

// ========================================
// OIDCProviderRepository
// ========================================

// OIDCProviderRepository handles OIDC provider database operations
type OIDCProviderRepository struct {
	db *DBConnection
}

// NewOIDCProviderRepository creates a new OIDC provider repository
func NewOIDCProviderRepository(db *DBConnection) *OIDCProviderRepository {
	return &OIDCProviderRepository{db: db}
}

const oidcProviderColumns = `id, provider_name, display_name, client_id, client_secret_vault_path,
		       authorization_url, token_url, userinfo_url, scopes, icon_url, redirect_uri, is_active,
		       created_at, updated_at`

// GetProviderByName retrieves a global/platform OIDC provider by name.
// Workspace-owned providers must use GetProviderByWorkspaceAndName so a
// workspace login can never accidentally bind to another workspace's config.
func (r *OIDCProviderRepository) GetProviderByName(providerName string) (*models.OIDCProvider, error) {
	// TENANT-EXEMPT: platform provider rows (workspace_id IS NULL), shared by every workspace.
	query := `SELECT ` + oidcProviderColumns + `
		FROM oidc_providers
		WHERE workspace_id IS NULL AND provider_name = $1
	`

	provider, err := scanOIDCProvider(r.db.QueryRow(query, providerName))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("OIDC provider not found: %s", providerName)
		}
		return nil, err
	}

	return provider, nil
}

// GetProviderByWorkspaceAndName retrieves a workspace-owned OIDC provider.
func (r *OIDCProviderRepository) GetProviderByWorkspaceAndName(workspaceID uuid.UUID, providerName string) (*models.OIDCProvider, error) {
	provider, err := scanOIDCProvider(scanFunc(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+oidcProviderColumns+`
		FROM oidc_providers
		WHERE workspace_id = $1 AND provider_name = $2`, []interface{}{providerName}, dest...)
	}))
	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return nil, fmt.Errorf("OIDC provider not found for workspace %s: %s", workspaceID, providerName)
		}
		return nil, err
	}
	provider.WorkspaceID = &workspaceID
	return provider, nil
}

// GetActiveProviders retrieves active global/platform OIDC providers.
func (r *OIDCProviderRepository) GetActiveProviders() ([]models.OIDCProvider, error) {
	// TENANT-EXEMPT: platform provider rows (workspace_id IS NULL), shared by every workspace.
	query := `SELECT ` + oidcProviderColumns + `
		FROM oidc_providers
		WHERE workspace_id IS NULL AND is_active = true
		ORDER BY display_name
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []models.OIDCProvider
	for rows.Next() {
		provider, err := scanOIDCProvider(rows)
		if err != nil {
			return nil, err
		}
		providers = append(providers, *provider)
	}

	return providers, rows.Err()
}

// GetWorkspaceProviders retrieves the OIDC providers owned by one workspace
// (for that workspace's admins). Platform rows (workspace_id IS NULL) are not
// included: they are not the workspace's to manage.
func (r *OIDCProviderRepository) GetWorkspaceProviders(workspaceID uuid.UUID) ([]models.OIDCProvider, error) {
	var providers []models.OIDCProvider
	err := queryScoped(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+oidcProviderColumns+`
		FROM oidc_providers
		WHERE workspace_id = $1
		ORDER BY display_name`, nil, func(rows *sql.Rows) error {
		provider, err := scanOIDCProvider(rows)
		if err != nil {
			return err
		}
		wsID := workspaceID
		provider.WorkspaceID = &wsID
		providers = append(providers, *provider)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return providers, nil
}

// UpdateProvider updates one workspace's OIDC provider configuration. Platform
// rows (workspace_id IS NULL) and other workspaces' rows are never touched.
func (r *OIDCProviderRepository) UpdateProvider(workspaceID uuid.UUID, providerName string, input *models.OIDCProviderUpdateInput) error {
	result, err := tenancy.ExecContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `
		UPDATE oidc_providers
			SET client_id = COALESCE(NULLIF($2, ''), client_id),
			    client_secret_vault_path = COALESCE(NULLIF($3, ''), client_secret_vault_path),
			    is_active = COALESCE($4, is_active),
			    icon_url = COALESCE(NULLIF($5, ''), icon_url),
			    redirect_uri = COALESCE(NULLIF($6, ''), redirect_uri),
			    updated_at = $7
			WHERE workspace_id = $1 AND provider_name = $8
		`,
		input.ClientID,
		input.ClientSecretVaultPath,
		input.IsActive,
		input.IconURL,
		input.RedirectURI,
		time.Now(),
		providerName,
	)
	if err != nil {
		return err
	}
	if affected(result) == 0 {
		return fmt.Errorf("OIDC provider not found: %s", providerName)
	}

	return nil
}

type oidcProviderScanner interface {
	Scan(dest ...interface{}) error
}

func scanOIDCProvider(scanner oidcProviderScanner) (*models.OIDCProvider, error) {
	provider := &models.OIDCProvider{}
	var iconURL, redirectURI sql.NullString
	err := scanner.Scan(
		&provider.ID,
		&provider.ProviderName,
		&provider.DisplayName,
		&provider.ClientID,
		&provider.ClientSecretVaultPath,
		&provider.AuthorizationURL,
		&provider.TokenURL,
		&provider.UserinfoURL,
		&provider.Scopes,
		&iconURL,
		&redirectURI,
		&provider.IsActive,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if iconURL.Valid {
		provider.IconURL = iconURL.String
	}
	if redirectURI.Valid {
		provider.RedirectURI = redirectURI.String
	}
	return provider, nil
}

// ========================================
// OIDCStateRepository
// ========================================

// OIDCStateRepository handles OIDC state database operations
type OIDCStateRepository struct {
	db *DBConnection
}

// NewOIDCStateRepository creates a new OIDC state repository
func NewOIDCStateRepository(db *DBConnection) *OIDCStateRepository {
	return &OIDCStateRepository{db: db}
}

// CreateState creates a new OIDC state entry. v4 columns (application_id,
// signed_state, login_challenge — added in migration 128) are written here;
// pre-v4 callers can leave them empty and they'll be NULL in the DB. A state
// of a workspace is written in that workspace under row-level security; a
// platform login's state (no workspace yet) has workspace_id NULL.
func (r *OIDCStateRepository) CreateState(state *models.OIDCState) error {
	now := time.Now()
	if state.CreatedAt.IsZero() {
		state.CreatedAt = now
	}
	if state.ID == uuid.Nil {
		state.ID = uuid.New()
	}

	requestHostParam := sql.NullString{
		String: state.OriginDomain,
		Valid:  state.OriginDomain != "",
	}
	signedStateParam := sql.NullString{
		String: state.SignedState,
		Valid:  state.SignedState != "",
	}
	loginChallengeParam := sql.NullString{
		String: state.LoginChallenge,
		Valid:  state.LoginChallenge != "",
	}
	var applicationIDParam interface{} // either uuid string or nil for NULL
	if state.ApplicationID != nil {
		applicationIDParam = state.ApplicationID.String()
	}
	args := []interface{}{
		state.ID,
		state.StateToken,
		state.WorkspaceDomain,
		requestHostParam,
		state.ProviderName,
		state.Action,
		state.CodeVerifier,
		state.RedirectAfter,
		state.ExpiresAt,
		state.CreatedAt,
		applicationIDParam,
		signedStateParam,
		loginChallengeParam,
	}

	var err error
	if state.WorkspaceID != nil {
		err = insertScoped(WithWorkspace(context.Background(), *state.WorkspaceID), r.db.DB, `
		INSERT INTO oidc_states (workspace_id, id, state_token, workspace_domain, request_host, provider_name,
		                         action, code_verifier, redirect_after, expires_at, created_at,
		                         application_id, signed_state, login_challenge)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`, args...)
	} else {
		// TENANT-EXEMPT: platform login or sign-up state, written before any workspace exists (workspace_id NULL).
		_, err = r.db.Exec(`
		INSERT INTO oidc_states (workspace_id, id, state_token, workspace_domain, request_host, provider_name,
		                         action, code_verifier, redirect_after, expires_at, created_at,
		                         application_id, signed_state, login_challenge)
		VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`, args...)
	}
	if err != nil {
		log.Printf("ERROR CreateState: Failed to insert state: %v", err)
	}
	return err
}

// GetStateByToken retrieves a valid (non-expired) state by token. Reads the
// v4 columns (application_id, signed_state, login_challenge) added by
// migration 128; older rows where these are NULL come back with empty values
// and the callback branches accordingly.
func (r *OIDCStateRepository) GetStateByToken(stateToken string) (*models.OIDCState, error) {
	// TENANT-EXEMPT: pre-auth callback lookup by a random, unique state token; the row names its workspace.
	query := `
		SELECT id, state_token, workspace_id, workspace_domain, request_host, provider_name,
		       action, code_verifier, redirect_after, expires_at, created_at,
		       application_id, signed_state, login_challenge
		FROM oidc_states
		WHERE state_token = $1 AND expires_at > $2
	`

	state := &models.OIDCState{}
	var workspaceID sql.NullString
	var requestHost, codeVerifier, redirectAfter sql.NullString
	var applicationID, signedState, loginChallenge sql.NullString

	err := r.db.QueryRow(query, stateToken, time.Now()).Scan(
		&state.ID,
		&state.StateToken,
		&workspaceID,
		&state.WorkspaceDomain,
		&requestHost,
		&state.ProviderName,
		&state.Action,
		&codeVerifier,
		&redirectAfter,
		&state.ExpiresAt,
		&state.CreatedAt,
		&applicationID,
		&signedState,
		&loginChallenge,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("OIDC state not found or expired")
		}
		return nil, err
	}

	if workspaceID.Valid {
		id, _ := uuid.Parse(workspaceID.String)
		state.WorkspaceID = &id
	}
	if requestHost.Valid {
		state.OriginDomain = requestHost.String
	}
	if codeVerifier.Valid {
		state.CodeVerifier = codeVerifier.String
	}
	if redirectAfter.Valid {
		state.RedirectAfter = redirectAfter.String
	}
	if applicationID.Valid {
		if id, perr := uuid.Parse(applicationID.String); perr == nil {
			state.ApplicationID = &id
		}
	}
	if signedState.Valid {
		state.SignedState = signedState.String
	}
	if loginChallenge.Valid {
		state.LoginChallenge = loginChallenge.String
	}

	return state, nil
}

// DeleteState deletes a state entry (after use or cleanup)
func (r *OIDCStateRepository) DeleteState(stateToken string) error {
	// TENANT-EXEMPT: pre-auth state, addressed by its random, unique token.
	query := `DELETE FROM oidc_states WHERE state_token = $1`
	_, err := r.db.Exec(query, stateToken)
	return err
}

// ConsumeState atomically deletes an unexpired state of the given action and
// returns it, so a state token can be redeemed at most once.
func (r *OIDCStateRepository) ConsumeState(stateToken, action string) (*models.OIDCState, error) {
	// TENANT-EXEMPT: pre-auth state, addressed by its random, unique token.
	query := `
		DELETE FROM oidc_states
		WHERE state_token = $1 AND action = $2 AND expires_at > $3
		RETURNING provider_name, COALESCE(signed_state, ''), COALESCE(request_host, '')
	`
	state := &models.OIDCState{StateToken: stateToken, Action: action}
	if err := r.db.QueryRow(query, stateToken, action, time.Now()).Scan(
		&state.ProviderName, &state.SignedState, &state.OriginDomain,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("state not found or expired")
		}
		return nil, err
	}
	return state, nil
}

// DeleteExpiredStates deletes all expired state entries (cleanup job)
func (r *OIDCStateRepository) DeleteExpiredStates() error {
	// TENANT-EXEMPT: platform cleanup job; removes only expired pre-auth states, of every workspace.
	query := `DELETE FROM oidc_states WHERE expires_at < $1`
	_, err := r.db.Exec(query, time.Now())
	return err
}

// ========================================
// OIDCUserIdentityRepository
// ========================================

// OIDCUserIdentityRepository handles OIDC user identity database operations
type OIDCUserIdentityRepository struct {
	db *DBConnection
}

// NewOIDCUserIdentityRepository creates a new OIDC user identity repository
func NewOIDCUserIdentityRepository(db *DBConnection) *OIDCUserIdentityRepository {
	return &OIDCUserIdentityRepository{db: db}
}

const oidcIdentityColumns = `id, workspace_id, user_id, provider_name, provider_user_id,
		       email, profile_data, last_login_at, created_at, updated_at`

func scanOIDCIdentity(scan func(dest ...interface{}) error) (*models.OIDCUserIdentity, error) {
	identity := &models.OIDCUserIdentity{}
	var profileData sql.NullString
	var email sql.NullString
	var lastLoginAt sql.NullTime

	err := scan(
		&identity.ID,
		&identity.WorkspaceID,
		&identity.UserID,
		&identity.ProviderName,
		&identity.ProviderUserID,
		&email,
		&profileData,
		&lastLoginAt,
		&identity.CreatedAt,
		&identity.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if email.Valid {
		identity.Email = email.String
	}
	if profileData.Valid {
		identity.ProfileData = profileData.String
	}
	if lastLoginAt.Valid {
		identity.LastLoginAt = &lastLoginAt.Time
	}
	return identity, nil
}

// CreateIdentity creates a new OIDC user identity link in identity's
// workspace, or updates it if it already exists.
func (r *OIDCUserIdentityRepository) CreateIdentity(identity *models.OIDCUserIdentity) error {
	now := time.Now()
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = now
	}
	identity.UpdatedAt = now
	if identity.ID == uuid.Nil {
		identity.ID = uuid.New()
	}

	ctx := WithWorkspace(context.Background(), identity.WorkspaceID)
	if err := insertScoped(ctx, r.db.DB, `
		INSERT INTO oidc_user_identities (workspace_id, id, user_id, provider_name, provider_user_id,
		                                  email, profile_data, created_at, updated_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (workspace_id, provider_name, provider_user_id) DO UPDATE
		SET email = EXCLUDED.email,
		    profile_data = EXCLUDED.profile_data,
		    updated_at = EXCLUDED.updated_at,
			last_login_at = EXCLUDED.updated_at`,
		identity.ID,
		identity.UserID,
		identity.ProviderName,
		identity.ProviderUserID,
		identity.Email,
		identity.ProfileData,
		identity.CreatedAt,
		identity.UpdatedAt,
		identity.CreatedAt, // last_login_at (same as created_at on first insert)
	); err != nil {
		return err
	}
	// An existing link keeps its id.
	return tenancy.QueryRowContext(ctx, r.db.DB,
		`SELECT id FROM oidc_user_identities WHERE workspace_id = $1 AND provider_name = $2 AND provider_user_id = $3`,
		[]interface{}{identity.ProviderName, identity.ProviderUserID}, &identity.ID)
}

// GetIdentityByProviderUser retrieves an identity by provider slug and provider
// user ID across workspaces. Prefer GetIdentityByTenantAndProviderUser for
// workspace-owned provider flows.
func (r *OIDCUserIdentityRepository) GetIdentityByProviderUser(providerName, providerUserID string) (*models.OIDCUserIdentity, error) {
	// TENANT-EXEMPT: cross-workspace by contract (see above); no caller today.
	query := `SELECT ` + oidcIdentityColumns + `
		FROM oidc_user_identities
		WHERE provider_name = $1 AND provider_user_id = $2
	`
	identity, err := scanOIDCIdentity(r.db.QueryRow(query, providerName, providerUserID).Scan)
	if err == sql.ErrNoRows {
		return nil, nil // Not found is valid - user doesn't have OIDC linked
	}
	return identity, err
}

// GetIdentityByTenantAndProviderUser retrieves identity for a specific tenant
// This answers: "Does this Google user exist in THIS tenant?"
func (r *OIDCUserIdentityRepository) GetIdentityByTenantAndProviderUser(workspaceID uuid.UUID, providerName, providerUserID string) (*models.OIDCUserIdentity, error) {
	identity, err := scanOIDCIdentity(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+oidcIdentityColumns+`
		FROM oidc_user_identities
		WHERE workspace_id = $1 AND provider_name = $2 AND provider_user_id = $3`,
			[]interface{}{providerName, providerUserID}, dest...)
	})
	if errors.Is(err, tenancy.ErrNotFound) {
		return nil, nil // Not found - user not in this tenant with this provider
	}
	return identity, err
}

// GetIdentitiesByUserID retrieves all OIDC identities for a user
func (r *OIDCUserIdentityRepository) GetIdentitiesByUserID(workspaceID, userID uuid.UUID) ([]models.OIDCUserIdentity, error) {
	var identities []models.OIDCUserIdentity
	err := queryScoped(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+oidcIdentityColumns+`
		FROM oidc_user_identities
		WHERE workspace_id = $1 AND user_id = $2`, []interface{}{userID}, func(rows *sql.Rows) error {
		identity, err := scanOIDCIdentity(rows.Scan)
		if err != nil {
			return err
		}
		identities = append(identities, *identity)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return identities, nil
}

// identityContext returns a context carrying the workspace that owns identity
// id, for the id-only entry points below, whose callers have just read the
// identity in its workspace (GetIdentityByTenantAndProviderUser).
func (r *OIDCUserIdentityRepository) identityContext(identityID uuid.UUID) (context.Context, error) {
	var ws uuid.UUID
	// TENANT-EXEMPT: resolves the owner of an identity id (globally unique) for the id-only entry points; nothing else is read.
	if err := r.db.QueryRow(`SELECT workspace_id FROM oidc_user_identities WHERE id = $1`, identityID).Scan(&ws); err != nil {
		return nil, err // sql.ErrNoRows: no such identity
	}
	return WithWorkspace(context.Background(), ws), nil
}

// UpdateLastLogin updates the last login timestamp for an identity
func (r *OIDCUserIdentityRepository) UpdateLastLogin(identityID uuid.UUID) error {
	ctx, err := r.identityContext(identityID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // nothing to update, as before
	} else if err != nil {
		return err
	}
	now := time.Now()
	_, err = tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE oidc_user_identities
		SET last_login_at = $2, updated_at = $3
		WHERE workspace_id = $1 AND id = $4
	`, now, now, identityID)
	return err
}

// UpdateProfileData updates the profile data for an identity
func (r *OIDCUserIdentityRepository) UpdateProfileData(identityID uuid.UUID, profileData map[string]interface{}) error {
	jsonData, err := json.Marshal(profileData)
	if err != nil {
		return err
	}
	ctx, err := r.identityContext(identityID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // nothing to update, as before
	} else if err != nil {
		return err
	}
	_, err = tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE oidc_user_identities
		SET profile_data = $2, updated_at = $3
		WHERE workspace_id = $1 AND id = $4
	`, string(jsonData), time.Now(), identityID)
	return err
}

// DeleteIdentity deletes an OIDC identity link (unlink provider)
func (r *OIDCUserIdentityRepository) DeleteIdentity(workspaceID, userID uuid.UUID, providerName string) error {
	result, err := tenancy.ExecContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `
		DELETE FROM oidc_user_identities
		WHERE workspace_id = $1 AND user_id = $2 AND provider_name = $3
	`, userID, providerName)
	if err != nil {
		return err
	}
	if affected(result) == 0 {
		return fmt.Errorf("OIDC identity not found")
	}

	return nil
}

// GetTenantsByProviderEmail retrieves all tenants where this email has OIDC identity
// Useful for "find my workspace" feature
func (r *OIDCUserIdentityRepository) GetTenantsByProviderEmail(email string) ([]uuid.UUID, error) {
	// TENANT-EXEMPT: "find my workspace" before sign-in; returns only the workspace ids an email has an identity in.
	query := `
		SELECT DISTINCT workspace_id
		FROM oidc_user_identities
		WHERE email = $1
	`

	rows, err := r.db.Query(query, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaceIDs []uuid.UUID
	for rows.Next() {
		var workspaceID uuid.UUID
		if err := rows.Scan(&workspaceID); err != nil {
			return nil, err
		}
		workspaceIDs = append(workspaceIDs, workspaceID)
	}

	return workspaceIDs, rows.Err()
}
