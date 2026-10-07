package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// CIBAAuthRepository handles CIBA auth request and device token database
// operations. Every method that takes a context works in the workspace that
// context carries (see WithWorkspace) under row-level security.
type CIBAAuthRepository struct {
	db *DBConnection
}

// NewCIBAAuthRepository creates a new CIBA auth repository
func NewCIBAAuthRepository(db *DBConnection) *CIBAAuthRepository {
	return &CIBAAuthRepository{db: db}
}

// ErrDeviceTokenTaken means the push token is registered in another
// workspace; it is never moved across workspaces.
var ErrDeviceTokenTaken = errors.New("device token is registered in another workspace")

// ========================================
// Device Token Operations
// ========================================

const deviceTokenColumns = `id, user_id, workspace_id, device_token, platform,
		       device_name, device_model, app_version, os_version,
		       is_active, last_used, created_at, updated_at`

func scanDeviceToken(scan func(dest ...interface{}) error) (*models.DeviceToken, error) {
	var token models.DeviceToken
	err := scan(
		&token.ID,
		&token.UserID,
		&token.WorkspaceID,
		&token.DeviceToken,
		&token.Platform,
		&token.DeviceName,
		&token.DeviceModel,
		&token.AppVersion,
		&token.OSVersion,
		&token.IsActive,
		&token.LastUsed,
		&token.CreatedAt,
		&token.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// CreateDeviceToken registers a device for push notifications in ctx's
// workspace. Re-registering the same push token re-binds it to the user and
// returns the existing row's id in token.ID; a push token held by another
// workspace is ErrDeviceTokenTaken.
func (r *CIBAAuthRepository) CreateDeviceToken(ctx context.Context, token *models.DeviceToken) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	token.WorkspaceID = ws
	token.CreatedAt = now
	token.UpdatedAt = now

	// The WHERE makes a conflict with another workspace's row a no-op (no
	// row returned) instead of moving it into this workspace.
	var id uuid.UUID
	err = tenancy.QueryRowContext(ctx, r.db.DB, `
		INSERT INTO device_tokens (
			workspace_id, id, user_id, device_token, platform,
			device_name, device_model, app_version, os_version,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (device_token)
		DO UPDATE SET
			user_id = EXCLUDED.user_id,
			device_name = EXCLUDED.device_name,
			device_model = EXCLUDED.device_model,
			app_version = EXCLUDED.app_version,
			os_version = EXCLUDED.os_version,
			is_active = TRUE,
			updated_at = EXCLUDED.updated_at
		WHERE device_tokens.workspace_id = $1
		RETURNING id`,
		[]interface{}{
			token.ID,
			token.UserID,
			token.DeviceToken,
			token.Platform,
			token.DeviceName,
			token.DeviceModel,
			token.AppVersion,
			token.OSVersion,
			token.IsActive,
			token.CreatedAt,
			token.UpdatedAt,
		}, &id)
	if errors.Is(err, tenancy.ErrNotFound) {
		return ErrDeviceTokenTaken
	}
	if err != nil {
		return fmt.Errorf("failed to create device token: %w", err)
	}
	token.ID = id
	return nil
}

// GetDeviceTokensByUserID retrieves the active device tokens of a user in
// ctx's workspace.
func (r *CIBAAuthRepository) GetDeviceTokensByUserID(ctx context.Context, userID uuid.UUID) ([]models.DeviceToken, error) {
	var tokens []models.DeviceToken
	err := queryScoped(ctx, r.db.DB, `
		SELECT `+deviceTokenColumns+`
		FROM device_tokens
		WHERE workspace_id = $1 AND user_id = $2 AND is_active = TRUE
		ORDER BY created_at DESC`,
		[]interface{}{userID}, func(rows *sql.Rows) error {
			t, err := scanDeviceToken(rows.Scan)
			if err != nil {
				return fmt.Errorf("failed to scan device token: %w", err)
			}
			tokens = append(tokens, *t)
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("failed to query device tokens: %w", err)
	}
	return tokens, nil
}

// UpdateDeviceTokenLastUsed updates the last_used timestamp
func (r *CIBAAuthRepository) UpdateDeviceTokenLastUsed(ctx context.Context, deviceTokenID uuid.UUID) error {
	_, err := tenancy.ExecContext(ctx, r.db.DB,
		`UPDATE device_tokens SET last_used = $3 WHERE workspace_id = $1 AND id = $2`,
		deviceTokenID, time.Now().Unix())
	return err
}

// ========================================
// CIBA Auth Request Operations
// ========================================

// CreateCIBAAuthRequest creates a CIBA authentication request in ctx's
// workspace.
func (r *CIBAAuthRepository) CreateCIBAAuthRequest(ctx context.Context, req *models.CIBAAuthRequest) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	req.WorkspaceID = ws
	req.CreatedAt = time.Now().Unix()

	err = insertScoped(ctx, r.db.DB, `
		INSERT INTO ciba_auth_requests (
			workspace_id, id, auth_req_id, user_id, user_email,
			client_id, device_token_id, binding_message, scopes,
			status, biometric_verified, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		req.ID,
		req.AuthReqID,
		req.UserID,
		req.UserEmail,
		req.ClientID,
		req.DeviceTokenID,
		req.BindingMessage,
		req.Scopes,
		req.Status,
		req.BiometricVerified,
		req.ExpiresAt,
		req.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create CIBA auth request: %w", err)
	}
	return nil
}

const cibaRequestColumns = `id, auth_req_id, user_id, workspace_id, user_email,
		       client_id, device_token_id, binding_message, scopes,
		       status, biometric_verified, expires_at, created_at,
		       responded_at, last_polled_at`

func scanCIBARequest(scan func(dest ...interface{}) error) (*models.CIBAAuthRequest, error) {
	var req models.CIBAAuthRequest
	err := scan(
		&req.ID,
		&req.AuthReqID,
		&req.UserID,
		&req.WorkspaceID,
		&req.UserEmail,
		&req.ClientID,
		&req.DeviceTokenID,
		&req.BindingMessage,
		&req.Scopes,
		&req.Status,
		&req.BiometricVerified,
		&req.ExpiresAt,
		&req.CreatedAt,
		&req.RespondedAt,
		&req.LastPolledAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, tenancy.ErrNotFound) {
			return nil, fmt.Errorf("CIBA request not found")
		}
		return nil, fmt.Errorf("failed to get CIBA request: %w", err)
	}
	return &req, nil
}

// GetCIBAAuthRequestByID retrieves a CIBA request of ctx's workspace by
// auth_req_id; another workspace's request is not found.
func (r *CIBAAuthRepository) GetCIBAAuthRequestByID(ctx context.Context, authReqID string) (*models.CIBAAuthRequest, error) {
	return scanCIBARequest(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, r.db.DB, `
		SELECT `+cibaRequestColumns+`
		FROM ciba_auth_requests
		WHERE workspace_id = $1 AND auth_req_id = $2`,
			[]interface{}{authReqID}, dest...)
	})
}

// LookupCIBAAuthRequest finds a CIBA request by its auth_req_id alone, for
// the unauthenticated token poll: the auth_req_id is a 256-bit random bearer
// value, and the request's own row supplies the workspace for every later
// statement.
func (r *CIBAAuthRepository) LookupCIBAAuthRequest(authReqID string) (*models.CIBAAuthRequest, error) {
	// TENANT-EXEMPT: pre-auth poll by a globally unique random auth_req_id; the row names its workspace.
	query := `SELECT ` + cibaRequestColumns + ` FROM ciba_auth_requests WHERE auth_req_id = $1`
	return scanCIBARequest(r.db.QueryRow(query, authReqID).Scan)
}

// UpdateLastPolled updates the last_polled_at timestamp
func (r *CIBAAuthRepository) UpdateLastPolled(ctx context.Context, authReqID string) error {
	_, err := tenancy.ExecContext(ctx, r.db.DB,
		`UPDATE ciba_auth_requests SET last_polled_at = $3 WHERE workspace_id = $1 AND auth_req_id = $2`,
		authReqID, time.Now().Unix())
	return err
}

// UpdateCIBAAuthRequestStatusIf atomically transitions a request from fromStatus
// → status in a single conditional UPDATE (mirrors the workspace-plane fix,
// Appendix §6 first-responder-wins). Returns (won, err): won is true iff exactly
// one row transitioned. Without the `AND status = fromStatus` guard two concurrent
// responders (multi-device) or two concurrent polls would both "succeed" and the
// second would clobber the first / double-mint.
func (r *CIBAAuthRepository) UpdateCIBAAuthRequestStatusIf(ctx context.Context, authReqID, fromStatus, status string, biometricVerified bool) (bool, error) {
	res, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE ciba_auth_requests
		SET status = $2, biometric_verified = $3, responded_at = $4
		WHERE workspace_id = $1 AND auth_req_id = $5 AND status = $6`,
		status, biometricVerified, time.Now().Unix(), authReqID, fromStatus)
	if err != nil {
		return false, fmt.Errorf("failed to conditionally update CIBA request status: %w", err)
	}
	return affected(res) == 1, nil
}

// MarkAsConsumedIf atomically transitions approved → consumed, returning whether
// this caller won the transition (RowsAffected==1). Only the winner should mint a
// token, so two concurrent polls cannot both issue.
func (r *CIBAAuthRepository) MarkAsConsumedIf(ctx context.Context, authReqID string) (bool, error) {
	res, err := tenancy.ExecContext(ctx, r.db.DB,
		`UPDATE ciba_auth_requests SET status = 'consumed' WHERE workspace_id = $1 AND auth_req_id = $2 AND status = 'approved'`,
		authReqID)
	if err != nil {
		return false, fmt.Errorf("failed to consume CIBA request: %w", err)
	}
	return affected(res) == 1, nil
}

// ExpireOldRequests marks expired CIBA requests
func (r *CIBAAuthRepository) ExpireOldRequests() (int64, error) {
	now := time.Now().Unix()
	// TENANT-EXEMPT: platform retention job over every workspace's expired requests.
	query := `UPDATE ciba_auth_requests SET status = 'expired' WHERE expires_at < $1 AND status = 'pending'`

	result, err := r.db.Exec(query, now)
	if err != nil {
		return 0, fmt.Errorf("failed to expire old requests: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// DeleteExpiredRequests deletes old expired/consumed/denied requests
func (r *CIBAAuthRepository) DeleteExpiredRequests(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	// TENANT-EXEMPT: platform retention job over every workspace's finished requests.
	query := `DELETE FROM ciba_auth_requests WHERE created_at < $1 AND status IN ('expired', 'consumed', 'denied')`

	result, err := r.db.Exec(query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired requests: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// ========================================
// Device Token Management (Admin APIs)
// ========================================

// DeactivateDeviceToken deactivates (soft-deletes) a device of a user in
// ctx's workspace.
func (r *CIBAAuthRepository) DeactivateDeviceToken(ctx context.Context, tokenID, userID uuid.UUID) error {
	res, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE device_tokens
		SET is_active = FALSE, updated_at = $2
		WHERE workspace_id = $1 AND id = $3 AND user_id = $4`,
		time.Now().Unix(), tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to deactivate device token: %w", err)
	}
	if affected(res) == 0 {
		return fmt.Errorf("device not found or unauthorized")
	}
	return nil
}

// GetDeviceTokenByID retrieves a device token of ctx's workspace by ID.
func (r *CIBAAuthRepository) GetDeviceTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.DeviceToken, error) {
	token, err := scanDeviceToken(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, r.db.DB, `
		SELECT `+deviceTokenColumns+`
		FROM device_tokens
		WHERE workspace_id = $1 AND id = $2`,
			[]interface{}{tokenID}, dest...)
	})
	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return nil, fmt.Errorf("device token not found")
		}
		return nil, fmt.Errorf("failed to get device token: %w", err)
	}
	return token, nil
}
