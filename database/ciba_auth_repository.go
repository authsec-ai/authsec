package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// CIBAAuthRepository handles CIBA auth request and device token database operations
type CIBAAuthRepository struct {
	db *DBConnection
}

// NewCIBAAuthRepository creates a new CIBA auth repository
func NewCIBAAuthRepository(db *DBConnection) *CIBAAuthRepository {
	return &CIBAAuthRepository{db: db}
}

// ========================================
// Device Token Operations
// ========================================

// CreateDeviceToken registers a new device for push notifications
func (r *CIBAAuthRepository) CreateDeviceToken(token *models.DeviceToken) error {
	now := time.Now().Unix()
	token.CreatedAt = now
	token.UpdatedAt = now

	query := `
		INSERT INTO device_tokens (
			id, user_id, workspace_id, device_token, platform,
			device_name, device_model, app_version, os_version,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (device_token)
		DO UPDATE SET
			user_id = EXCLUDED.user_id,
			workspace_id = EXCLUDED.workspace_id,
			device_name = EXCLUDED.device_name,
			device_model = EXCLUDED.device_model,
			app_version = EXCLUDED.app_version,
			os_version = EXCLUDED.os_version,
			is_active = TRUE,
			updated_at = EXCLUDED.updated_at
	`

	_, err := r.db.Exec(query,
		token.ID,
		token.UserID,
		token.WorkspaceID,
		token.DeviceToken,
		token.Platform,
		token.DeviceName,
		token.DeviceModel,
		token.AppVersion,
		token.OSVersion,
		token.IsActive,
		token.CreatedAt,
		token.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create device token: %w", err)
	}

	return nil
}

// GetDeviceTokensByUserID retrieves all active device tokens for a user
func (r *CIBAAuthRepository) GetDeviceTokensByUserID(userID uuid.UUID, workspaceID uuid.UUID) ([]models.DeviceToken, error) {
	query := `
		SELECT id, user_id, workspace_id, device_token, platform,
		       device_name, device_model, app_version, os_version,
		       is_active, last_used, created_at, updated_at
		FROM device_tokens
		WHERE user_id = $1 AND workspace_id = $2 AND is_active = TRUE
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, userID, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query device tokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.DeviceToken
	for rows.Next() {
		var token models.DeviceToken
		err := rows.Scan(
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
			return nil, fmt.Errorf("failed to scan device token: %w", err)
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// UpdateDeviceTokenLastUsed updates the last_used timestamp
func (r *CIBAAuthRepository) UpdateDeviceTokenLastUsed(deviceTokenID uuid.UUID) error {
	now := time.Now().Unix()
	query := `UPDATE device_tokens SET last_used = $1 WHERE id = $2`
	_, err := r.db.Exec(query, now, deviceTokenID)
	return err
}

// ========================================
// CIBA Auth Request Operations
// ========================================

// CreateCIBAAuthRequest creates a new CIBA authentication request
func (r *CIBAAuthRepository) CreateCIBAAuthRequest(req *models.CIBAAuthRequest) error {
	now := time.Now().Unix()
	req.CreatedAt = now

	query := `
		INSERT INTO ciba_auth_requests (
			id, auth_req_id, user_id, workspace_id, user_email,
			client_id, device_token_id, binding_message, scopes,
			status, biometric_verified, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.db.Exec(query,
		req.ID,
		req.AuthReqID,
		req.UserID,
		req.WorkspaceID,
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

// GetCIBAAuthRequestByID retrieves a CIBA request by auth_req_id
func (r *CIBAAuthRepository) GetCIBAAuthRequestByID(authReqID string) (*models.CIBAAuthRequest, error) {
	query := `
		SELECT id, auth_req_id, user_id, workspace_id, user_email,
		       client_id, device_token_id, binding_message, scopes,
		       status, biometric_verified, expires_at, created_at,
		       responded_at, last_polled_at
		FROM ciba_auth_requests
		WHERE auth_req_id = $1
	`

	var req models.CIBAAuthRequest
	err := r.db.QueryRow(query, authReqID).Scan(
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
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("CIBA request not found")
		}
		return nil, fmt.Errorf("failed to get CIBA request: %w", err)
	}

	return &req, nil
}

// UpdateCIBAAuthRequestStatus updates the status of a CIBA request unconditionally.
//
// Deprecated: this is not concurrency-safe — an unconditional UPDATE can clobber a
// terminal state set by a concurrent responder/poll (double-approve / double-mint).
// Use UpdateCIBAAuthRequestStatusIf (conditional CAS on fromStatus) instead. Kept
// only because removing an exported method is a breaking API change; it has no
// callers in the respond/poll hot paths.
func (r *CIBAAuthRepository) UpdateCIBAAuthRequestStatus(authReqID string, status string, biometricVerified bool) error {
	now := time.Now().Unix()
	query := `
		UPDATE ciba_auth_requests
		SET status = $1, biometric_verified = $2, responded_at = $3
		WHERE auth_req_id = $4
	`

	_, err := r.db.Exec(query, status, biometricVerified, now, authReqID)
	if err != nil {
		return fmt.Errorf("failed to update CIBA request status: %w", err)
	}

	return nil
}

// UpdateLastPolled updates the last_polled_at timestamp
func (r *CIBAAuthRepository) UpdateLastPolled(authReqID string) error {
	now := time.Now().Unix()
	query := `UPDATE ciba_auth_requests SET last_polled_at = $1 WHERE auth_req_id = $2`
	_, err := r.db.Exec(query, now, authReqID)
	return err
}

// MarkAsConsumed marks a CIBA request as consumed (token issued) unconditionally.
//
// Deprecated: not concurrency-safe — two concurrent polls would both "consume" and
// both mint. Use MarkAsConsumedIf (CAS on status='approved') so only one poll wins.
func (r *CIBAAuthRepository) MarkAsConsumed(authReqID string) error {
	query := `UPDATE ciba_auth_requests SET status = 'consumed' WHERE auth_req_id = $1`
	_, err := r.db.Exec(query, authReqID)
	return err
}

// UpdateCIBAAuthRequestStatusIf atomically transitions a request from fromStatus
// → status in a single conditional UPDATE (mirrors the workspace-plane fix,
// Appendix §6 first-responder-wins). Returns (won, err): won is true iff exactly
// one row transitioned. Without the `AND status = fromStatus` guard two concurrent
// responders (multi-device) or two concurrent polls would both "succeed" and the
// second would clobber the first / double-mint.
func (r *CIBAAuthRepository) UpdateCIBAAuthRequestStatusIf(authReqID, fromStatus, status string, biometricVerified bool) (bool, error) {
	now := time.Now().Unix()
	query := `
		UPDATE ciba_auth_requests
		SET status = $1, biometric_verified = $2, responded_at = $3
		WHERE auth_req_id = $4 AND status = $5
	`
	res, err := r.db.Exec(query, status, biometricVerified, now, authReqID, fromStatus)
	if err != nil {
		return false, fmt.Errorf("failed to conditionally update CIBA request status: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// MarkAsConsumedIf atomically transitions approved → consumed, returning whether
// this caller won the transition (RowsAffected==1). Only the winner should mint a
// token, so two concurrent polls cannot both issue.
func (r *CIBAAuthRepository) MarkAsConsumedIf(authReqID string) (bool, error) {
	query := `UPDATE ciba_auth_requests SET status = 'consumed' WHERE auth_req_id = $1 AND status = 'approved'`
	res, err := r.db.Exec(query, authReqID)
	if err != nil {
		return false, fmt.Errorf("failed to consume CIBA request: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ExpireOldRequests marks expired CIBA requests
func (r *CIBAAuthRepository) ExpireOldRequests() (int64, error) {
	now := time.Now().Unix()
	query := `
		UPDATE ciba_auth_requests
		SET status = 'expired'
		WHERE expires_at < $1 AND status = 'pending'
	`

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
	query := `
		DELETE FROM ciba_auth_requests
		WHERE created_at < $1 AND status IN ('expired', 'consumed', 'denied')
	`

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

// DeactivateDeviceToken deactivates a device token (soft delete)
func (r *CIBAAuthRepository) DeactivateDeviceToken(tokenID, userID, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	query := `
		UPDATE device_tokens
		SET is_active = FALSE, updated_at = $1
		WHERE id = $2 AND user_id = $3 AND workspace_id = $4
	`

	result, err := r.db.Exec(query, now, tokenID, userID, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to deactivate device token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("device not found or unauthorized")
	}

	return nil
}

// GetDeviceTokenByID retrieves a device token by ID
func (r *CIBAAuthRepository) GetDeviceTokenByID(tokenID uuid.UUID) (*models.DeviceToken, error) {
	query := `
		SELECT id, user_id, workspace_id, device_token, platform,
		       device_name, device_model, app_version, os_version,
		       is_active, last_used, created_at, updated_at
		FROM device_tokens
		WHERE id = $1
	`

	var token models.DeviceToken
	err := r.db.QueryRow(query, tokenID).Scan(
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
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("device token not found")
		}
		return nil, fmt.Errorf("failed to get device token: %w", err)
	}

	return &token, nil
}
