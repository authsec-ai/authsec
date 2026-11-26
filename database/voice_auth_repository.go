package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// VoiceAuthRepository handles voice authentication database operations.
//
// Workspace-owned statements run through internal/tenancy under row-level
// security. Methods taking a ctx work in the workspace it carries (see
// WithWorkspace): the voice service passes the workspace of the session it
// found by token. Methods taking a workspace id, or a row that names its
// workspace, run in that workspace. Only the pre-auth lookup of a session by
// its random token and the platform cleanup jobs run without one.
type VoiceAuthRepository struct {
	db *DBConnection
}

// NewVoiceAuthRepository creates a new voice authentication repository
func NewVoiceAuthRepository(db *DBConnection) *VoiceAuthRepository {
	return &VoiceAuthRepository{db: db}
}

// requireRow returns a check of a statement's result that fails with
// notFound when the statement changed no row.
func requireRow(notFound string) func(sql.Result, error) error {
	return func(res sql.Result, err error) error {
		if err != nil {
			return err
		}
		if affected(res) == 0 {
			return errors.New(notFound)
		}
		return nil
	}
}

// ========================================
// Voice Session Operations
// ========================================

const voiceSessionColumns = `id, workspace_id, client_id, session_token, voice_otp,
		       otp_attempts, voice_platform, voice_user_id, device_info,
		       user_id, user_email, status, linked_device_code, scopes,
		       expires_at, verified_at, created_at, updated_at`

func scanVoiceSession(scan func(dest ...interface{}) error) (*models.VoiceSession, error) {
	vs := &models.VoiceSession{}
	var clientID, userID sql.NullString
	var voicePlatform, voiceUserID, userEmail, linkedDeviceCode sql.NullString
	var deviceInfoJSON, scopesJSON []byte
	var verifiedAt sql.NullInt64

	err := scan(
		&vs.ID,
		&vs.WorkspaceID,
		&clientID,
		&vs.SessionToken,
		&vs.VoiceOTP,
		&vs.OTPAttempts,
		&voicePlatform,
		&voiceUserID,
		&deviceInfoJSON,
		&userID,
		&userEmail,
		&vs.Status,
		&linkedDeviceCode,
		&scopesJSON,
		&vs.ExpiresAt,
		&verifiedAt,
		&vs.CreatedAt,
		&vs.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if clientID.Valid {
		id := uuid.MustParse(clientID.String)
		vs.ClientID = &id
	}
	if userID.Valid {
		id := uuid.MustParse(userID.String)
		vs.UserID = &id
	}
	if voicePlatform.Valid {
		vs.VoicePlatform = voicePlatform.String
	}
	if voiceUserID.Valid {
		vs.VoiceUserID = voiceUserID.String
	}
	if userEmail.Valid {
		vs.UserEmail = userEmail.String
	}
	if linkedDeviceCode.Valid {
		vs.LinkedDeviceCode = linkedDeviceCode.String
	}
	if verifiedAt.Valid {
		vs.VerifiedAt = &verifiedAt.Int64
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(deviceInfoJSON, &vs.DeviceInfo); err != nil {
		vs.DeviceInfo = make(map[string]interface{})
	}
	if err := json.Unmarshal(scopesJSON, &vs.Scopes); err != nil {
		vs.Scopes = []string{}
	}
	return vs, nil
}

// CreateVoiceSession creates a new voice authentication session in
// session.WorkspaceID.
func (r *VoiceAuthRepository) CreateVoiceSession(session *models.VoiceSession) error {
	scopesJSON, err := json.Marshal(session.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	deviceInfoJSON, err := json.Marshal(session.DeviceInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal device_info: %w", err)
	}

	now := time.Now().Unix()
	session.CreatedAt = now
	session.UpdatedAt = now

	return insertScoped(WithWorkspace(context.Background(), session.WorkspaceID), r.db.DB, `
		INSERT INTO voice_sessions (
			workspace_id, id, client_id, session_token, voice_otp,
			otp_attempts, voice_platform, voice_user_id, device_info,
			status, scopes, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		session.ID,
		session.ClientID,
		session.SessionToken,
		session.VoiceOTP,
		session.OTPAttempts,
		session.VoicePlatform,
		session.VoiceUserID,
		deviceInfoJSON,
		session.Status,
		scopesJSON,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
	)
}

// FindVoiceSessionByToken retrieves a voice session by session_token. The
// caller checks that the session is its client's.
func (r *VoiceAuthRepository) FindVoiceSessionByToken(sessionToken string) (*models.VoiceSession, error) {
	// TENANT-EXEMPT: pre-auth lookup by a random, unique session token; the row names its workspace and client.
	query := `SELECT ` + voiceSessionColumns + `
		FROM voice_sessions
		WHERE session_token = $1
	`
	vs, err := scanVoiceSession(r.db.QueryRow(query, sessionToken).Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("voice session not found")
	}
	return vs, err
}

// UpdateVoiceSessionStatus updates the status of a voice session of ctx's
// workspace.
func (r *VoiceAuthRepository) UpdateVoiceSessionStatus(ctx context.Context, sessionToken string, status string) error {
	_, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_sessions
		SET status = $2, updated_at = $3
		WHERE workspace_id = $1 AND session_token = $4
	`, status, time.Now().Unix(), sessionToken)
	return err
}

// IncrementOTPAttempts increments the OTP verification attempts of a voice
// session of ctx's workspace.
func (r *VoiceAuthRepository) IncrementOTPAttempts(ctx context.Context, sessionToken string) error {
	_, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_sessions
		SET otp_attempts = otp_attempts + 1, updated_at = $2
		WHERE workspace_id = $1 AND session_token = $3
	`, time.Now().Unix(), sessionToken)
	return err
}

// VerifyVoiceSession marks a voice session of ctx's workspace as verified.
func (r *VoiceAuthRepository) VerifyVoiceSession(ctx context.Context, sessionToken string, userID *uuid.UUID, userEmail string) error {
	now := time.Now().Unix()
	return requireRow("voice session not found or already processed")(tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_sessions
		SET status = 'verified', user_id = $2, user_email = $3, verified_at = $4, updated_at = $5
		WHERE workspace_id = $1 AND session_token = $6 AND status = 'initiated'
	`, userID, userEmail, now, now, sessionToken))
}

// LinkDeviceCode links a voice session of ctx's workspace to a device
// authorization code.
func (r *VoiceAuthRepository) LinkDeviceCode(ctx context.Context, sessionToken string, deviceCode string) error {
	_, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_sessions
		SET linked_device_code = $2, updated_at = $3
		WHERE workspace_id = $1 AND session_token = $4
	`, deviceCode, time.Now().Unix(), sessionToken)
	return err
}

// ExpireOldVoiceSessions marks expired voice sessions as expired
func (r *VoiceAuthRepository) ExpireOldVoiceSessions() (int64, error) {
	// TENANT-EXEMPT: platform cleanup job; touches only expired sessions, of every workspace.
	query := `
		UPDATE voice_sessions
		SET status = 'expired', updated_at = $1
		WHERE status = 'initiated' AND expires_at < $2
	`

	now := time.Now().Unix()
	result, err := r.db.Exec(query, now, now)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// DeleteExpiredVoiceSessions deletes old expired voice sessions for cleanup
func (r *VoiceAuthRepository) DeleteExpiredVoiceSessions(olderThan time.Duration) (int64, error) {
	// TENANT-EXEMPT: platform cleanup job; deletes only finished, expired sessions, of every workspace.
	query := `
		DELETE FROM voice_sessions
		WHERE status IN ('expired', 'failed', 'verified')
		AND expires_at < $1
	`

	cutoff := time.Now().Add(-olderThan).Unix()
	result, err := r.db.Exec(query, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// ========================================
// Voice Identity Link Operations
// ========================================

const voiceLinkColumns = `id, workspace_id, voice_platform, voice_user_id, voice_user_name,
		       user_id, user_email, is_active, link_method, last_used_at,
		       linked_at, created_at, updated_at`

func scanVoiceLink(scan func(dest ...interface{}) error) (*models.VoiceIdentityLink, error) {
	link := &models.VoiceIdentityLink{}
	var voiceUserName, linkMethod sql.NullString
	var lastUsedAt sql.NullInt64

	err := scan(
		&link.ID,
		&link.WorkspaceID,
		&link.VoicePlatform,
		&link.VoiceUserID,
		&voiceUserName,
		&link.UserID,
		&link.UserEmail,
		&link.IsActive,
		&linkMethod,
		&lastUsedAt,
		&link.LinkedAt,
		&link.CreatedAt,
		&link.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if voiceUserName.Valid {
		link.VoiceUserName = voiceUserName.String
	}
	if linkMethod.Valid {
		link.LinkMethod = linkMethod.String
	}
	if lastUsedAt.Valid {
		link.LastUsedAt = &lastUsedAt.Int64
	}
	return link, nil
}

// CreateVoiceIdentityLink creates a new voice identity link in
// link.WorkspaceID.
func (r *VoiceAuthRepository) CreateVoiceIdentityLink(link *models.VoiceIdentityLink) error {
	now := time.Now().Unix()
	link.CreatedAt = now
	link.UpdatedAt = now
	link.LinkedAt = now

	return insertScoped(WithWorkspace(context.Background(), link.WorkspaceID), r.db.DB, `
		INSERT INTO voice_identity_links (
			workspace_id, id, voice_platform, voice_user_id, voice_user_name,
			user_id, user_email, is_active, link_method, linked_at,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		link.ID,
		link.VoicePlatform,
		link.VoiceUserID,
		link.VoiceUserName,
		link.UserID,
		link.UserEmail,
		link.IsActive,
		link.LinkMethod,
		link.LinkedAt,
		link.CreatedAt,
		link.UpdatedAt,
	)
}

// FindVoiceIdentityLink retrieves a voice identity link
func (r *VoiceAuthRepository) FindVoiceIdentityLink(workspaceID uuid.UUID, voicePlatform string, voiceUserID string) (*models.VoiceIdentityLink, error) {
	link, err := scanVoiceLink(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+voiceLinkColumns+`
		FROM voice_identity_links
		WHERE workspace_id = $1 AND voice_platform = $2 AND voice_user_id = $3`,
			[]interface{}{voicePlatform, voiceUserID}, dest...)
	})
	if errors.Is(err, tenancy.ErrNotFound) {
		return nil, fmt.Errorf("voice identity link not found")
	}
	return link, err
}

// ListVoiceIdentityLinks lists all voice identity links for a user
func (r *VoiceAuthRepository) ListVoiceIdentityLinks(workspaceID uuid.UUID, userID uuid.UUID) ([]models.VoiceIdentityLink, error) {
	var links []models.VoiceIdentityLink
	err := queryScoped(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+voiceLinkColumns+`
		FROM voice_identity_links
		WHERE workspace_id = $1 AND user_id = $2
		ORDER BY linked_at DESC`, []interface{}{userID}, func(rows *sql.Rows) error {
		link, err := scanVoiceLink(rows.Scan)
		if err != nil {
			return err
		}
		links = append(links, *link)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return links, nil
}

// UpdateVoiceIdentityLinkLastUsed updates the last_used_at timestamp of a
// link of ctx's workspace.
func (r *VoiceAuthRepository) UpdateVoiceIdentityLinkLastUsed(ctx context.Context, linkID uuid.UUID) error {
	now := time.Now().Unix()
	_, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_identity_links
		SET last_used_at = $2, updated_at = $3
		WHERE workspace_id = $1 AND id = $4
	`, now, now, linkID)
	return err
}

// DeactivateVoiceIdentityLink deactivates a voice identity link
func (r *VoiceAuthRepository) DeactivateVoiceIdentityLink(workspaceID uuid.UUID, voicePlatform string, voiceUserID string) error {
	return requireRow("voice identity link not found")(tenancy.ExecContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `
		UPDATE voice_identity_links
		SET is_active = false, updated_at = $2
		WHERE workspace_id = $1 AND voice_platform = $3 AND voice_user_id = $4
	`, time.Now().Unix(), voicePlatform, voiceUserID))
}

// DeleteVoiceIdentityLink permanently deletes a voice identity link of ctx's
// workspace.
func (r *VoiceAuthRepository) DeleteVoiceIdentityLink(ctx context.Context, linkID uuid.UUID) error {
	return requireRow("voice identity link not found")(tenancy.ExecContext(ctx, r.db.DB,
		`DELETE FROM voice_identity_links WHERE workspace_id = $1 AND id = $2`, linkID))
}

// ========================================
// Code Generation Helpers
// ========================================

// GenerateSessionToken generates a secure random session token (128 characters max)
func GenerateSessionToken() (string, error) {
	bytes := make([]byte, 64) // 64 bytes = ~102 chars in base32 (well under 128)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)), nil
}

// GenerateVoiceOTP generates a 4-digit numeric OTP for voice
// Returns a string like "8532" which can be spoken as "eight-five-three-two"
func GenerateVoiceOTP() (string, error) {
	// Generate a random number between 0000 and 9999
	max := big.NewInt(10000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// Format as 4-digit string with leading zeros
	return fmt.Sprintf("%04d", n.Int64()), nil
}

// ========================================
// Voice Active Session Operations
// ========================================

const voiceActiveSessionColumns = `id, workspace_id, client_id, user_id, user_email, session_id,
		       voice_platform, voice_user_id, device_info, device_name,
		       access_token_hash, refresh_token_hash,
		       login_at, last_activity_at, expires_at,
		       is_active, revoked_at, revoked_reason, created_at, updated_at`

// CreateVoiceActiveSession creates a new active session record in
// session.WorkspaceID.
func (r *VoiceAuthRepository) CreateVoiceActiveSession(session *models.VoiceActiveSession) error {
	deviceInfoJSON, err := json.Marshal(session.DeviceInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal device_info: %w", err)
	}

	now := time.Now().Unix()
	session.CreatedAt = now
	session.UpdatedAt = now
	if session.LoginAt == 0 {
		session.LoginAt = now
	}
	if session.LastActivityAt == 0 {
		session.LastActivityAt = now
	}

	return insertScoped(WithWorkspace(context.Background(), session.WorkspaceID), r.db.DB, `
		INSERT INTO voice_active_sessions (
			workspace_id, id, client_id, user_id, user_email, session_id,
			voice_platform, voice_user_id, device_info, device_name,
			access_token_hash, refresh_token_hash,
			login_at, last_activity_at, expires_at,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		session.ID,
		session.ClientID,
		session.UserID,
		session.UserEmail,
		session.SessionID,
		session.VoicePlatform,
		session.VoiceUserID,
		deviceInfoJSON,
		session.DeviceName,
		session.AccessTokenHash,
		session.RefreshTokenHash,
		session.LoginAt,
		session.LastActivityAt,
		session.ExpiresAt,
		session.IsActive,
		session.CreatedAt,
		session.UpdatedAt,
	)
}

// findVoiceActiveSession reads one active session of ctx's workspace by the
// column named in where ($2).
func (r *VoiceAuthRepository) findVoiceActiveSession(ctx context.Context, where string, arg interface{}) (*models.VoiceActiveSession, error) {
	session, err := scanVoiceActiveSession(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, r.db.DB, `SELECT `+voiceActiveSessionColumns+`
		FROM voice_active_sessions
		WHERE workspace_id = $1 AND `+where+` = $2`, []interface{}{arg}, dest...)
	})
	if errors.Is(err, tenancy.ErrNotFound) {
		return nil, fmt.Errorf("voice active session not found")
	}
	return session, err
}

// FindVoiceActiveSessionByID retrieves an active session of ctx's workspace
// by ID.
func (r *VoiceAuthRepository) FindVoiceActiveSessionByID(ctx context.Context, sessionID uuid.UUID) (*models.VoiceActiveSession, error) {
	return r.findVoiceActiveSession(ctx, "id", sessionID)
}

// FindVoiceActiveSessionBySessionID retrieves an active session of ctx's
// workspace by session_id (jti).
func (r *VoiceAuthRepository) FindVoiceActiveSessionBySessionID(ctx context.Context, sessionID string) (*models.VoiceActiveSession, error) {
	return r.findVoiceActiveSession(ctx, "session_id", sessionID)
}

// FindVoiceActiveSessionByTokenHash retrieves an active session of ctx's
// workspace by token hash.
func (r *VoiceAuthRepository) FindVoiceActiveSessionByTokenHash(ctx context.Context, tokenHash string) (*models.VoiceActiveSession, error) {
	return r.findVoiceActiveSession(ctx, "access_token_hash", tokenHash)
}

// listVoiceActiveSessions lists the sessions of a user of workspaceID,
// newest first; activeOnly keeps the non-revoked, unexpired ones.
func (r *VoiceAuthRepository) listVoiceActiveSessions(workspaceID, userID uuid.UUID, activeOnly bool) ([]models.VoiceActiveSession, error) {
	var sessions []models.VoiceActiveSession
	err := queryScoped(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+voiceActiveSessionColumns+`
		FROM voice_active_sessions
		WHERE workspace_id = $1 AND user_id = $2 AND (NOT $3 OR (is_active = true AND expires_at > $4))
		ORDER BY login_at DESC`, []interface{}{userID, activeOnly, time.Now().Unix()}, func(rows *sql.Rows) error {
		session, err := scanVoiceActiveSession(rows.Scan)
		if err != nil {
			return err
		}
		sessions = append(sessions, *session)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// ListVoiceActiveSessions lists all active sessions for a user
func (r *VoiceAuthRepository) ListVoiceActiveSessions(workspaceID uuid.UUID, userID uuid.UUID) ([]models.VoiceActiveSession, error) {
	return r.listVoiceActiveSessions(workspaceID, userID, false)
}

// ListActiveVoiceSessions lists only active (non-revoked, non-expired) sessions
func (r *VoiceAuthRepository) ListActiveVoiceSessions(workspaceID uuid.UUID, userID uuid.UUID) ([]models.VoiceActiveSession, error) {
	return r.listVoiceActiveSessions(workspaceID, userID, true)
}

// RevokeVoiceActiveSession revokes a session of ctx's workspace.
func (r *VoiceAuthRepository) RevokeVoiceActiveSession(ctx context.Context, sessionID string, reason string) error {
	now := time.Now().Unix()
	return requireRow("session not found or already revoked")(tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_active_sessions
		SET is_active = false, revoked_at = $2, revoked_reason = $3, updated_at = $4
		WHERE workspace_id = $1 AND session_id = $5 AND is_active = true
	`, now, reason, now, sessionID))
}

// RevokeAllVoiceActiveSessions revokes all active sessions for a user
func (r *VoiceAuthRepository) RevokeAllVoiceActiveSessions(workspaceID uuid.UUID, userID uuid.UUID, reason string, exceptSessionID string) (int64, error) {
	now := time.Now().Unix()
	result, err := tenancy.ExecContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `
		UPDATE voice_active_sessions
		SET is_active = false, revoked_at = $2, revoked_reason = $3, updated_at = $4
		WHERE workspace_id = $1 AND user_id = $5 AND is_active = true AND session_id != $6
	`, now, reason, now, userID, exceptSessionID)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// UpdateVoiceActiveSessionActivity updates the last_activity_at timestamp of
// a session of ctx's workspace.
func (r *VoiceAuthRepository) UpdateVoiceActiveSessionActivity(ctx context.Context, sessionID string) error {
	now := time.Now().Unix()
	_, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_active_sessions
		SET last_activity_at = $2, updated_at = $3
		WHERE workspace_id = $1 AND session_id = $4 AND is_active = true
	`, now, now, sessionID)
	return err
}

// IsSessionRevoked checks if a session of ctx's workspace is revoked; a
// session that is not found (including another workspace's) counts as
// revoked.
func (r *VoiceAuthRepository) IsSessionRevoked(ctx context.Context, sessionID string) (bool, error) {
	var isActive bool
	var expiresAt int64
	err := tenancy.QueryRowContext(ctx, r.db.DB,
		`SELECT is_active, expires_at FROM voice_active_sessions WHERE workspace_id = $1 AND session_id = $2`,
		[]interface{}{sessionID}, &isActive, &expiresAt)
	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return true, nil // Session not found = treated as revoked
		}
		return false, err
	}

	// Session is revoked if not active OR expired
	return !isActive || time.Now().Unix() > expiresAt, nil
}

// CountActiveSessionsForUser counts active sessions for a user
func (r *VoiceAuthRepository) CountActiveSessionsForUser(workspaceID uuid.UUID, userID uuid.UUID) (int, error) {
	var count int
	err := tenancy.QueryRowContext(WithWorkspace(context.Background(), workspaceID), r.db.DB, `
		SELECT COUNT(*) FROM voice_active_sessions
		WHERE workspace_id = $1 AND user_id = $2 AND is_active = true AND expires_at > $3
	`, []interface{}{userID, time.Now().Unix()}, &count)
	return count, err
}

// CleanupExpiredVoiceActiveSessions marks expired sessions as inactive
func (r *VoiceAuthRepository) CleanupExpiredVoiceActiveSessions() (int64, error) {
	// TENANT-EXEMPT: platform cleanup job; touches only expired sessions, of every workspace.
	query := `
		UPDATE voice_active_sessions
		SET is_active = false, revoked_at = $1, revoked_reason = 'expired', updated_at = $2
		WHERE is_active = true AND expires_at < $3
	`

	now := time.Now().Unix()
	result, err := r.db.Exec(query, now, now, now)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// DeleteOldVoiceActiveSessions deletes old inactive sessions
func (r *VoiceAuthRepository) DeleteOldVoiceActiveSessions(olderThan time.Duration) (int64, error) {
	// TENANT-EXEMPT: platform cleanup job; deletes only long-revoked sessions, of every workspace.
	query := `
		DELETE FROM voice_active_sessions
		WHERE is_active = false AND revoked_at < $1
	`

	cutoff := time.Now().Add(-olderThan).Unix()
	result, err := r.db.Exec(query, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// scanVoiceActiveSession scans one voiceActiveSessionColumns row.
func scanVoiceActiveSession(scan func(dest ...interface{}) error) (*models.VoiceActiveSession, error) {
	session := &models.VoiceActiveSession{}
	var clientID sql.NullString
	var voicePlatform, voiceUserID, deviceName sql.NullString
	var deviceInfoJSON []byte
	var accessTokenHash, refreshTokenHash sql.NullString
	var revokedAt sql.NullInt64
	var revokedReason sql.NullString

	err := scan(
		&session.ID,
		&session.WorkspaceID,
		&clientID,
		&session.UserID,
		&session.UserEmail,
		&session.SessionID,
		&voicePlatform,
		&voiceUserID,
		&deviceInfoJSON,
		&deviceName,
		&accessTokenHash,
		&refreshTokenHash,
		&session.LoginAt,
		&session.LastActivityAt,
		&session.ExpiresAt,
		&session.IsActive,
		&revokedAt,
		&revokedReason,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if clientID.Valid {
		id := uuid.MustParse(clientID.String)
		session.ClientID = &id
	}
	if voicePlatform.Valid {
		session.VoicePlatform = voicePlatform.String
	}
	if voiceUserID.Valid {
		session.VoiceUserID = voiceUserID.String
	}
	if deviceName.Valid {
		session.DeviceName = deviceName.String
	}
	if accessTokenHash.Valid {
		session.AccessTokenHash = accessTokenHash.String
	}
	if refreshTokenHash.Valid {
		session.RefreshTokenHash = refreshTokenHash.String
	}
	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Int64
	}
	if revokedReason.Valid {
		session.RevokedReason = revokedReason.String
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(deviceInfoJSON, &session.DeviceInfo); err != nil {
		session.DeviceInfo = make(map[string]interface{})
	}

	return session, nil
}

// ========================================
// Pending Voice Auth Request Operations
// ========================================

// SetVoiceSessionPendingApproval marks a voice session of ctx's workspace as
// pending approval.
func (r *VoiceAuthRepository) SetVoiceSessionPendingApproval(ctx context.Context, sessionToken string, pending bool) error {
	status := ""
	if pending {
		status = "pending"
	}

	_, err := tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_sessions
		SET pending_approval = $2, approval_status = $3, updated_at = $4
		WHERE workspace_id = $1 AND session_token = $5
	`, pending, status, time.Now().Unix(), sessionToken)
	return err
}

// ApproveVoiceSession approves or denies a pending voice session of ctx's
// workspace.
func (r *VoiceAuthRepository) ApproveVoiceSession(ctx context.Context, sessionToken string, approve bool, approverUserID uuid.UUID) error {
	status := "denied"
	if approve {
		status = "approved"
	}

	now := time.Now().Unix()
	return requireRow("voice session not found or not pending approval")(tenancy.ExecContext(ctx, r.db.DB, `
		UPDATE voice_sessions
		SET pending_approval = false, approval_status = $2, approved_at = $3, approved_by = $4, updated_at = $5
		WHERE workspace_id = $1 AND session_token = $6 AND pending_approval = true
	`, status, now, approverUserID, now, sessionToken))
}

// ListPendingVoiceSessions lists pending voice auth requests for a tenant
func (r *VoiceAuthRepository) ListPendingVoiceSessions(workspaceID uuid.UUID) ([]models.VoiceSession, error) {
	var sessions []models.VoiceSession
	err := queryScoped(WithWorkspace(context.Background(), workspaceID), r.db.DB, `SELECT `+voiceSessionColumns+`
		FROM voice_sessions
		WHERE workspace_id = $1 AND pending_approval = true AND approval_status = 'pending' AND expires_at > $2
		ORDER BY created_at DESC`, []interface{}{time.Now().Unix()}, func(rows *sql.Rows) error {
		vs, err := scanVoiceSession(rows.Scan)
		if err != nil {
			return err
		}
		sessions = append(sessions, *vs)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetVoiceSessionApprovalStatus gets the approval status of a voice session
// of ctx's workspace.
func (r *VoiceAuthRepository) GetVoiceSessionApprovalStatus(ctx context.Context, sessionToken string) (string, error) {
	var status string
	err := tenancy.QueryRowContext(ctx, r.db.DB,
		`SELECT COALESCE(approval_status, '') FROM voice_sessions WHERE workspace_id = $1 AND session_token = $2`,
		[]interface{}{sessionToken}, &status)
	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return "", fmt.Errorf("voice session not found")
		}
		return "", err
	}

	return status, nil
}

// GenerateSessionID generates a unique session ID for JWT jti claim
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)), nil
}
