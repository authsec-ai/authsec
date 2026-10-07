package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Purposes of an emailed one-time code (otp_entries.purpose, 068). A code
// issued for one purpose never verifies, unlocks or deletes another (AS-038).
const (
	// OTPPurposeWorkspaceSignup: admin sign-up / workspace bootstrap (no
	// workspace exists yet).
	OTPPurposeWorkspaceSignup = "workspace_signup"
	// OTPPurposeAdminLogin: admin login fallback when no MFA is configured.
	OTPPurposeAdminLogin = "admin_login"
	// OTPPurposeAdminPasswordReset: admin forgot-password.
	OTPPurposeAdminPasswordReset = "admin_password_reset"
	// OTPPurposeEndUserRegister: end-user self-registration in a workspace.
	OTPPurposeEndUserRegister = "enduser_register"
	// OTPPurposeEndUserPasswordReset: end-user forgot-password in a workspace.
	OTPPurposeEndUserPasswordReset = "enduser_password_reset"
)

// OTPScope selects the otp_entries rows of one flow: the purpose, and the
// workspace the code was issued in (nil when the flow has none). AnyWorkspace
// matches every workspace of that purpose; use it only where the decisive
// later step re-checks the row's workspace.
type OTPScope struct {
	Purpose      string
	WorkspaceID  *uuid.UUID
	AnyWorkspace bool
}

// OTPScopeFor is the scope of purpose in workspace ws (uuid.Nil = none).
func OTPScopeFor(purpose string, ws uuid.UUID) OTPScope {
	if ws == uuid.Nil {
		return OTPScope{Purpose: purpose}
	}
	return OTPScope{Purpose: purpose, WorkspaceID: &ws}
}

// OTPScopeForString is OTPScopeFor with the workspace as a string from a
// request; an unparsable value selects no workspace, so it matches only rows
// issued without one.
func OTPScopeForString(purpose, ws string) OTPScope {
	id, err := uuid.Parse(ws)
	if err != nil {
		id = uuid.Nil
	}
	return OTPScopeFor(purpose, id)
}

// where returns the predicate for scope, with its arguments numbered from n.
func (s OTPScope) where(n int) (string, []interface{}) {
	if s.AnyWorkspace {
		return fmt.Sprintf("purpose = $%d", n), []interface{}{s.Purpose}
	}
	return fmt.Sprintf("purpose = $%d AND workspace_id IS NOT DISTINCT FROM $%d", n, n+1),
		[]interface{}{s.Purpose, s.WorkspaceID}
}

// OTPRepository handles OTP database operations without GORM.
//
// otp_entries is read before authentication, by (email, purpose, workspace):
// the raw statements below are scoped by that predicate rather than by the
// tenancy package.
type OTPRepository struct {
	db *DBConnection
}

// NewOTPRepository creates a new OTP repository
func NewOTPRepository(db *DBConnection) *OTPRepository {
	return &OTPRepository{db: db}
}

type otpQueryRower interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

func createOTP(q otpQueryRower, otp *models.OTPEntry) error {
	if otp.Purpose == "" {
		return fmt.Errorf("otp: purpose is required")
	}
	now := time.Now()
	if otp.CreatedAt.IsZero() {
		otp.CreatedAt = now
	}
	if otp.UpdatedAt.IsZero() {
		otp.UpdatedAt = now
	}
	// TENANT-EXEMPT: pre-auth code row; workspace_id is part of the row itself
	return q.QueryRow(`INSERT INTO otp_entries (email, otp, expires_at, verified, created_at, updated_at, purpose, workspace_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		otp.Email, otp.OTP, otp.ExpiresAt, otp.Verified, otp.CreatedAt, otp.UpdatedAt,
		otp.Purpose, otp.WorkspaceID,
	).Scan(&otp.ID)
}

// CreateOTP creates a new OTP entry. otp.Purpose is required; set
// otp.WorkspaceID when the flow has a workspace.
func (or *OTPRepository) CreateOTP(otp *models.OTPEntry) error {
	return createOTP(or.db, otp)
}

func (or *OTPRepository) getOTP(scope OTPScope, email string, extra string, extraArgs ...interface{}) (*models.OTPEntry, error) {
	pred, args := scope.where(2 + len(extraArgs))
	query := `SELECT id, email, otp, expires_at, verified, created_at, updated_at, purpose, workspace_id
		FROM otp_entries -- TENANT-EXEMPT: scoped by (email, purpose, workspace_id)
		WHERE email = $1 AND ` + extra + ` AND ` + pred + `
		ORDER BY created_at DESC
		LIMIT 1`
	all := append(append([]interface{}{email}, extraArgs...), args...)
	otp := &models.OTPEntry{}
	err := or.db.QueryRow(query, all...).Scan(
		&otp.ID, &otp.Email, &otp.OTP, &otp.ExpiresAt, &otp.Verified, &otp.CreatedAt, &otp.UpdatedAt,
		&otp.Purpose, &otp.WorkspaceID,
	)
	if err != nil {
		return nil, err
	}
	return otp, nil
}

// GetValidOTP retrieves a valid (non-expired, unverified) OTP of scope for an email
func (or *OTPRepository) GetValidOTP(scope OTPScope, email, otpCode string) (*models.OTPEntry, error) {
	// 1-second grace period for timing precision right after creation.
	gracePeriod := time.Now().Add(-1 * time.Second)
	otp, err := or.getOTP(scope, email, "otp = $2 AND expires_at > $3 AND verified = false", otpCode, gracePeriod)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("valid OTP not found")
	}
	return otp, err
}

// GetVerifiedOTP retrieves a verified, unexpired OTP of scope for an email
func (or *OTPRepository) GetVerifiedOTP(scope OTPScope, email string) (*models.OTPEntry, error) {
	otp, err := or.getOTP(scope, email, "verified = true AND expires_at > $2", time.Now())
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("verified OTP not found")
	}
	return otp, err
}

// VerifyOTP marks an OTP as verified
func (or *OTPRepository) VerifyOTP(otpID uuid.UUID) error {
	query := `
		UPDATE otp_entries -- TENANT-EXEMPT: by primary key of a row read through its scope
		SET verified = true, updated_at = $1
		WHERE id = $2
	`

	result, err := or.db.Exec(query, time.Now(), otpID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("OTP not found")
	}

	return nil
}

type otpExecer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func deleteOTPs(e otpExecer, scope OTPScope, email string) error {
	pred, args := scope.where(2)
	// TENANT-EXEMPT: scoped by (email, purpose, workspace_id)
	_, err := e.Exec(`DELETE FROM otp_entries WHERE email = $1 AND `+pred, append([]interface{}{email}, args...)...)
	return err
}

// DeleteOTPsByEmail deletes the OTP entries of one scope for an email (cleanup)
func (or *OTPRepository) DeleteOTPsByEmail(scope OTPScope, email string) error {
	return deleteOTPs(or.db, scope, email)
}

// DeleteExpiredOTPs deletes all expired OTP entries (cleanup job)
func (or *OTPRepository) DeleteExpiredOTPs() error {
	query := `DELETE FROM otp_entries WHERE expires_at < $1` // TENANT-EXEMPT: platform-wide expiry sweep

	_, err := or.db.Exec(query, time.Now())
	return err
}

// HasValidOTP checks if there's a valid OTP of scope for an email
func (or *OTPRepository) HasValidOTP(scope OTPScope, email string) (bool, error) {
	_, err := or.getOTP(scope, email, "expires_at > $2 AND verified = false", time.Now())
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// Transaction support

// CreateOTPTx creates an OTP within a transaction
func (or *OTPRepository) CreateOTPTx(tx *sql.Tx, otp *models.OTPEntry) error {
	return createOTP(tx, otp)
}

// VerifyOTPTx marks an OTP as verified within a transaction
func (or *OTPRepository) VerifyOTPTx(tx *sql.Tx, otpID uuid.UUID) error {
	query := `
		UPDATE otp_entries -- TENANT-EXEMPT: by primary key of a row read through its scope
		SET verified = true, updated_at = $1
		WHERE id = $2
	`

	result, err := tx.Exec(query, time.Now(), otpID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("OTP not found")
	}

	return nil
}

// DeleteOTPsByEmailTx deletes the OTPs of one scope for an email within a transaction
func (or *OTPRepository) DeleteOTPsByEmailTx(tx *sql.Tx, scope OTPScope, email string) error {
	return deleteOTPs(tx, scope, email)
}

// PendingRegistrationRepository handles pending registration database operations
type PendingRegistrationRepository struct {
	db *DBConnection
}

// NewPendingRegistrationRepository creates a new pending registration repository
func NewPendingRegistrationRepository(db *DBConnection) *PendingRegistrationRepository {
	return &PendingRegistrationRepository{db: db}
}

// CreatePendingRegistration creates a new pending registration
func (pr *PendingRegistrationRepository) CreatePendingRegistration(pending *models.PendingRegistration) error {
	// Phase A: client_id column removed from pending_registrations.
	query := `
		INSERT INTO pending_registrations (email, password_hash, first_name, last_name, // TENANT-EXEMPT: sign-up before the workspace exists
			workspace_id, project_id, expires_at, created_at, updated_at, workspace_domain)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`

	now := time.Now()
	if pending.CreatedAt.IsZero() {
		pending.CreatedAt = now
	}
	if pending.UpdatedAt.IsZero() {
		pending.UpdatedAt = now
	}

	err := pr.db.QueryRow(query,
		pending.Email,
		pending.PasswordHash,
		pending.FirstName,
		pending.LastName,
		pending.WorkspaceID,
		pending.ProjectID,
		pending.ExpiresAt,
		pending.CreatedAt,
		pending.UpdatedAt,
		pending.WorkspaceDomain,
	).Scan(&pending.ID)

	return err
}

// GetPendingRegistration retrieves a pending registration by email
func (pr *PendingRegistrationRepository) GetPendingRegistration(email string) (*models.PendingRegistration, error) {
	// Phase A: client_id column removed from pending_registrations.
	query := `
		SELECT id, email, password_hash, first_name, last_name, workspace_id,
			project_id, expires_at, created_at, updated_at, workspace_domain
		FROM pending_registrations
		WHERE email = $1 AND expires_at > $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	pending := &models.PendingRegistration{}
	err := pr.db.QueryRow(query, email, time.Now()).Scan(
		&pending.ID,
		&pending.Email,
		&pending.PasswordHash,
		&pending.FirstName,
		&pending.LastName,
		&pending.WorkspaceID,
		&pending.ProjectID,
		&pending.ExpiresAt,
		&pending.CreatedAt,
		&pending.UpdatedAt,
		&pending.WorkspaceDomain,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Not found is a valid case - return nil, nil so caller can create new registration
			return nil, nil
		}
		return nil, err
	}

	return pending, nil
}

// DeletePendingRegistrationsByEmail deletes pending registrations by email (cleanup)
func (pr *PendingRegistrationRepository) DeletePendingRegistrationsByEmail(email string) error {
	query := `DELETE FROM pending_registrations WHERE email = $1` // TENANT-EXEMPT: pending sign-up keyed by email before a workspace exists

	_, err := pr.db.Exec(query, email)
	return err
}

// DeleteExpiredPendingRegistrations deletes expired pending registrations (cleanup job)
func (pr *PendingRegistrationRepository) DeleteExpiredPendingRegistrations() error {
	query := `DELETE FROM pending_registrations WHERE expires_at < $1` // TENANT-EXEMPT: platform-wide expiry sweep

	_, err := pr.db.Exec(query, time.Now())
	return err
}

// Transaction support

// DeletePendingRegistrationsByEmailTx deletes pending registrations within a transaction
func (pr *PendingRegistrationRepository) DeletePendingRegistrationsByEmailTx(tx *sql.Tx, email string) error {
	query := `DELETE FROM pending_registrations WHERE email = $1` // TENANT-EXEMPT: pending sign-up keyed by email before a workspace exists

	_, err := tx.Exec(query, email)
	return err
}

// UpdatePendingRegistration updates an existing pending registration
func (pr *PendingRegistrationRepository) UpdatePendingRegistration(pending *models.PendingRegistration) error {
	// Phase A: client_id column removed from pending_registrations.
	query := `
		UPDATE pending_registrations
		SET password_hash = $1, workspace_id = $2, project_id = $3,
		    workspace_domain = $4, expires_at = $5, updated_at = $6
		WHERE email = $7
	`

	now := time.Now()
	pending.UpdatedAt = now

	_, err := pr.db.Exec(query,
		pending.PasswordHash,
		pending.WorkspaceID,
		pending.ProjectID,
		pending.WorkspaceDomain,
		pending.ExpiresAt,
		pending.UpdatedAt,
		pending.Email,
	)

	return err
}
