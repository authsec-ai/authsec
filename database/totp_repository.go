package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// TOTPRepository handles database operations for TOTP authentication. Every
// method works in the workspace carried by ctx (see WithWorkspace), through
// internal/tenancy under row-level security.
type TOTPRepository struct {
	db *sql.DB
}

// NewTOTPRepository creates a new TOTP repository
func NewTOTPRepository(db *sql.DB) *TOTPRepository {
	return &TOTPRepository{db: db}
}

const totpSecretColumns = `id, user_id, workspace_id, secret, device_name, device_type, last_used,
	          is_active, is_primary, created_at, updated_at`

// CreateTOTPSecret stores a new TOTP secret in ctx's workspace.
func (r *TOTPRepository) CreateTOTPSecret(ctx context.Context, secret *models.TOTPSecret) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}
	now := time.Now().Unix()
	secret.WorkspaceID = ws
	secret.CreatedAt = now
	secret.UpdatedAt = now

	return insertScoped(ctx, r.db, `
		INSERT INTO totp_secrets (
			workspace_id, id, user_id, secret, device_name, device_type,
			is_active, is_primary, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		secret.ID, secret.UserID, secret.Secret,
		secret.DeviceName, secret.DeviceType, secret.IsActive,
		secret.IsPrimary, secret.CreatedAt, secret.UpdatedAt,
	)
}

// UpdateTOTPSecret updates a TOTP secret of ctx's workspace.
func (r *TOTPRepository) UpdateTOTPSecret(ctx context.Context, secret *models.TOTPSecret) error {
	secret.UpdatedAt = time.Now().Unix()
	_, err := tenancy.ExecContext(ctx, r.db, `
		UPDATE totp_secrets
		SET device_name = $2, is_active = $3, is_primary = $4, updated_at = $5
		WHERE workspace_id = $1 AND id = $6 AND user_id = $7`,
		secret.DeviceName, secret.IsActive, secret.IsPrimary,
		secret.UpdatedAt, secret.ID, secret.UserID,
	)
	return err
}

// UpdateLastUsed updates the last_used timestamp
func (r *TOTPRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := tenancy.ExecContext(ctx, r.db,
		`UPDATE totp_secrets SET last_used = $2, updated_at = $2 WHERE workspace_id = $1 AND id = $3`,
		time.Now().Unix(), id)
	return err
}

// GetTOTPSecretByID retrieves a TOTP secret of a user in ctx's workspace.
func (r *TOTPRepository) GetTOTPSecretByID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.TOTPSecret, error) {
	s, err := scanTOTPSecret(func(dest ...interface{}) error {
		return tenancy.QueryRowContext(ctx, r.db, `SELECT `+totpSecretColumns+`
	          FROM totp_secrets WHERE workspace_id = $1 AND id = $2 AND user_id = $3`,
			[]interface{}{id, userID}, dest...)
	})
	if errors.Is(err, tenancy.ErrNotFound) {
		return nil, sql.ErrNoRows
	}
	return s, err
}

// GetUserTOTPSecrets retrieves the active TOTP secrets of a user in ctx's
// workspace.
func (r *TOTPRepository) GetUserTOTPSecrets(ctx context.Context, userID uuid.UUID) ([]models.TOTPSecret, error) {
	var secrets []models.TOTPSecret
	err := queryScoped(ctx, r.db, `SELECT `+totpSecretColumns+`
	          FROM totp_secrets
	          WHERE workspace_id = $1 AND user_id = $2 AND is_active = true
	          ORDER BY is_primary DESC, created_at DESC`,
		[]interface{}{userID}, func(rows *sql.Rows) error {
			s, err := scanTOTPSecret(rows.Scan)
			if err != nil {
				return err
			}
			secrets = append(secrets, *s)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

// DeleteTOTPSecret deletes a TOTP secret of a user in ctx's workspace;
// sql.ErrNoRows when there is none.
func (r *TOTPRepository) DeleteTOTPSecret(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	result, err := tenancy.ExecContext(ctx, r.db,
		`DELETE FROM totp_secrets WHERE workspace_id = $1 AND id = $2 AND user_id = $3`, id, userID)
	if err != nil {
		return err
	}
	if affected(result) == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetPrimaryTOTPSecret sets a device as primary (unsets others)
func (r *TOTPRepository) SetPrimaryTOTPSecret(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	return tenancy.WithTx(ctx, r.db, ws, func(tx *sql.Tx) error {
		// Unset all primary flags for user
		if _, err := tenancy.ExecContext(ctx, tx,
			`UPDATE totp_secrets SET is_primary = false WHERE workspace_id = $1 AND user_id = $2`, userID); err != nil {
			return err
		}
		// Set this device as primary
		_, err := tenancy.ExecContext(ctx, tx,
			`UPDATE totp_secrets SET is_primary = true, updated_at = $2 WHERE workspace_id = $1 AND id = $3 AND user_id = $4`,
			time.Now().Unix(), id, userID)
		return err
	})
}

// ============================
// Backup Codes
// ============================

// CreateBackupCode stores a new backup code in ctx's workspace.
func (r *TOTPRepository) CreateBackupCode(ctx context.Context, code *models.BackupCode) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	if code.ID == uuid.Nil {
		code.ID = uuid.New()
	}
	code.WorkspaceID = ws
	code.CreatedAt = time.Now().Unix()

	return insertScoped(ctx, r.db, `
		INSERT INTO totp_backup_codes (workspace_id, id, user_id, code, is_used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		code.ID, code.UserID, code.Code, code.IsUsed, code.CreatedAt)
}

// GetUserBackupCodes retrieves the backup codes of a user in ctx's workspace.
func (r *TOTPRepository) GetUserBackupCodes(ctx context.Context, userID uuid.UUID) ([]models.BackupCode, error) {
	var codes []models.BackupCode
	err := queryScoped(ctx, r.db, `SELECT id, user_id, workspace_id, code, is_used, created_at, used_at
	          FROM totp_backup_codes
	          WHERE workspace_id = $1 AND user_id = $2
	          ORDER BY created_at DESC`,
		[]interface{}{userID}, func(rows *sql.Rows) error {
			var c models.BackupCode
			if err := rows.Scan(&c.ID, &c.UserID, &c.WorkspaceID, &c.Code, &c.IsUsed, &c.CreatedAt, &c.UsedAt); err != nil {
				return err
			}
			codes = append(codes, c)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// UseBackupCode marks an unused backup code as used. It reports whether this
// call used it, so two concurrent sign-ins cannot both spend the same code.
func (r *TOTPRepository) UseBackupCode(ctx context.Context, codeID uuid.UUID) (bool, error) {
	res, err := tenancy.ExecContext(ctx, r.db,
		`UPDATE totp_backup_codes SET is_used = true, used_at = $2 WHERE workspace_id = $1 AND id = $3 AND is_used = false`,
		time.Now().Unix(), codeID)
	if err != nil {
		return false, err
	}
	return affected(res) == 1, nil
}

// DeleteBackupCodes deletes all backup codes of a user in ctx's workspace.
func (r *TOTPRepository) DeleteBackupCodes(ctx context.Context, userID uuid.UUID) error {
	_, err := tenancy.ExecContext(ctx, r.db,
		`DELETE FROM totp_backup_codes WHERE workspace_id = $1 AND user_id = $2`, userID)
	return err
}

// scanTOTPSecret scans one totpSecretColumns row through scan.
func scanTOTPSecret(scan func(dest ...interface{}) error) (*models.TOTPSecret, error) {
	var s models.TOTPSecret
	err := scan(
		&s.ID, &s.UserID, &s.WorkspaceID, &s.Secret, &s.DeviceName, &s.DeviceType,
		&s.LastUsed, &s.IsActive, &s.IsPrimary, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
