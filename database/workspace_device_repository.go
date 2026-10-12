package database

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TenantDeviceRepository handles the workspace plane's push devices, CIBA
// requests, TOTP secrets and backup codes. Every method runs in one
// workspace through tenancy.Transaction: the workspace predicate is added
// to every statement and Postgres row-level security is in force. The
// workspace is the one the caller resolved from the verified token, or from
// the OAuth client of a pre-auth request; for a model the repository writes,
// it is the model's WorkspaceID.
type TenantDeviceRepository struct {
	db *gorm.DB
}

// NewTenantDeviceRepository creates a new tenant device repository
func NewTenantDeviceRepository(db *gorm.DB) *TenantDeviceRepository {
	return &TenantDeviceRepository{db: db}
}

// in runs fn in workspace ws (see tenancy.Transaction).
func (r *TenantDeviceRepository) in(ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	if ws == uuid.Nil {
		return tenancy.ErrNoTenant
	}
	return tenancy.Transaction(WithWorkspace(context.Background(), ws), r.db, fn)
}

// ========================================
// Tenant Device Token Operations
// ========================================

// CreateTenantDeviceToken registers a new device for push notifications in
// the token's workspace.
func (r *TenantDeviceRepository) CreateTenantDeviceToken(token *models.TenantDeviceToken) error {
	now := time.Now().Unix()
	token.CreatedAt = now
	token.UpdatedAt = now

	err := r.in(token.WorkspaceID, func(tx *gorm.DB) error { return tx.Create(token).Error })
	if err != nil {
		// workspace_device_tokens FKs (master bootstrap): fk_workspace_device
		// (workspace_id) and fk_workspace_device_user (user_id, workspace_id).
		if strings.Contains(err.Error(), "fk_workspace_device_user") {
			return errors.New("user_not_found")
		}
		if strings.Contains(err.Error(), "fk_workspace_device") {
			return errors.New("tenant_not_found")
		}
		return err
	}
	return nil
}

// GetTenantDeviceTokensByUserID retrieves all active device tokens for a user in tenant DB
func (r *TenantDeviceRepository) GetTenantDeviceTokensByUserID(userID, workspaceID uuid.UUID) ([]models.TenantDeviceToken, error) {
	var tokens []models.TenantDeviceToken
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("user_id = ? AND is_active = ?", userID, true).
			Order("created_at DESC").
			Find(&tokens).Error
	})
	return tokens, err
}

// GetTenantDeviceTokenByToken retrieves device token by device token string
func (r *TenantDeviceRepository) GetTenantDeviceTokenByToken(deviceToken string, workspaceID uuid.UUID) (*models.TenantDeviceToken, error) {
	var token models.TenantDeviceToken
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("device_token = ?", deviceToken).First(&token).Error
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil when not found (different from error)
		}
		return nil, err
	}
	return &token, nil
}

// DeactivateTenantDeviceToken deactivates a device token
func (r *TenantDeviceRepository) DeactivateTenantDeviceToken(tokenID, userID, workspaceID uuid.UUID) error {
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.TenantDeviceToken{}).
			Where("id = ? AND user_id = ?", tokenID, userID).
			Update("is_active", false).Error
	})
}

// UpdateTenantDeviceToken updates an existing device token
func (r *TenantDeviceRepository) UpdateTenantDeviceToken(token *models.TenantDeviceToken) error {
	token.UpdatedAt = time.Now().Unix()
	return r.in(token.WorkspaceID, func(tx *gorm.DB) error { return tx.Save(token).Error })
}

// ========================================
// Tenant CIBA Operations
// ========================================

// CreateTenantCIBAAuthRequest creates a new CIBA authentication request in
// the request's workspace.
func (r *TenantDeviceRepository) CreateTenantCIBAAuthRequest(request *models.TenantCIBAAuthRequest) error {
	now := time.Now().Unix()
	request.CreatedAt = now
	request.ExpiresAt = now + 300 // 5 minutes expiration

	err := r.in(request.WorkspaceID, func(tx *gorm.DB) error { return tx.Create(request).Error })
	if err != nil {
		// workspace_ciba_auth_requests FKs (master bootstrap): fk_workspace_ciba
		// (workspace_id), fk_workspace_ciba_user (user_id, workspace_id),
		// fk_workspace_ciba_device (device_token_id, workspace_id).
		if strings.Contains(err.Error(), "fk_workspace_ciba_user") {
			return errors.New("user_not_found")
		}
		if strings.Contains(err.Error(), "fk_workspace_ciba_device") {
			return errors.New("device_not_found")
		}
		if strings.Contains(err.Error(), "fk_workspace_ciba") {
			return errors.New("tenant_not_found")
		}
		return err
	}
	return nil
}

// GetTenantCIBAAuthRequestByAuthReqID retrieves CIBA request by auth_req_id
func (r *TenantDeviceRepository) GetTenantCIBAAuthRequestByAuthReqID(authReqID string, workspaceID uuid.UUID) (*models.TenantCIBAAuthRequest, error) {
	var request models.TenantCIBAAuthRequest
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("auth_req_id = ?", authReqID).First(&request).Error
	})
	if err != nil {
		return nil, err
	}
	return &request, nil
}

// UpdateTenantCIBAAuthRequest updates CIBA request status and response
func (r *TenantDeviceRepository) UpdateTenantCIBAAuthRequest(request *models.TenantCIBAAuthRequest) error {
	return r.in(request.WorkspaceID, func(tx *gorm.DB) error { return tx.Save(request).Error })
}

// UpdateTenantCIBAAuthRequestStatusIf atomically transitions a CIBA request from
// fromStatus → status in a single conditional UPDATE (Appendix §6 first-responder-
// wins). It returns (won, err): won is true iff exactly one row transitioned
// (RowsAffected==1) — i.e. this caller observed the request still in fromStatus
// and flipped it. A won==false with nil err means another caller already moved
// it out of fromStatus (the loser must treat this idempotently, never re-mint).
//
// The `AND status = ?` guard is the whole point: without it two concurrent
// responders (multi-device CIBA) or two concurrent token polls would both
// "succeed" and the second would clobber the first / double-mint.
func (r *TenantDeviceRepository) UpdateTenantCIBAAuthRequestStatusIf(authReqID string, workspaceID uuid.UUID, fromStatus, status string, approved bool, biometricVerified bool) (bool, error) {
	updates := map[string]interface{}{
		"status":             status,
		"biometric_verified": biometricVerified,
	}

	if status == "approved" || status == "denied" {
		now := time.Now().Unix()
		updates["responded_at"] = now
	}

	var rows int64
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		res := tx.Model(&models.TenantCIBAAuthRequest{}).
			Where("auth_req_id = ? AND status = ?", authReqID, fromStatus).
			Updates(updates)
		rows = res.RowsAffected
		return res.Error
	})
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

// UpdateTenantCIBAAuthRequestLastPolled updates the last_polled_at timestamp
func (r *TenantDeviceRepository) UpdateTenantCIBAAuthRequestLastPolled(authReqID string, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.TenantCIBAAuthRequest{}).
			Where("auth_req_id = ?", authReqID).
			Update("last_polled_at", now).Error
	})
}

// GetPendingTenantCIBAAuthRequests gets all pending CIBA requests for a user
func (r *TenantDeviceRepository) GetPendingTenantCIBAAuthRequests(userID, workspaceID uuid.UUID) ([]models.TenantCIBAAuthRequest, error) {
	var requests []models.TenantCIBAAuthRequest
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("user_id = ? AND status = ?", userID, "pending").
			Where("expires_at > ?", time.Now().Unix()).
			Order("created_at DESC").
			Find(&requests).Error
	})
	return requests, err
}

// ========================================
// Tenant TOTP Operations
// ========================================

// CreateTenantTOTPSecret stores a new TOTP secret in the secret's workspace.
func (r *TenantDeviceRepository) CreateTenantTOTPSecret(secret *models.TenantTOTPSecret) error {
	now := time.Now().Unix()
	secret.CreatedAt = now
	secret.UpdatedAt = now

	err := r.in(secret.WorkspaceID, func(tx *gorm.DB) error { return tx.Create(secret).Error })
	if err != nil {
		if strings.Contains(err.Error(), "fk_tenant_totp_tenant") {
			return errors.New("tenant_not_found")
		}
		if strings.Contains(err.Error(), "fk_tenant_totp_user") {
			return errors.New("user_not_found")
		}
		return err
	}
	return nil
}

// GetTenantTOTPSecretByID retrieves a TOTP secret by ID in tenant DB
func (r *TenantDeviceRepository) GetTenantTOTPSecretByID(id, userID, workspaceID uuid.UUID) (*models.TenantTOTPSecret, error) {
	var secret models.TenantTOTPSecret
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("id = ? AND user_id = ? AND is_active = ?", id, userID, true).First(&secret).Error
	})
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// GetTenantUserTOTPSecrets retrieves all active TOTP secrets for a user in tenant DB
func (r *TenantDeviceRepository) GetTenantUserTOTPSecrets(userID, workspaceID uuid.UUID) ([]models.TenantTOTPSecret, error) {
	var secrets []models.TenantTOTPSecret
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("user_id = ? AND is_active = ?", userID, true).
			Order("is_primary DESC, created_at DESC").
			Find(&secrets).Error
	})
	return secrets, err
}

// UpdateTenantTOTPSecret updates a TOTP secret in the secret's workspace.
func (r *TenantDeviceRepository) UpdateTenantTOTPSecret(secret *models.TenantTOTPSecret) error {
	secret.UpdatedAt = time.Now().Unix()
	return r.in(secret.WorkspaceID, func(tx *gorm.DB) error { return tx.Save(secret).Error })
}

// DeleteTenantTOTPSecret soft deletes a TOTP secret by setting is_active to false
func (r *TenantDeviceRepository) DeleteTenantTOTPSecret(id, userID, workspaceID uuid.UUID) error {
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.TenantTOTPSecret{}).
			Where("id = ? AND user_id = ?", id, userID).
			Update("is_active", false).Error
	})
}

// UpdateTenantTOTPSecretLastUsed updates last_used timestamp for TOTP secret
func (r *TenantDeviceRepository) UpdateTenantTOTPSecretLastUsed(id, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.TenantTOTPSecret{}).
			Where("id = ?", id).
			Update("last_used", now).Error
	})
}

// SetTenantTOTPSecretAsPrimary sets a TOTP secret as primary and unsets others
func (r *TenantDeviceRepository) SetTenantTOTPSecretAsPrimary(id, userID, workspaceID uuid.UUID) error {
	return r.in(workspaceID, func(tx *gorm.DB) error {
		// Unset all other secrets as primary
		if err := tx.Model(&models.TenantTOTPSecret{}).
			Where("user_id = ? AND id != ?", userID, id).
			Update("is_primary", false).Error; err != nil {
			return err
		}
		// Set this secret as primary
		return tx.Model(&models.TenantTOTPSecret{}).
			Where("id = ? AND user_id = ?", id, userID).
			Update("is_primary", true).Error
	})
}

// ========================================
// Tenant Backup Code Operations
// ========================================

// CreateTenantBackupCodes creates backup codes for a user. All codes must
// belong to one workspace.
func (r *TenantDeviceRepository) CreateTenantBackupCodes(codes []models.TenantBackupCode) error {
	if len(codes) == 0 {
		return nil
	}
	ws := codes[0].WorkspaceID
	for i := range codes {
		if codes[i].WorkspaceID != ws {
			return errors.New("backup codes span several workspaces")
		}
		codes[i].CreatedAt = time.Now().Unix()
	}

	err := r.in(ws, func(tx *gorm.DB) error { return tx.CreateInBatches(codes, 100).Error })
	if err != nil {
		if strings.Contains(err.Error(), "fk_tenant_backup_tenant") {
			return errors.New("tenant_not_found")
		}
		if strings.Contains(err.Error(), "fk_tenant_backup_user") {
			return errors.New("user_not_found")
		}
		return err
	}
	return nil
}

// GetTenantUserBackupCodes retrieves all unused backup codes for a user in tenant DB
func (r *TenantDeviceRepository) GetTenantUserBackupCodes(userID, workspaceID uuid.UUID) ([]models.TenantBackupCode, error) {
	var codes []models.TenantBackupCode
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("user_id = ? AND is_used = ?", userID, false).
			Order("created_at DESC").
			Find(&codes).Error
	})
	return codes, err
}

// UseTenantBackupCode marks a backup code as used in tenant DB
func (r *TenantDeviceRepository) UseTenantBackupCode(code, userID, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.TenantBackupCode{}).
			Where("code = ? AND user_id = ? AND is_used = ?", code, userID, false).
			Updates(map[string]interface{}{
				"is_used": true,
				"used_at": now,
			}).Error
	})
}

// DeleteTenantUserBackupCodes deletes all backup codes for a user in tenant DB
func (r *TenantDeviceRepository) DeleteTenantUserBackupCodes(userID, workspaceID uuid.UUID) error {
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("user_id = ?", userID).Delete(&models.TenantBackupCode{}).Error
	})
}

// ========================================
// Tenant User Operations (helper methods)
// ========================================

// GetTenantUserByEmail retrieves a user of workspaceID by e-mail and the
// OAuth client the request came through.
func (r *TenantDeviceRepository) GetTenantUserByEmail(email string, clientID, workspaceID uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Where("email = ? AND client_id = ?", email, clientID).First(&user).Error
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateTenantUserLastLogin updates the last_login timestamp of a user of
// workspaceID.
func (r *TenantDeviceRepository) UpdateTenantUserLastLogin(userID, workspaceID uuid.UUID) error {
	now := time.Now()
	return r.in(workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.User{}).
			Where("id = ?", userID).
			Update("last_login", now).Error
	})
}
