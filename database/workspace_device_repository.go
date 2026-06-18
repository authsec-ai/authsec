package database

import (
	"errors"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TenantDeviceRepository handles tenant device database operations
type TenantDeviceRepository struct {
	db *gorm.DB
}

// NewTenantDeviceRepository creates a new tenant device repository
func NewTenantDeviceRepository(db *gorm.DB) *TenantDeviceRepository {
	return &TenantDeviceRepository{db: db}
}

// ========================================
// Tenant Device Token Operations
// ========================================

// CreateTenantDeviceToken registers a new device for push notifications in tenant DB
func (r *TenantDeviceRepository) CreateTenantDeviceToken(token *models.TenantDeviceToken) error {
	now := time.Now().Unix()
	token.CreatedAt = now
	token.UpdatedAt = now

	err := r.db.Create(token).Error
	if err != nil {
		if strings.Contains(err.Error(), "fk_tenant_device_tenant") {
			return errors.New("tenant_not_found")
		}
		if strings.Contains(err.Error(), "fk_tenant_device_user") {
			return errors.New("user_not_found")
		}
		return err
	}
	return nil
}

// GetTenantDeviceTokensByUserID retrieves all active device tokens for a user in tenant DB
func (r *TenantDeviceRepository) GetTenantDeviceTokensByUserID(userID, workspaceID uuid.UUID) ([]models.TenantDeviceToken, error) {
	var tokens []models.TenantDeviceToken
	err := r.db.Where("user_id = ? AND workspace_id = ? AND is_active = ?", userID, workspaceID, true).
		Order("created_at DESC").
		Find(&tokens).Error
	return tokens, err
}

// GetTenantDeviceTokenByToken retrieves device token by device token string
func (r *TenantDeviceRepository) GetTenantDeviceTokenByToken(deviceToken string, workspaceID uuid.UUID) (*models.TenantDeviceToken, error) {
	var token models.TenantDeviceToken
	err := r.db.Where("device_token = ? AND workspace_id = ?", deviceToken, workspaceID).
		First(&token).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // Return nil when not found (different from error)
		}
		return nil, err
	}
	return &token, nil
}

// DeactivateTenantDeviceToken deactivates a device token
func (r *TenantDeviceRepository) DeactivateTenantDeviceToken(tokenID, userID, workspaceID uuid.UUID) error {
	return r.db.Model(&models.TenantDeviceToken{}).
		Where("id = ? AND user_id = ? AND workspace_id = ?", tokenID, userID, workspaceID).
		Update("is_active", false).Error
}

// UpdateLastUsed updates last_used timestamp for device token
func (r *TenantDeviceRepository) UpdateLastUsed(tokenID uuid.UUID) error {
	now := time.Now().Unix()
	return r.db.Model(&models.TenantDeviceToken{}).
		Where("id = ?", tokenID).
		Update("last_used", now).Error
}

// UpdateTenantDeviceToken updates an existing device token
func (r *TenantDeviceRepository) UpdateTenantDeviceToken(token *models.TenantDeviceToken) error {
	token.UpdatedAt = time.Now().Unix()
	return r.db.Save(token).Error
}

// ========================================
// Tenant CIBA Operations
// ========================================

// CreateTenantCIBAAuthRequest creates a new CIBA authentication request in tenant DB
func (r *TenantDeviceRepository) CreateTenantCIBAAuthRequest(request *models.TenantCIBAAuthRequest) error {
	now := time.Now().Unix()
	request.CreatedAt = now
	request.ExpiresAt = now + 300 // 5 minutes expiration

	err := r.db.Create(request).Error
	if err != nil {
		if strings.Contains(err.Error(), "fk_tenant_ciba_tenant") {
			return errors.New("tenant_not_found")
		}
		if strings.Contains(err.Error(), "fk_tenant_ciba_user") {
			return errors.New("user_not_found")
		}
		if strings.Contains(err.Error(), "fk_tenant_ciba_device") {
			return errors.New("device_not_found")
		}
		return err
	}
	return nil
}

// GetTenantCIBAAuthRequestByAuthReqID retrieves CIBA request by auth_req_id
func (r *TenantDeviceRepository) GetTenantCIBAAuthRequestByAuthReqID(authReqID string, workspaceID uuid.UUID) (*models.TenantCIBAAuthRequest, error) {
	var request models.TenantCIBAAuthRequest
	err := r.db.Where("auth_req_id = ? AND workspace_id = ?", authReqID, workspaceID).
		First(&request).Error
	if err != nil {
		return nil, err
	}
	return &request, nil
}

// UpdateTenantCIBAAuthRequest updates CIBA request status and response
func (r *TenantDeviceRepository) UpdateTenantCIBAAuthRequest(request *models.TenantCIBAAuthRequest) error {
	return r.db.Save(request).Error
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

	res := r.db.Model(&models.TenantCIBAAuthRequest{}).
		Where("auth_req_id = ? AND workspace_id = ? AND status = ?", authReqID, workspaceID, fromStatus).
		Updates(updates)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// UpdateTenantCIBAAuthRequestLastPolled updates the last_polled_at timestamp
func (r *TenantDeviceRepository) UpdateTenantCIBAAuthRequestLastPolled(authReqID string, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	return r.db.Model(&models.TenantCIBAAuthRequest{}).
		Where("auth_req_id = ? AND workspace_id = ?", authReqID, workspaceID).
		Update("last_polled_at", now).Error
}

// GetPendingTenantCIBAAuthRequests gets all pending CIBA requests for a user
func (r *TenantDeviceRepository) GetPendingTenantCIBAAuthRequests(userID, workspaceID uuid.UUID) ([]models.TenantCIBAAuthRequest, error) {
	var requests []models.TenantCIBAAuthRequest
	err := r.db.Where("user_id = ? AND workspace_id = ? AND status = ?", userID, workspaceID, "pending").
		Where("expires_at > ?", time.Now().Unix()).
		Order("created_at DESC").
		Find(&requests).Error
	return requests, err
}

// ========================================
// Tenant TOTP Operations
// ========================================

// CreateTenantTOTPSecret stores a new TOTP secret in tenant DB
func (r *TenantDeviceRepository) CreateTenantTOTPSecret(secret *models.TenantTOTPSecret) error {
	now := time.Now().Unix()
	secret.CreatedAt = now
	secret.UpdatedAt = now

	err := r.db.Create(secret).Error
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
	err := r.db.Where("id = ? AND user_id = ? AND workspace_id = ? AND is_active = ?", id, userID, workspaceID, true).
		First(&secret).Error
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// GetTenantUserTOTPSecrets retrieves all active TOTP secrets for a user in tenant DB
func (r *TenantDeviceRepository) GetTenantUserTOTPSecrets(userID, workspaceID uuid.UUID) ([]models.TenantTOTPSecret, error) {
	var secrets []models.TenantTOTPSecret
	err := r.db.Where("user_id = ? AND workspace_id = ? AND is_active = ?", userID, workspaceID, true).
		Order("is_primary DESC, created_at DESC").
		Find(&secrets).Error
	return secrets, err
}

// UpdateTenantTOTPSecret updates a TOTP secret in tenant DB
func (r *TenantDeviceRepository) UpdateTenantTOTPSecret(secret *models.TenantTOTPSecret) error {
	secret.UpdatedAt = time.Now().Unix()
	return r.db.Save(secret).Error
}

// DeleteTenantTOTPSecret soft deletes a TOTP secret by setting is_active to false
func (r *TenantDeviceRepository) DeleteTenantTOTPSecret(id, userID, workspaceID uuid.UUID) error {
	return r.db.Model(&models.TenantTOTPSecret{}).
		Where("id = ? AND user_id = ? AND workspace_id = ?", id, userID, workspaceID).
		Update("is_active", false).Error
}

// UpdateTenantTOTPSecretLastUsed updates last_used timestamp for TOTP secret
func (r *TenantDeviceRepository) UpdateTenantTOTPSecretLastUsed(id uuid.UUID) error {
	now := time.Now().Unix()
	return r.db.Model(&models.TenantTOTPSecret{}).
		Where("id = ?", id).
		Update("last_used", now).Error
}

// SetTenantTOTPSecretAsPrimary sets a TOTP secret as primary and unsets others
func (r *TenantDeviceRepository) SetTenantTOTPSecretAsPrimary(id, userID, workspaceID uuid.UUID) error {
	// Start transaction
	tx := r.db.Begin()

	// Unset all other secrets as primary
	if err := tx.Model(&models.TenantTOTPSecret{}).
		Where("user_id = ? AND workspace_id = ? AND id != ?", userID, workspaceID, id).
		Update("is_primary", false).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Set this secret as primary
	if err := tx.Model(&models.TenantTOTPSecret{}).
		Where("id = ? AND user_id = ? AND workspace_id = ?", id, userID, workspaceID).
		Update("is_primary", true).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// ========================================
// Tenant Backup Code Operations
// ========================================

// CreateTenantBackupCodes creates backup codes for a user in tenant DB
func (r *TenantDeviceRepository) CreateTenantBackupCodes(codes []models.TenantBackupCode) error {
	for i := range codes {
		codes[i].CreatedAt = time.Now().Unix()
	}

	err := r.db.CreateInBatches(codes, 100).Error
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
	err := r.db.Where("user_id = ? AND workspace_id = ? AND is_used = ?", userID, workspaceID, false).
		Order("created_at DESC").
		Find(&codes).Error
	return codes, err
}

// UseTenantBackupCode marks a backup code as used in tenant DB
func (r *TenantDeviceRepository) UseTenantBackupCode(code, userID, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	return r.db.Model(&models.TenantBackupCode{}).
		Where("code = ? AND user_id = ? AND workspace_id = ? AND is_used = ?", code, userID, workspaceID, false).
		Updates(map[string]interface{}{
			"is_used": true,
			"used_at": now,
		}).Error
}

// DeleteTenantUserBackupCodes deletes all backup codes for a user in tenant DB
func (r *TenantDeviceRepository) DeleteTenantUserBackupCodes(userID, workspaceID uuid.UUID) error {
	return r.db.Where("user_id = ? AND workspace_id = ?", userID, workspaceID).
		Delete(&models.TenantBackupCode{}).Error
}

// ========================================
// Tenant User Operations (helper methods)
// ========================================

// GetTenantUserByEmail retrieves a user by email from tenant DB
func (r *TenantDeviceRepository) GetTenantUserByEmail(email string, clientID uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ? AND client_id = ? ", email, clientID).
		First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateTenantUserLastLogin updates the last_login timestamp for a user in tenant DB
func (r *TenantDeviceRepository) UpdateTenantUserLastLogin(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&models.User{}).
		Where("id = ?", userID).
		Update("last_login", now).Error
}
