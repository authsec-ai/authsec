package platform

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	util "github.com/authsec-ai/authsec/utils"
	sharedmodels "github.com/authsec-ai/sharedmodels"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func maybeSeedLocalDemoEndUser(tenantDB *gorm.DB, client sharedmodels.Client, tenantDomain string) error {
	if tenantDB == nil || config.AppConfig == nil {
		return nil
	}
	if !strings.EqualFold(config.AppConfig.Environment, "development") {
		return nil
	}

	email := strings.ToLower(strings.TrimSpace(os.Getenv("LOCAL_DEMO_ENDUSER_EMAIL")))
	password := os.Getenv("LOCAL_DEMO_ENDUSER_PASSWORD")
	name := strings.TrimSpace(os.Getenv("LOCAL_DEMO_ENDUSER_NAME"))
	totpSecret := normalizeLocalDemoTOTPSecret(os.Getenv("LOCAL_DEMO_ENDUSER_TOTP_SECRET"))
	if email == "" || password == "" {
		return nil
	}
	if name == "" {
		name = "Local Demo User"
	}

	username := strings.Split(email, "@")[0]
	normalizedTenantDomain := normalizeLocalDemoTenantDomain(tenantDomain)
	now := time.Now().UTC()
	defaultMFAMethod := "totp"

	passwordHolder := &models.ExtendedUser{}
	passwordHolder.PasswordHash = password
	if err := passwordHolder.HashPassword(); err != nil {
		return fmt.Errorf("hash local demo end-user password: %w", err)
	}

	var existing models.ExtendedUser
	err := tenantDB.
		Where("client_id = ? AND LOWER(email) = LOWER(?)", client.ClientID, email).
		First(&existing).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("lookup local demo end-user: %w", err)
	}

	updates := map[string]interface{}{
		"name":                    name,
		"username":                username,
		"password_hash":           passwordHolder.PasswordHash,
		"tenant_domain":           normalizedTenantDomain,
		"provider":                "custom",
		"provider_id":             "",
		"active":                  true,
		"mfa_enabled":             true,
		"mfa_verified":            false,
		"mfa_method":              []string{"totp"},
		"mfa_default_method":      "totp",
		"last_login":              now,
		"failed_login_attempts":   0,
		"account_locked_at":       nil,
		"password_reset_required": false,
	}

	if err == nil {
		if updateErr := tenantDB.Model(&existing).Updates(updates).Error; updateErr != nil {
			return fmt.Errorf("update local demo end-user: %w", updateErr)
		}
		return seedLocalDemoTOTPMethod(tenantDB, existing.ID, client.ClientID, totpSecret)
	}

	user := models.ExtendedUser{
		User: sharedmodels.User{
			ClientID:         client.ClientID,
			TenantID:         client.TenantID,
			ProjectID:        client.ProjectID,
			Name:             name,
			Username:         &username,
			Email:            email,
			PasswordHash:     passwordHolder.PasswordHash,
			TenantDomain:     normalizedTenantDomain,
			Provider:         "custom",
			ProviderID:       "",
			Active:           true,
			MFAEnabled:       true,
			MFAMethod:        []string{"totp"},
			MFADefaultMethod: &defaultMFAMethod,
			MFAVerified:      false,
			LastLogin:        &now,
		},
	}

	if createErr := tenantDB.Create(&user).Error; createErr != nil {
		return fmt.Errorf("create local demo end-user: %w", createErr)
	}

	return seedLocalDemoTOTPMethod(tenantDB, user.ID, client.ClientID, totpSecret)
}

func normalizeLocalDemoTenantDomain(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return config.AppConfig.TenantDomainSuffix
	}
	if strings.Contains(value, "://") {
		value = strings.SplitN(value, "://", 2)[1]
	}
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func normalizeLocalDemoTOTPSecret(raw string) string {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "" {
		return "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	}
	return value
}

func seedLocalDemoTOTPMethod(tenantDB *gorm.DB, userID, clientID uuid.UUID, secret string) error {
	encryptedSecret, err := util.EncryptString(secret)
	if err != nil {
		return fmt.Errorf("encrypt local demo TOTP secret: %w", err)
	}

	methodData := map[string]interface{}{
		"secret_encrypted": encryptedSecret,
		"issuer":           "AuthSec",
		"algorithm":        "SHA1",
		"digits":           6,
		"period":           30,
		"setup_completed":  time.Now().UTC(),
	}

	mfaRepo := repositories.NewMFARepository(tenantDB)
	if err := mfaRepo.EnableMethod(clientID.String(), "totp", methodData, userID); err != nil {
		return fmt.Errorf("seed local demo TOTP MFA method: %w", err)
	}

	return tenantDB.Model(&sharedmodels.MFAMethod{}).
		Where("client_id = ? AND method_type = ?", clientID.String(), "totp").
		Updates(map[string]interface{}{
			"display_name": "Authenticator App",
			"description":  "Seeded local SDK demo TOTP method",
			"recommended":  true,
			"is_primary":   true,
			"verified":     true,
			"enabled":      true,
			"updated_at":   time.Now().UTC(),
		}).Error
}
