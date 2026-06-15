package platform

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ─────────────────────────────────────────────────────────────────────────
// Forgot-password for custom-login end-users in the OAuth v2 flow.
//
// All three endpoints accept login_challenge so the tenant context is always
// resolved from the ongoing OAuth dance — no client_id required from the UI.
//
// OTP namespace: "pwreset_v2:<email>" so these rows never collide with the
// legacy /uflow/user/forgot-password flow or the email-OTP 2FA rows.
// ─────────────────────────────────────────────────────────────────────────

const fpOTPNamespace = "pwreset_v2:"

func fpOTPKey(email string) string { return fpOTPNamespace + strings.ToLower(email) }

// ForgotPassword handles POST /authsec/oauth/v2/login/forgot-password.
// Body: { login_challenge, email }
// Resolves the tenant from login_challenge, verifies the user has a custom
// login, generates a 6-digit OTP, stores it for 15 minutes, and sends it.
// Always returns 200 to avoid user-enumeration.
func (ctrl *LoginV2Controller) ForgotPassword(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
		Email          string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge and email required"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	_, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil {
		// Don't leak whether the challenge is invalid — just return success.
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "If your email is registered, you will receive a reset code."})
		return
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant database unavailable"})
		return
	}

	var user models.ExtendedUser
	if err := tenantDB.Where(
		"email = ? AND provider IN ?",
		req.Email,
		[]string{"custom", "ad_sync", "entra_id", "scim"},
	).First(&user).Error; err != nil {
		// User not found — silent OK to prevent enumeration.
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "If your email is registered, you will receive a reset code."})
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		log.Printf("[forgot-password-v2] OTP generation failed for %s: %v", req.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not generate reset code"})
		return
	}

	key := fpOTPKey(req.Email)
	// Clear any existing OTP for this namespace+email.
	_ = config.DB.Where("email = ?", key).Delete(&models.OTPEntry{}).Error

	entry := models.OTPEntry{
		Email:     key,
		OTP:       otp,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Verified:  false,
	}
	if err := config.DB.Create(&entry).Error; err != nil {
		log.Printf("[forgot-password-v2] failed to store OTP for %s: %v", req.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not create reset code"})
		return
	}

	if err := utils.SendPasswordResetOTPEmail(req.Email, otp); err != nil {
		log.Printf("[forgot-password-v2] email send failed for %s: %v", req.Email, err)
		// OTP is stored; email delivery failure is non-fatal on the API side.
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "If your email is registered, you will receive a reset code."})
}

// ForgotPasswordVerifyOTP handles POST /authsec/oauth/v2/login/forgot-password/verify-otp.
// Body: { email, otp }
// Verifies the OTP against the stored entry. Does not need login_challenge.
func (ctrl *LoginV2Controller) ForgotPasswordVerifyOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "email and otp required"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.OTP = strings.TrimSpace(req.OTP)

	key := fpOTPKey(req.Email)
	var entry models.OTPEntry
	if err := config.DB.Where(
		"email = ? AND otp = ? AND expires_at > ? AND verified = ?",
		key, req.OTP, time.Now(), false,
	).First(&entry).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid or expired code"})
		return
	}

	if err := config.DB.Model(&entry).Update("verified", true).Error; err != nil {
		log.Printf("[forgot-password-v2] verify update failed for %s: %v", req.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "verification failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ForgotPasswordReset handles POST /authsec/oauth/v2/login/forgot-password/reset.
// Body: { login_challenge, email, new_password }
// Confirms OTP was verified, hashes and stores the new password in the tenant DB.
func (ctrl *LoginV2Controller) ForgotPasswordReset(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
		Email          string `json:"email" binding:"required,email"`
		NewPassword    string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge, email, and new_password (≥8 chars) required"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	_, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge not found or expired"})
		return
	}

	key := fpOTPKey(req.Email)
	var entry models.OTPEntry
	if err := config.DB.Where(
		"email = ? AND verified = ? AND expires_at > ?",
		key, true, time.Now(),
	).First(&entry).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "OTP not verified or session expired — request a new code"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "verification check failed"})
		}
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not hash password"})
		return
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant database unavailable"})
		return
	}

	result := tenantDB.Model(&models.ExtendedUser{}).
		Where("email = ? AND provider IN ?", req.Email, []string{"custom", "ad_sync", "entra_id", "scim"}).
		Update("password", string(hash))
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "password update failed"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "user not found"})
		return
	}

	// Clean up the OTP row.
	_ = config.DB.Where("email = ?", key).Delete(&models.OTPEntry{}).Error

	log.Printf("[forgot-password-v2] password reset completed for %s tenant=%s", req.Email, tenantID)
	c.JSON(http.StatusOK, gin.H{"success": true})
}
