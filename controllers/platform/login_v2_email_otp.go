package platform

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
)

// ─────────────────────────────────────────────────────────────────────────
// Email-OTP verification — confirms that a newly registered email+password
// user owns the email address they signed up with.
//
// Called only after RegisterEndUser succeeds (arcRow.UserID is already set).
// OIDC/SAML users skip this step because the upstream provider guarantees
// email ownership.
//
// The OTP does NOT accept the Hydra login — that happens later when the
// passkey enrollment WebAuthn step completes. This handler only confirms
// email ownership and returns needs_webauthn: true so the UI proceeds.
//
// OTP namespace: "emailotp_v2:<login_challenge>"
// Expiry: 10 minutes.
// ─────────────────────────────────────────────────────────────────────────

func emailOTPKey(loginChallenge string) string {
	h := sha256.Sum256([]byte(loginChallenge))
	return fmt.Sprintf("emailotp_v2:%x", h)
}

// EmailOTPSend handles POST /authsec/oauth/v2/login/email-otp/send.
// Body: { login_challenge }
// The user must have already registered (arcRow.UserID set by RegisterEndUser).
// Sends a 6-digit OTP to the user's registered email address.
func (ctrl *LoginV2Controller) EmailOTPSend(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge required"})
		return
	}

	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil || arcRow.UserID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no registered user for this challenge"})
		return
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant database unavailable"})
		return
	}

	var email string
	if err := tenantDB.Raw(`SELECT COALESCE(email,'') FROM users WHERE id = ?`, *arcRow.UserID).
		Row().Scan(&email); err != nil || email == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not resolve user email"})
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		log.Printf("[email-otp-v2] OTP generation failed challenge=%s: %v", req.LoginChallenge, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not generate code"})
		return
	}

	key := emailOTPKey(req.LoginChallenge)
	_ = config.DB.Where("email = ?", key).Delete(&models.OTPEntry{}).Error

	entry := models.OTPEntry{
		Email:     key,
		OTP:       otp,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Verified:  false,
	}
	if err := config.DB.Create(&entry).Error; err != nil {
		log.Printf("[email-otp-v2] failed to store OTP challenge=%s: %v", req.LoginChallenge, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not create code"})
		return
	}

	if err := utils.SendOTPEmail(email, otp); err != nil {
		log.Printf("[email-otp-v2] email send failed %s: %v", email, err)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "masked_email": maskEmail(email)})
}

// EmailOTPVerify handles POST /authsec/oauth/v2/login/email-otp/verify.
// Body: { login_challenge, otp }
// Verifies the code. On success returns needs_webauthn: true — the Hydra
// login is accepted later by the WebAuthn finish step.
func (ctrl *LoginV2Controller) EmailOTPVerify(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
		OTP            string `json:"otp" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge and otp required"})
		return
	}
	req.OTP = strings.TrimSpace(req.OTP)

	arcRow, _, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil || arcRow.UserID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no registered user for this challenge"})
		return
	}

	key := emailOTPKey(req.LoginChallenge)
	var entry models.OTPEntry
	if err := config.DB.Where(
		"email = ? AND otp = ? AND expires_at > ? AND verified = ?",
		key, req.OTP, time.Now(), false,
	).First(&entry).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid or expired code"})
		return
	}

	_ = config.DB.Model(&entry).Update("verified", true).Error
	_ = config.DB.Where("email = ?", key).Delete(&models.OTPEntry{}).Error

	c.JSON(http.StatusOK, gin.H{"success": true, "needs_webauthn": true})
}

// maskEmail returns a privacy-safe hint like "ab***@example.com".
func maskEmail(email string) string {
	at := strings.Index(email, "@")
	if at <= 0 {
		return email
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return fmt.Sprintf("%s***%s", string(local[0]), domain)
	}
	return fmt.Sprintf("%s***%s", local[:2], domain)
}
