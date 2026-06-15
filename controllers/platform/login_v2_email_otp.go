package platform

import (
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
// Email-OTP second factor for the OAuth v2 login flow.
//
// After primary auth (password or OIDC/SAML), the UI can offer email OTP as
// an alternative to passkeys or TOTP. The user clicks "Send code", receives
// a 6-digit OTP at their registered address, enters it, and the login is
// accepted.
//
// OTP namespace: "emailotp_v2:<login_challenge>" so rows are tied to the
// specific login session and never collide with password-reset OTPs.
// Expiry: 10 minutes (short because the challenge context is active).
// ─────────────────────────────────────────────────────────────────────────

func emailOTPKey(loginChallenge string) string {
	return "emailotp_v2:" + loginChallenge
}

// EmailOTPSend handles POST /authsec/oauth/v2/login/email-otp/send.
// Body: { login_challenge }
// Resolves the authenticated user from the ongoing challenge, fetches their
// email from the tenant DB, generates a 6-digit OTP and sends it.
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no authenticated user for this challenge"})
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
		log.Printf("[email-otp-v2] OTP generation failed for challenge=%s: %v", req.LoginChallenge, err)
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
		log.Printf("[email-otp-v2] failed to store OTP for challenge=%s: %v", req.LoginChallenge, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not create code"})
		return
	}

	// Send via the standard OTP email; the subject line makes the purpose clear.
	if err := utils.SendOTPEmail(email, otp); err != nil {
		log.Printf("[email-otp-v2] email send failed for %s: %v", email, err)
		// OTP is stored; email delivery failure is non-fatal on the API side.
	}

	// Return a masked hint of the email so the UI can confirm which address to check.
	maskedEmail := maskEmail(email)
	c.JSON(http.StatusOK, gin.H{"success": true, "masked_email": maskedEmail})
}

// EmailOTPVerify handles POST /authsec/oauth/v2/login/email-otp/verify.
// Body: { login_challenge, otp }
// Verifies the code, then calls acceptSecondFactor to accept the Hydra login.
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

	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil || arcRow.UserID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no authenticated user for this challenge"})
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

	// Mark used — idempotency guard.
	_ = config.DB.Model(&entry).Update("verified", true).Error

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant database unavailable"})
		return
	}

	redirectTo, aerr := ctrl.acceptSecondFactor(req.LoginChallenge, tenantID, *arcRow.UserID, "email_otp_2fa", tenantDB)
	if aerr != nil {
		log.Printf("[email-otp-v2] acceptSecondFactor failed challenge=%s: %v", req.LoginChallenge, aerr)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}

	// Clean up OTP row.
	_ = config.DB.Where("email = ?", key).Delete(&models.OTPEntry{}).Error

	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": redirectTo})
}

// maskEmail returns a privacy-safe hint like "a***@example.com" so the UI
// can tell the user which inbox to check without exposing the full address.
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
