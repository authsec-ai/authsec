package platform

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// ─────────────────────────────────────────────────────────────────────────
// TOTP (authenticator app) — the alternative second factor to WebAuthn,
// interposed between primary auth and consent. Same shape as the WebAuthn
// endpoints: bound to the login_challenge, accepts the Hydra login only after
// a valid code via the shared acceptSecondFactor helper.
// ─────────────────────────────────────────────────────────────────────────

// Login2FAMethods handles POST /authsec/oauth/v2/login/2fa/methods. Returns
// which second factors the user has enrolled so the UI can decide whether to
// offer enrollment (none yet → pick passkey or authenticator) or a challenge
// (use an existing factor).
func (ctrl *LoginV2Controller) Login2FAMethods(c *gin.Context) {
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
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "invalid tenant"})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant db unavailable"})
		return
	}
	var credCount int64
	_ = tenantDB.Table("credentials").Where("client_id = ?", *arcRow.UserID).Count(&credCount).Error
	secrets, _ := database.NewTenantDeviceRepository(tenantDB).GetTenantUserTOTPSecrets(*arcRow.UserID, tenantUUID)
	c.JSON(http.StatusOK, gin.H{
		"success":           true,
		"webauthn_enrolled": credCount > 0,
		"totp_enrolled":     len(secrets) > 0,
	})
}

// TotpBegin handles POST /authsec/oauth/v2/login/totp/begin. For a user with no
// TOTP secret it provisions one and returns the otpauth URI + secret to render
// a QR / manual key. For a user who already has TOTP it returns mode
// "challenge" — they just enter their current code (no new secret).
func (ctrl *LoginV2Controller) TotpBegin(c *gin.Context) {
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
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "invalid tenant"})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant db unavailable"})
		return
	}

	repo := database.NewTenantDeviceRepository(tenantDB)
	existing, _ := repo.GetTenantUserTOTPSecrets(*arcRow.UserID, tenantUUID)
	if len(existing) > 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "mode": "challenge"})
		return
	}

	var email string
	_ = tenantDB.Raw(`SELECT COALESCE(email,'') FROM users WHERE id = ?`, *arcRow.UserID).Row().Scan(&email)

	svc := services.NewTenantTOTPService()
	resp, rerr := svc.RegisterTenantTOTPDevice(
		&models.TenantTOTPRegistrationRequest{DeviceName: "Authenticator", DeviceType: "totp"},
		*arcRow.UserID, tenantUUID, email,
	)
	if rerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not start authenticator setup"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"mode":             "enroll",
		"provisioning_uri": resp.QRCodeURL,
		"secret":           resp.Secret,
	})
}

// TotpVerify handles POST /authsec/oauth/v2/login/totp/verify. Validates the
// 6-digit code against the user's TOTP secret(s) — works for both freshly
// enrolled and returning users — then accepts the login → consent.
func (ctrl *LoginV2Controller) TotpVerify(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
		Code           string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge and code required"})
		return
	}
	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil || arcRow.UserID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no authenticated user for this challenge"})
		return
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "invalid tenant"})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant db unavailable"})
		return
	}

	repo := database.NewTenantDeviceRepository(tenantDB)
	secrets, _ := repo.GetTenantUserTOTPSecrets(*arcRow.UserID, tenantUUID)
	if len(secrets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no authenticator enrolled; start setup first"})
		return
	}

	svc := services.NewTenantTOTPService()
	code := strings.TrimSpace(req.Code)
	ok := false
	for _, s := range secrets {
		if svc.ValidateTOTPCode(s.Secret, code) {
			ok = true
			break
		}
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid code"})
		return
	}

	redirectTo, aerr := ctrl.acceptSecondFactor(req.LoginChallenge, tenantID, *arcRow.UserID, "totp_2fa", tenantDB)
	if aerr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": redirectTo})
}
