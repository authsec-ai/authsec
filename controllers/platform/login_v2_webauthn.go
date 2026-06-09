package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	session "github.com/authsec-ai/authsec/internal/session"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	sharedmodels "github.com/authsec-ai/sharedmodels"
)

// ─────────────────────────────────────────────────────────────────────────
// WebAuthn 2FA, interposed between primary auth and consent.
//
// Primary auth (CompleteCustomLogin / CallbackOIDC / CallbackSAML / register)
// stamps auth_request_context.user_id but does NOT accept the Hydra login.
// The SPA then runs a WebAuthn ceremony here — enroll a passkey on first login,
// challenge an existing one thereafter — and only on success do we set
// second_factor_completed and accept the login, which hands off to consent.
//
// The ceremony is bound to the login_challenge (the challenge session key) so a
// returning user's assertion can't be skipped: the user_id comes from the
// server-side context, and FinishLogin requires a fresh challenge-response from
// the registered authenticator.
// ─────────────────────────────────────────────────────────────────────────

// oauthWAUser adapts an end-user row to the go-webauthn User interface.
type oauthWAUser struct {
	id    uuid.UUID
	email string
	name  string
	creds []webauthn.Credential
}

func (u *oauthWAUser) WebAuthnID() []byte                         { return []byte(u.id.String()) }
func (u *oauthWAUser) WebAuthnName() string                       { return u.email }
func (u *oauthWAUser) WebAuthnDisplayName() string                { if u.name != "" { return u.name }; return u.email }
func (u *oauthWAUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// oauthWAKey is the challenge-session key, scoped per mode + login_challenge.
func oauthWAKey(mode, loginChallenge string) string {
	return fmt.Sprintf("oauth2fa:%s:%s", mode, loginChallenge)
}

// oauthBuildWebAuthn builds a request-scoped *webauthn.WebAuthn from the
// browser Origin, mirroring EndUserWebAuthnHandler.validateOriginAndCreateWebAuthn:
// verified custom domains use the domain as RP ID, otherwise standard authsec
// subdomains are accepted (SetupWebAuthn auto-adjusts the RP ID to the origin).
func oauthBuildWebAuthn(c *gin.Context) (*webauthn.WebAuthn, error) {
	origin := c.Request.Header.Get("Origin")

	if u, err := url.Parse(origin); err == nil && u.Scheme == "https" {
		domain := u.Host
		if gdb, derr := config.ConnectGlobalDB(); derr == nil {
			var count int64
			if cerr := gdb.Table("tenant_domains").
				Where("domain = ? AND is_verified = true", domain).
				Count(&count).Error; cerr == nil && count > 0 {
				return config.SetupWebAuthn("AuthSec MFA Service", domain, origin), nil
			}
		}
	}

	if config.ValidateSubdomainOrigin(origin) {
		return config.SetupWebAuthn("AuthSec MFA Service", "app.authsec.dev", origin), nil
	}
	return nil, fmt.Errorf("invalid origin: %s", origin)
}

// loadOAuthWAUser loads the end-user + their WebAuthn credentials for the 2FA
// ceremony from the tenant DB.
func loadOAuthWAUser(tenantDB *gorm.DB, userID uuid.UUID) (*oauthWAUser, []repositories.Credential, error) {
	var u sharedmodels.User
	if err := tenantDB.Where("id = ?", userID).First(&u).Error; err != nil {
		return nil, nil, fmt.Errorf("load user: %w", err)
	}
	repo := repositories.NewClientRepository(tenantDB)
	dbCreds, err := repo.GetCredentialsByClientID(userID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("load credentials: %w", err)
	}
	waCreds := make([]webauthn.Credential, 0, len(dbCreds))
	for _, cr := range dbCreds {
		waCreds = append(waCreds, webauthn.Credential{
			ID:              cr.CredentialID,
			PublicKey:       cr.PublicKey,
			AttestationType: cr.AttestationType,
			Authenticator:   webauthn.Authenticator{SignCount: uint32(cr.SignCount)},
			Flags:           webauthn.CredentialFlags{BackupEligible: cr.BackupEligible, BackupState: cr.BackupState},
		})
	}
	return &oauthWAUser{id: u.ID, email: u.Email, name: u.Name, creds: waCreds}, dbCreds, nil
}

// WebauthnBegin handles POST /authsec/oauth/v2/login/webauthn/begin.
// Returns the ceremony options and the mode ("enroll" if the user has no
// passkey yet, otherwise "authenticate").
func (ctrl *LoginV2Controller) WebauthnBegin(c *gin.Context) {
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
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant db unavailable"})
		return
	}
	user, dbCreds, err := loadOAuthWAUser(tenantDB, *arcRow.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to load user"})
		return
	}
	wa, err := oauthBuildWebAuthn(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid origin"})
		return
	}

	mode := "authenticate"
	var options interface{}
	var sd *webauthn.SessionData
	if len(dbCreds) == 0 {
		mode = "enroll"
		options, sd, err = wa.BeginRegistration(user)
	} else {
		options, sd, err = wa.BeginLogin(user)
	}
	if err != nil {
		log.Printf("[login-v2-2fa] begin %s failed: %v", mode, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to begin webauthn"})
		return
	}

	mgr := session.NewPostgreSQLSessionManager(tenantDB, "")
	if err := mgr.Save(oauthWAKey(mode, req.LoginChallenge), sd); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save webauthn session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "mode": mode, "options": options})
}

// WebauthnFinish handles POST /authsec/oauth/v2/login/webauthn/finish.
// Validates the ceremony, marks second_factor_completed, accepts the Hydra
// login (carrying identity claims for consent/ID-token), and returns the
// redirect to consent.
func (ctrl *LoginV2Controller) WebauthnFinish(c *gin.Context) {
	var req struct {
		LoginChallenge string          `json:"login_challenge" binding:"required"`
		Mode           string          `json:"mode" binding:"required"`
		Credential     json.RawMessage `json:"credential" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge, mode and credential required"})
		return
	}
	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil || arcRow.UserID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no authenticated user for this challenge"})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant db unavailable"})
		return
	}
	user, _, err := loadOAuthWAUser(tenantDB, *arcRow.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to load user"})
		return
	}
	wa, err := oauthBuildWebAuthn(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid origin"})
		return
	}

	mgr := session.NewPostgreSQLSessionManager(tenantDB, "")
	key := oauthWAKey(req.Mode, req.LoginChallenge)
	sd, found := mgr.Get(key)
	if !found {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no webauthn session; begin again"})
		return
	}

	// go-webauthn parses the credential from the request body.
	c.Request.Body = io.NopCloser(bytes.NewReader(req.Credential))
	c.Request.ContentLength = int64(len(req.Credential))
	c.Request.Header.Set("Content-Type", "application/json")

	repo := repositories.NewClientRepository(tenantDB)
	now := time.Now().UTC()

	switch req.Mode {
	case "enroll":
		cred, ferr := wa.FinishRegistration(user, *sd, c.Request)
		if ferr != nil {
			log.Printf("[login-v2-2fa] enroll finish failed: %v", ferr)
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "passkey registration failed"})
			return
		}
		attestation := cred.AttestationType
		if attestation == "" {
			attestation = "none"
		}
		rpID := wa.Config.RPID
		row := repositories.Credential{
			ID:              uuid.New(),
			ClientID:        user.id,
			CredentialID:    cred.ID,
			PublicKey:       cred.PublicKey,
			AttestationType: attestation,
			SignCount:       int64(cred.Authenticator.SignCount),
			BackupEligible:  cred.Flags.BackupEligible,
			BackupState:     cred.Flags.BackupState,
			RPID:            &rpID,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if len(cred.Authenticator.AAGUID) == 16 {
			if parsed, perr := uuid.FromBytes(cred.Authenticator.AAGUID); perr == nil {
				row.AAGUID = &parsed
			}
		}
		if serr := repo.SaveCredential(&row); serr != nil {
			log.Printf("[login-v2-2fa] save credential failed: %v", serr)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save passkey"})
			return
		}
		mfaRepo := repositories.NewMFARepository(tenantDB)
		_ = mfaRepo.EnableMethod(user.id.String(), "webauthn", map[string]interface{}{
			"credential_id": fmt.Sprintf("%x", cred.ID),
		}, user.id)
		_ = tenantDB.Exec(
			`UPDATE users SET mfa_enabled = true, mfa_verified = true, mfa_default_method = 'webauthn', updated_at = ? WHERE id = ?`,
			now, user.id).Error

	case "authenticate":
		cred, ferr := wa.FinishLogin(user, *sd, c.Request)
		if ferr != nil {
			log.Printf("[login-v2-2fa] authenticate finish failed: %v", ferr)
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "passkey verification failed"})
			return
		}
		_ = repo.UpdateCredentialSignCount(cred.ID, cred.Authenticator.SignCount)
		_ = tenantDB.Table("mfa_methods").
			Where("client_id = ? AND method_type = ?", user.id, "webauthn").
			Updates(map[string]interface{}{"last_used_at": now, "updated_at": now}).Error

	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "mode must be enroll or authenticate"})
		return
	}

	mgr.Delete(key)
	_ = now // (credential rows stamped their own timestamps above)

	redirectTo, aerr := ctrl.acceptSecondFactor(req.LoginChallenge, tenantID, *arcRow.UserID, "webauthn_2fa", tenantDB)
	if aerr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": redirectTo})
}

// acceptSecondFactor marks the second factor satisfied on the context, then
// accepts the Hydra login and returns the consent redirect. Shared by the
// WebAuthn and TOTP finish paths. Carries identity claims (email/name/provider)
// so finalizeConsent can hydrate the ID token — it reads them from the consent
// request Context, which mirrors the login Context we pass here.
func (ctrl *LoginV2Controller) acceptSecondFactor(loginChallenge, tenantID string, userID uuid.UUID, authMethod string, tenantDB *gorm.DB) (string, error) {
	now := time.Now().UTC()
	if err := tenantDB.Model(&models.AuthRequestContext{}).
		Where("login_challenge = ? AND tenant_id = ?", loginChallenge, tenantID).
		Updates(map[string]interface{}{"second_factor_completed": true, "auth_time": now}).Error; err != nil {
		log.Printf("[login-v2-2fa] mark second_factor_completed failed challenge=%s: %v", loginChallenge, err)
	}

	var email, name, provider string
	_ = tenantDB.Raw(
		`SELECT COALESCE(email,''), COALESCE(name,''), COALESCE(provider,'') FROM users WHERE id = ?`,
		userID,
	).Row().Scan(&email, &name, &provider)

	acceptResp, err := ctrl.hydraLogin.AcceptLoginRequest(loginChallenge, services.HydraAcceptLoginRequest{
		Subject:     userID.String(),
		Remember:    true,
		RememberFor: 8 * 3600,
		ACR:         "mfa", // primary factor + second factor
		Context: map[string]interface{}{
			"email":       email,
			"name":        name,
			"provider":    provider,
			"auth_method": authMethod,
			"tenant_id":   tenantID,
		},
	})
	if err != nil {
		return "", err
	}
	return acceptResp.RedirectTo, nil
}
