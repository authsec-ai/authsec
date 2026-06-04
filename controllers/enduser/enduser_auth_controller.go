package enduser

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	shared "github.com/authsec-ai/authsec/controllers/shared"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EndUserAuthController struct {
	workspaceRepo        *database.WorkspaceRepository
	otpRepo           *database.OTPRepository
	pendingRepo       *database.PendingRegistrationRepository
	antiReplayService *services.AntiReplayService
}

// NewEndUserAuthController creates a new end-user auth controller
func NewEndUserAuthController() (*EndUserAuthController, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	redisClient := config.GetRedisClient()
	if redisClient == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	return &EndUserAuthController{
		workspaceRepo:        database.NewWorkspaceRepository(db),
		otpRepo:           database.NewOTPRepository(db),
		pendingRepo:       database.NewPendingRegistrationRepository(db),
		antiReplayService: services.NewAntiReplayService(redisClient),
	}, nil
}

// SAMLLogin handles SAML-based login without password validation.
// Workspace is resolved from the Host header (canonical v4 path) with
// workspace_id body field as fallback for SDK callers that cannot set Host.
// User identity: (workspace_id, LOWER(email), provider LIKE 'saml-%').
//
// @Summary SAML login
// @Description Authenticates end-users via SAML provider. Workspace is resolved
// from the Host header; the user's provider must start with 'saml-'.
// @Tags End-User Authentication
// @Accept json
// @Produce json
// @Param input body models.SAMLLoginInput true "SAML login data (email + optional workspace_id)"
// @Success 200 {object} models.LoginResponse "Login successful"
// @Failure 400 {object} map[string]string "Bad request - invalid input"
// @Failure 401 {object} map[string]string "Unauthorized - SAML user not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /authsec/uflow/user/saml/login [post]
func (euac *EndUserAuthController) SAMLLogin(c *gin.Context) {
	var input models.SAMLLoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Resolve workspace: host first, then explicit body field.
	workspaceID, err := shared.WorkspaceFromHost(c)
	if err != nil && input.WorkspaceID != "" {
		if parsed, parseErr := uuid.Parse(input.WorkspaceID); parseErr == nil {
			workspaceID = parsed
			err = nil
		}
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace could not be resolved from host; provide workspace_id in request body"})
		return
	}

	tenantDB := config.DB

	// Find user by (workspace_id, LOWER(email)) — provider must start with saml-.
	var user models.User
	if err := tenantDB.Where(
		"workspace_id = ? AND LOWER(email) = LOWER(?) AND provider LIKE 'saml-%'",
		workspaceID, input.Email,
	).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "SAML user not found or provider does not start with saml-"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to authenticate user"})
		return
	}

	// No password validation for SAML users — assertion verified by IdP upstream.
	isFirstLogin := user.LastLogin == nil

	response := models.LoginResponse{
		WorkspaceID: user.WorkspaceID.String(),
		Email:       user.Email,
		FirstLogin:  isFirstLogin,
		OTPRequired: false,
	}

	// Audit log: SAML login successful
	middlewares.Audit(c, "enduser", user.ID.String(), "saml_login", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"email":        user.Email,
			"workspace_id": workspaceID.String(),
			"first_login":  isFirstLogin,
			"provider":     user.Provider,
		},
	})

	c.JSON(http.StatusOK, response)
}

// WebAuthnCallback handles WebAuthn authentication callback
// @Summary WebAuthn authentication callback
// @Description Processes WebAuthn authentication responses for passwordless login
// @Tags End-User Authentication
// @Accept json
// @Produce json
// @Param input body models.WebAuthnCallbackInput true "WebAuthn callback data"
// @Success 200 {object} models.CustomLoginStatus "Successful WebAuthn authentication"
// @Failure 400 {object} map[string]string "Bad request - invalid input"
// @Failure 401 {object} map[string]string "Unauthorized - authentication failed"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /authsec/uflow/auth/enduser/webauthn-callback [post]
func (euac *EndUserAuthController) WebAuthnCallback(c *gin.Context) {
	var input models.WebAuthnCallbackInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.Email = strings.ToLower(input.Email)

	if input.MFAVerified == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA verification status is required"})
		return
	}
	if !*input.MFAVerified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA verification failed"})
		return
	}

	tenant, err := euac.workspaceRepo.GetWorkspaceByWorkspaceID(input.WorkspaceID.String())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	workspaceIDStr := tenant.WorkspaceID.String()
	tenantDB := config.DB

	var user models.User
	if err := tenantDB.Where("LOWER(email) = LOWER(?)", input.Email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user"})
		return
	}

	if !user.Active {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is disabled"})
		return
	}

	isFirstLogin := user.LastLogin == nil
	clientIDStr := ""
	if user.ClientID != uuid.Nil {
		clientIDStr = user.ClientID.String()
	}

	token, err := euac.generateJWTToken(workspaceIDStr, clientIDStr, user.Email, user.WorkspaceDomain, &user.ID, tenantDB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	now := time.Now()
	if err := tenantDB.Model(&models.User{}).Where("id = ?", user.ID).Update("last_login", now).Error; err != nil {
		log.Printf("Failed to update user last login after WebAuthn callback: %v", err)
	}

	response := gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   365 * 24 * 60 * 60,
		"first_login":  isFirstLogin,
		"workspace_id": workspaceIDStr,
		"email":        user.Email,
	}

	// Audit log: WebAuthn callback login successful
	middlewares.Audit(c, "enduser", user.ID.String(), "webauthn_login", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"email":        user.Email,
			"workspace_id": workspaceIDStr,
			"first_login":  isFirstLogin,
			"mfa_method":   "webauthn",
		},
	})

	c.JSON(http.StatusOK, response)
}

func (euac *EndUserAuthController) generateJWTToken(workspaceID, clientID, emailID, workspaceDomain string, userID *uuid.UUID, tenantDB interface{}) (string, error) {
	// Collect scopes for potential inclusion in token (though auth-manager fetches from DB)
	scopes := []string{"read", "write"}

	if userID != nil {
		userIDStr := userID.String()

		if tenantDB != nil {
			switch db := tenantDB.(type) {
			case *gorm.DB:
				if sqlDB, err := db.DB(); err == nil && sqlDB != nil {
					permSvc := services.NewPermissionService(sqlDB)
					_, dbScopes := permSvc.GetUserPermissions(userIDStr, workspaceID), permSvc.GetUserScopes(userIDStr, workspaceID)
					if len(dbScopes) > 0 {
						scopes = dbScopes
					}
				}
			case *sql.DB:
				permSvc := services.NewPermissionService(db)
				_, dbScopes := permSvc.GetUserPermissions(userIDStr, workspaceID), permSvc.GetUserScopes(userIDStr, workspaceID)
				if len(dbScopes) > 0 {
					scopes = dbScopes
				}
			}
		}
	}

	// Use centralized auth-manager token service
	if userID == nil {
		// For cases without userID, create a temporary one
		tempID := uuid.New()
		userID = &tempID
	}

	return config.TokenService.GenerateEndUserToken(
		*userID,
		workspaceID,
		clientID,
		emailID,
		scopes,
		365*24*time.Hour,
	)
}

// GetAuthChallenge generates a challenge for anti-replay protection
// @Summary Get authentication challenge
// @Description Generates a server-issued challenge for use in login requests to prevent replay attacks
// @Tags End User Authentication
// @Accept json
// @Produce json
// @Success 200 {object} models.AuthChallenge "Challenge generated successfully"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /authsec/uflow/auth/enduser/challenge [get]
func (euac *EndUserAuthController) GetAuthChallenge(c *gin.Context) {
	challenge, err := euac.antiReplayService.GenerateChallenge()
	if err != nil {
		log.Printf("ERROR: Failed to generate auth challenge: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate challenge"})
		return
	}

	log.Printf("INFO: Auth challenge generated: %s, expires at: %v", challenge.Challenge, challenge.ExpiresAt)

	c.JSON(http.StatusOK, gin.H{
		"challenge":  challenge.Challenge,
		"expires_at": challenge.ExpiresAt.Unix(),
		"created_at": challenge.CreatedAt.Unix(),
	})
}
