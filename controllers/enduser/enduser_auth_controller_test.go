package enduser

import (
	"os"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/authsec-ai/authsec/services"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set required environment variables for tests
	if os.Getenv("JWT_DEF_SECRET") == "" {
		os.Setenv("JWT_DEF_SECRET", "test-jwt-secret-for-testing-only-do-not-use-in-production")
	}
	if os.Getenv("JWT_SDK_SECRET") == "" {
		os.Setenv("JWT_SDK_SECRET", "test-jwt-sdk-secret-for-testing-only-do-not-use-in-production")
	}
	// Initialize the global token service for unit tests that call generateJWTToken
	if config.TokenService == nil {
		tokenService, err := services.NewAuthManagerTokenService()
		if err == nil {
			config.TokenService = tokenService
		}
	}
}

func TestEndUserAuthController_Instantiation(t *testing.T) {
	controller, err := NewEndUserAuthController()

	if err == nil && controller != nil {
		t.Skip("Database available; skipping negative instantiation test")
	}

	assert.Nil(t, controller)
	assert.Error(t, err) // Expected DB connection error in test
}

func TestEndUserAuthController_MethodsExist(t *testing.T) {
	controller, err := NewEndUserAuthController()
	if err != nil || controller == nil {
		t.Skip("database not initialized for controller methods test")
	}

	// Legacy client_id-first handlers (InitiateRegistration, Login,
	// VerifyOTPAndCompleteRegistration, VerifyLoginOTP, ResendOTP, WebAuthnRegister,
	// WebAuthnMFALoginStatus) were removed; the v4 flow lives in EndUserController.
	assert.NotNil(t, controller.SAMLLogin)
	assert.NotNil(t, controller.WebAuthnCallback)
	assert.NotNil(t, controller.GetAuthChallenge)
}

func TestEndUserAuthController_generateJWTTokenCompatibility(t *testing.T) {
	controller := &EndUserAuthController{}

	userID := uuid.New()
	workspaceID := uuid.NewString() // a token is always for a real workspace (AS-095)
	token, err := controller.generateJWTToken(workspaceID, "client-1", "user@example.com", "example.com", &userID, nil)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// An end-user-class token (AS-033): it verifies only as that class, and
	// never under the raw JWT_DEF_SECRET.
	_, rawErr := jwt.Parse(token, func(tok *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_DEF_SECRET")), nil
	})
	require.Error(t, rawErr)
	_, _, err = sessiontoken.Verify(token, sessiontoken.Admin)
	require.Error(t, err)
	claims, class, err := sessiontoken.Verify(token, sessiontoken.EndUser)
	require.NoError(t, err)
	require.Equal(t, sessiontoken.EndUser, class)

	// Ultra-minimal token: identity only
	// Auth-manager fetches roles/permissions from DB via GetAuthz() on every request
	assert.Equal(t, "authsec-ai/auth-manager", claims["iss"])
	assert.Equal(t, "authsec-enduser", claims["aud"])
	assert.Equal(t, "enduser", claims["typ"])
	assert.Equal(t, workspaceID, claims["workspace_id"])
	assert.Equal(t, workspaceID, claims["project_id"]) // project_id defaults to workspace_id for endusers
	assert.Equal(t, "client-1", claims["client_id"])
	assert.Equal(t, "user@example.com", claims["email_id"])

	now := time.Now().Unix()
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))

	require.LessOrEqual(t, iat, now, "issued-at should not be in the future")
	require.Greater(t, exp, now, "expiration should be in the future")
	require.InDelta(t, (365 * 24 * time.Hour).Seconds(), float64(exp-iat), 5, "token lifetime should be ~365 days")
}
