package services

import (
	"fmt"
	"os"
	"time"

	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AuthManagerTokenService provides centralized token generation using auth-manager library
// This service wraps auth-manager's TokenController for programmatic token generation
type AuthManagerTokenService struct {
	jwtDefaultSecret []byte // "default" key (KID: "default")
	jwtSDKSecret     []byte // "sdk-agent" key (KID: "sdk-agent")
}

// NewAuthManagerTokenService creates a new token service using auth-manager library
func NewAuthManagerTokenService() (*AuthManagerTokenService, error) {
	defaultSecret := os.Getenv("JWT_DEF_SECRET")
	if defaultSecret == "" {
		return nil, fmt.Errorf("CRITICAL: JWT_DEF_SECRET environment variable is not set. Cannot generate secure tokens")
	}

	sdkSecret := os.Getenv("JWT_SDK_SECRET")
	if sdkSecret == "" {
		return nil, fmt.Errorf("CRITICAL: JWT_SDK_SECRET environment variable is not set. Cannot generate secure tokens")
	}

	return &AuthManagerTokenService{
		jwtDefaultSecret: []byte(defaultSecret),
		jwtSDKSecret:     []byte(sdkSecret),
	}, nil
}

// TokenClaims represents the standard claims structure for auth-manager compatible tokens
type TokenClaims struct {
	WorkspaceID           string
	WorkspaceMembershipID string
	WorkspaceDomain       string // Tenant domain for display/routing
	ClientID              string
	EmailID               string
	UserID                *uuid.UUID
	Scopes                []string
	Roles                 []string // User roles for authorization
	// ProjectID is a backward-compat mirror of workspace_id, emitted ONLY for
	// end-user tokens (GenerateEndUserToken) where downstream consumers still read
	// project_id. Phase 6 dropped tenant_id entirely; project_id is a separate,
	// documented end-user affordance and is omitted from every other token type.
	ProjectID string
	ExpiresIn time.Duration
}

// GenerateToken generates a JWT token following auth-manager patterns
// Token type: "default" (uses JWT_DEF_SECRET with KID: "default")
// Auth-manager fetches roles/permissions from DB via GetAuthz() on every request
// Tokens contain minimal claims; authorization data is fetched from database dynamically
func (s *AuthManagerTokenService) GenerateToken(claims TokenClaims) (string, error) {
	return s.generateTokenWithType(claims, "default", s.jwtDefaultSecret)
}

// GenerateSDKToken generates an SDK/agent token following auth-manager patterns
// Token type: "sdk-agent" (uses JWT_SDK_SECRET with KID: "sdk-agent")
// Used for service-to-service authentication
func (s *AuthManagerTokenService) GenerateSDKToken(claims TokenClaims) (string, error) {
	return s.generateTokenWithType(claims, "sdk-agent", s.jwtSDKSecret)
}

func (s *AuthManagerTokenService) GenerateWorkspaceToken(userID uuid.UUID, workspaceID uuid.UUID, membershipID uuid.UUID, clientID string, email string, expiresIn time.Duration) (string, error) {
	if clientID == "" {
		clientID = userID.String()
	}

	return s.GenerateToken(TokenClaims{
		WorkspaceID:           workspaceID.String(),
		WorkspaceMembershipID: membershipID.String(),
		ClientID:              clientID,
		EmailID:               email,
		UserID:                &userID,
		ExpiresIn:             expiresIn,
	})
}

// Uses the same algorithm as auth-manager's TokenController.GenerateToken()
func (s *AuthManagerTokenService) generateTokenWithType(claims TokenClaims, tokenType string, secret []byte) (string, error) {
	now := time.Now()
	expiresIn := claims.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 24 * time.Hour // Default 24 hours
	}

	// Phase 6: workspace_id is the only identity claim emitted.
	workspaceID := claims.WorkspaceID

	// Build JWT claims following auth-manager's exact pattern
	// Reference: github.com/authsec-ai/auth-manager/controllers/token_controller.go
	jwtClaims := jwt.MapClaims{
		"workspace_id": workspaceID,
		"client_id":    claims.ClientID,
		"email_id":     claims.EmailID,
		"token_type":   tokenType,
		"aud":          "authsec-api",
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(expiresIn).Unix(),
		"iss":          "authsec-ai/auth-manager",
	}
	if claims.WorkspaceMembershipID != "" {
		jwtClaims["workspace_membership_id"] = claims.WorkspaceMembershipID
	}

	// project_id (end-user backward-compat mirror of workspace_id) — emitted only
	// when set, i.e. only for end-user tokens. Not tenant_id; other token types
	// stay workspace_id-only per Phase 6.
	if claims.ProjectID != "" {
		jwtClaims["project_id"] = claims.ProjectID
	}

	// Add optional user_id if provided
	if claims.UserID != nil {
		jwtClaims["user_id"] = claims.UserID.String()
		jwtClaims["sub"] = claims.UserID.String() // Standard JWT subject claim
	}

	// Add scopes if provided (auth-manager fetches full authz from DB on validation)
	if len(claims.Scopes) > 0 {
		jwtClaims["scope"] = claims.Scopes
	}

	// Add workspace_domain if provided
	if claims.WorkspaceDomain != "" {
		jwtClaims["workspace_domain"] = claims.WorkspaceDomain
	}

	// Add roles if provided
	if len(claims.Roles) > 0 {
		jwtClaims["roles"] = claims.Roles
	}

	// Sign token using auth-manager's signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	token.Header["kid"] = tokenType // KID header for key selection

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateTokenViaAuthManager generates a token using auth-manager's TokenRequest model
// This is a programmatic wrapper around auth-manager's token generation logic
func (s *AuthManagerTokenService) GenerateTokenViaAuthManager(req *sharedmodels.TokenRequest) (string, error) {
	// Auth-manager's TokenController.GenerateToken() requires Gin context
	// Since we're using it programmatically, we replicate its logic here
	// using the same signing secrets and algorithm

	tokenType := "default"
	secret := s.jwtDefaultSecret

	if req.SecretID != nil {
		tokenType = "sdk-agent"
		secret = s.jwtSDKSecret
	}

	now := time.Now()
	// Phase 6: workspace_id is the only identity claim.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"workspace_id": req.WorkspaceID,
		"client_id":    req.ClientID,
		"email_id":     req.EmailID,
		"token_type":   tokenType,
		"aud":          "authsec-api",
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(24 * time.Hour).Unix(),
		"iss":          "authsec-ai/auth-manager",
	})
	token.Header["kid"] = tokenType

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate token via auth-manager pattern: %w", err)
	}

	return tokenString, nil
}

// GenerateAdminToken generates a token for admin users
func (s *AuthManagerTokenService) GenerateAdminToken(adminUserID uuid.UUID, email string, workspaceID *uuid.UUID, workspaceDomain string, roles []string) (string, error) {
	// Use actual workspace_id if provided, otherwise default to "admin" for super-admins
	workspaceIDStr := "admin"
	if workspaceID != nil && *workspaceID != uuid.Nil {
		workspaceIDStr = workspaceID.String()
	}

	claims := TokenClaims{
		WorkspaceID:     workspaceIDStr,  // Use actual workspace_id
		WorkspaceDomain: workspaceDomain, // Include tenant domain
		ClientID:        adminUserID.String(),
		EmailID:         email,
		UserID:          &adminUserID,
		Roles:           roles, // Include admin roles
		ExpiresIn:       24 * time.Hour,
	}
	return s.GenerateToken(claims)
}

// GenerateTenantUserToken generates a token for tenant users
func (s *AuthManagerTokenService) GenerateTenantUserToken(
	userID uuid.UUID,
	workspaceID uuid.UUID,
	email string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID.String(),
		ClientID:    userID.String(),
		EmailID:     email,
		UserID:      &userID,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}

// GenerateEndUserToken generates a token for end users (with default project_id = workspace_id)
func (s *AuthManagerTokenService) GenerateEndUserToken(
	userID uuid.UUID,
	workspaceID string,
	clientID string,
	email string,
	scopes []string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID,
		ProjectID:   workspaceID, // end-user compat: project_id mirrors workspace_id
		ClientID:    clientID,
		EmailID:     email,
		UserID:      &userID,
		Scopes:      scopes,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}

// GenerateVoiceAuthToken generates a token for voice authentication
func (s *AuthManagerTokenService) GenerateVoiceAuthToken(
	userID uuid.UUID,
	workspaceID uuid.UUID,
	email string,
	scopes []string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID.String(),
		ClientID:    userID.String(),
		EmailID:     email,
		UserID:      &userID,
		Scopes:      scopes,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}

// GenerateDeviceAuthToken generates a token for device authentication flows
func (s *AuthManagerTokenService) GenerateDeviceAuthToken(
	userID uuid.UUID,
	workspaceID uuid.UUID,
	email string,
	scopes []string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID.String(),
		ClientID:    userID.String(),
		EmailID:     email,
		UserID:      &userID,
		Scopes:      scopes,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}

// GenerateCIBAToken generates a token for CIBA (Client-Initiated Backchannel Authentication)
func (s *AuthManagerTokenService) GenerateCIBAToken(
	userID uuid.UUID,
	workspaceID uuid.UUID,
	email string,
	scopes []string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID.String(),
		ClientID:    userID.String(),
		EmailID:     email,
		UserID:      &userID,
		Scopes:      scopes,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}

// GenerateTenantCIBAToken generates a CIBA token with the correct client_id (not user_id)
func (s *AuthManagerTokenService) GenerateTenantCIBAToken(
	userID uuid.UUID,
	workspaceID uuid.UUID,
	clientID uuid.UUID,
	email string,
	scopes []string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID.String(),
		ClientID:    clientID.String(),
		EmailID:     email,
		UserID:      &userID,
		Scopes:      scopes,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}

// GenerateTOTPToken generates a token for TOTP authentication
func (s *AuthManagerTokenService) GenerateTOTPToken(
	userID uuid.UUID,
	workspaceID uuid.UUID,
	email string,
	expiresIn time.Duration,
) (string, error) {
	claims := TokenClaims{
		WorkspaceID: workspaceID.String(),
		ClientID:    userID.String(),
		EmailID:     email,
		UserID:      &userID,
		ExpiresIn:   expiresIn,
	}
	return s.GenerateToken(claims)
}
