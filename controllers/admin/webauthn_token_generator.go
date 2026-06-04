package admin

import (
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
)

// WebAuthnRegisterInternal is called by the webauthn handler after a successful
// WebAuthn registration or authentication to obtain JWT tokens.
// It replaces the HTTP POST to /uflow/webauthn/register from the old microservice setup.
func WebAuthnRegisterInternal(clientID, email, workspaceID string) (accessToken, refreshToken string, err error) {
	uc, err := NewUserController()
	if err != nil {
		return "", "", err
	}
	return uc.generateWebAuthnTokens(clientID, email, workspaceID)
}

// generateWebAuthnTokens is the internal implementation used by WebAuthnRegisterInternal.
// It replicates the token generation logic from WebAuthnRegister but returns tokens
// directly instead of writing an HTTP response.
//
// Flow:
//  1. Look up tenant by workspaceID
//  2. Look up user by email in the global database
//  3. Verify the user is active and MFA-verified
//  4. Generate and return JWT tokens using the centralized token service
func (uc *UserController) generateWebAuthnTokens(clientID, email, workspaceID string) (accessToken, refreshToken string, err error) {
	log.Printf("[WebAuthnBridge] Generating tokens for email=%s, workspaceID=%s, clientID=%s", email, workspaceID, clientID)

	// Look up tenant by workspaceID
	tenant, err := uc.workspaceRepo.GetWorkspaceByWorkspaceID(workspaceID)
	if err != nil {
		log.Printf("[WebAuthnBridge] Tenant not found for workspaceID=%s: %v", workspaceID, err)
		return "", "", fmt.Errorf("tenant not found: %w", err)
	}

	// Look up user by email, scoped to the workspace
	user, err := uc.userRepo.GetUserByEmailAndTenant(email, tenant.WorkspaceID)
	if err != nil {
		log.Printf("[WebAuthnBridge] User not found for email=%s: %v", email, err)
		return "", "", fmt.Errorf("user not found: %w", err)
	}

	// Verify user is active
	if !user.Active {
		log.Printf("[WebAuthnBridge] User account disabled for email=%s", email)
		return "", "", fmt.Errorf("account is disabled")
	}

	// Verify MFA was verified before issuing tokens
	// The webauthn handlers must have set mfa_verified=true after successful credential verification
	if !user.MFAVerified {
		log.Printf("[WebAuthnBridge] MFA not verified for email=%s - tokens not issued", email)
		return "", "", fmt.Errorf("MFA verification required: webauthn credentials must be verified first")
	}

	log.Printf("[WebAuthnBridge] MFA verification confirmed for email=%s, workspaceID=%s", email, workspaceID)

	// Parse UUIDs
	workspaceUUID, err := uuid.Parse(tenant.WorkspaceID.String())
	if err != nil {
		return "", "", fmt.Errorf("invalid workspace_id: %w", err)
	}

	// Generate access token using the centralized auth-manager token service
	token, err := config.TokenService.GenerateTenantUserToken(
		user.ID,
		workspaceUUID,
		email,
		24*time.Hour,
	)
	if err != nil {
		log.Printf("[WebAuthnBridge] Token generation failed for email=%s: %v", email, err)
		return "", "", fmt.Errorf("token generation failed: %w", err)
	}

	log.Printf("[WebAuthnBridge] Tokens generated successfully for email=%s", email)

	// Return access token; refresh_token is empty in this flow (same as the HTTP handler)
	return token, "", nil
}

// WebAuthnRegisterInternalForTest calls WebAuthnRegisterInternal for test access.
func WebAuthnRegisterInternalForTest(clientID, email, workspaceID string) (string, string, error) {
	return WebAuthnRegisterInternal(clientID, email, workspaceID)
}
