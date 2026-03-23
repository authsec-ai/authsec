package handlers

import (
	sharedmodels "github.com/authsec-ai/sharedmodels"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// SessionManagerInterface defines session management methods
type SessionManagerInterface interface {
	Save(key string, data interface{}) error
	Get(key string) (interface{}, bool)
	Delete(key string)
}

// WebAuthnHandler handles WebAuthn operations
type WebAuthnHandler struct {
	WebAuthn       *webauthn.WebAuthn
	SessionManager SessionManagerInterface
	RPDisplayName  string
	RPID           string
	RPOrigins      []string
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// WebAuthn Request/Response structs
type BeginRegistrationRequest struct {
	TenantID string `json:"tenant_id" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

type BeginAuthenticationRequest struct {
	TenantID string `json:"tenant_id" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

type FinishAuthenticationRequest struct {
	TenantID   string                               `json:"tenant_id" binding:"required"`
	Email      string                               `json:"email" binding:"required,email"`
	Credential protocol.CredentialAssertionResponse `json:"credential" binding:"required"`
}

type RegistrationSuccessResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	CredentialID string `json:"credential_id,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type AuthenticationSuccessResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	CredentialID string `json:"credential_id,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// WebAuthnUser wraps a User for WebAuthn operations
type WebAuthnUser struct {
	*sharedmodels.User
	credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.ID.String())
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.Email
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *WebAuthnUser) SetCredentials(creds []webauthn.Credential) {
	u.credentials = creds
}

// SessionData represents data stored in sessions - matches webauthn.SessionData
type SessionData struct {
	Challenge        string                 `json:"challenge"`
	UserID           []byte                 `json:"user_id,omitempty"`
	UserVerification string                 `json:"user_verification,omitempty"`
	Extensions       map[string]interface{} `json:"extensions,omitempty"`
}

// ToWebAuthnSessionData converts our SessionData to webauthn.SessionData
func (s *SessionData) ToWebAuthnSessionData() *webauthn.SessionData {
	if s == nil {
		return nil
	}
	return &webauthn.SessionData{
		Challenge:        s.Challenge,
		UserID:           s.UserID,
		UserVerification: protocol.UserVerificationRequirement(s.UserVerification),
		Extensions:       s.Extensions,
	}
}
