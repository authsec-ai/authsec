package sharedmodels

type BeginRegistrationRequest struct {
	WorkspaceID string `json:"workspace_id" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

type MFAOption struct {
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Recommended bool   `json:"recommended"`
	Enabled     bool   `json:"enabled"`
}

type MFAMethodsResponse struct {
	AvailableMFAMethods []MFAOption `json:"available_mfa_methods"`
	UserID              string      `json:"user_id"`
	Email               string      `json:"email"`
	ExistingMethods     int         `json:"existing_methods"`
	Message             string      `json:"message"`
}

type WebAuthnOptionsResponse struct {
	PublicKey interface{} `json:"publicKey"`
}

type FinishRegistrationRequest struct {
	WorkspaceID string      `json:"workspace_id" binding:"required"`
	Email    string      `json:"email" binding:"required,email"`
	Response interface{} `json:"response" binding:"required"`
}

type RegistrationSuccessResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	CredentialID string `json:"credential_id,omitempty"`
}

type AuthenticationSuccessResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	CredentialID string `json:"credential_id,omitempty"`
}

type WebAuthnHandler struct {
	WebAuthn      interface{}
	RPDisplayName string
	RPID          string
	RPOrigins     []string
}

type WebAuthnUser struct {
	*Tenant
	credentials []interface{}
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

func (u *WebAuthnUser) WebAuthnCredentials() []interface{} {
	return u.credentials
}

func (u *WebAuthnUser) SetCredentials(creds []interface{}) {
	u.credentials = creds
}

type LoginSuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
