package sharedmodels

import (
	"time"

	"github.com/google/uuid"
)

// Request models for client registration
type RegisterClientsRequest struct {
	WorkspaceID  string `json:"workspace_id" binding:"required"`
	ProjectID string `json:"project_id" binding:"required"`
	Name      string `json:"name" binding:"required"`
	Email     string `json:"email" binding:"required"`
}

type RegisterClientsResponse struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	WorkspaceID  string    `json:"workspace_id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	SecretID  string    `json:"secret_id,omitempty"`
	Email     string    `json:"email"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	Message   string    `json:"message"`
}

// Paginated response models
type PaginatedEndUsersResponse struct {
	Users      []User `json:"users"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
	TotalPages int    `json:"total_pages"`
}

// Update models
type UpdateEndUserStatusInput struct {
	Active bool `json:"active" binding:"required"`
}

type UpdateEndUserStatusResponse struct {
	Message   string    `json:"message"`
	Active    bool      `json:"active"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OIDC Login models
type OIDCLoginInput struct {
	AccessToken string `json:"access_token" binding:"required"`
}

// Custom login models
type CustomLoginInput struct {
	// WorkspaceID is the canonical scope, resolved by the UI from the Hydra
	// login_challenge page-data. Accepts UUID, slug, or workspace_domain.
	WorkspaceID string `json:"workspace_id"`
	// ClientID is deprecated for user-identity flows; no longer used as the
	// workspace identifier. Kept optional so older builds don't 400.
	ClientID string `json:"client_id"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CustomLoginStatus struct {
	// WorkspaceID is the canonical scope. The UI sets it from the page-data
	// response that resolved the Hydra login_challenge. Accepts UUID, slug,
	// or workspace_domain.
	WorkspaceID string `json:"workspace_id"`
	// ClientID is deprecated for user-identity flows — it is NOT used to
	// resolve the workspace anymore (OAuth clients are global per OAuth 2.1).
	// Kept optional so older UI builds don't 400 during the rollout; ignored.
	ClientID string `json:"client_id"`
	Email    string `json:"email" binding:"required"`
}

type CustomLoginRegister struct {
	WorkspaceID string `json:"workspace_id"`
	ClientID    string `json:"client_id"` // deprecated, ignored — see CustomLoginStatus
	Email       string `json:"email" binding:"required"`
	Password    string `json:"password" binding:"required"`
}

// Forgot password models
type CustomForgotPasswordInput struct {
	WorkspaceID string `json:"workspace_id"`
	ClientID    string `json:"client_id"` // deprecated, ignored
	Email       string `json:"email" binding:"required"`
}

type CustomForgotPasswordResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

type CustomVerifyPasswordResetOTPInput struct {
	Email string `json:"email" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}

type CustomVerifyPasswordResetOTPResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

type CustomResetPasswordInput struct {
	// WorkspaceID scopes the password reset user lookup.
	WorkspaceID string `json:"workspace_id"`
	// ClientID is deprecated; ignored by the backend.
	ClientID    string `json:"client_id"`
	Email       string `json:"email" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type CustomResetPasswordResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

// Admin password management models
type AdminChangePasswordInput struct {
	WorkspaceID    string `json:"workspace_id" binding:"required"`
	UserID      string `json:"user_id,omitempty"`
	Email       string `json:"email,omitempty"`
	NewPassword string `json:"new_password" binding:"required"`
}

type AdminChangePasswordResponse struct {
	Message  string `json:"message"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	WorkspaceID string `json:"workspace_id"`
}

type AdminResetPasswordInput struct {
	WorkspaceID  string `json:"workspace_id" binding:"required"`
	UserID    string `json:"user_id,omitempty"`
	Email     string `json:"email,omitempty"`
	SendEmail bool   `json:"send_email,omitempty"`
}

type AdminResetPasswordResponse struct {
	Message           string `json:"message"`
	UserID            string `json:"user_id"`
	Email             string `json:"email"`
	WorkspaceID          string `json:"workspace_id"`
	TemporaryPassword string `json:"temporary_password,omitempty"`
	EmailSent         bool   `json:"email_sent"`
}

// OTP Entry model

// Token verification models
type TokenVerifyRequest struct {
	Token string `json:"token" binding:"required"`
}

type TokenVerifyResponse struct {
	Valid  bool      `json:"valid"`
	UserID uuid.UUID `json:"user_id,omitempty"`
	Error  string    `json:"error,omitempty"`
}

//
