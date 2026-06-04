package sharedmodels

import (
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
	"time"
)

// HashPassword hashes the user's password before saving
func (u *User) HashPassword() error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hashedPassword)
	return nil
}

// CheckPassword compares the provided password with the stored hash
func (u *User) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}

// Duplicate client registration types removed (kept in requests.go)

// Duplicate types removed: UpdateEndUserStatusInput, UpdateEndUserStatusResponse,
// PaginatedEndUsersResponse, OIDCLoginInput (kept in requests.go)

type OIDCLoginResponse struct {
	Message     string `json:"message"`
	RedirectURL string `json:"redirect_url"`
}

// Duplicate Introspection type removed (canonical in hydra.go)

/*
type Client struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	ClientID  string    `json:"client_id" gorm:"uniqueIndex;not null"`
	WorkspaceID  string    `json:"workspace_id" gorm:"not null;index"`
	ProjectID string    `json:"project_id" gorm:"not null;index"`
	Name      string    `json:"name"`
	Active    bool      `json:"active" gorm:"default:true;index"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}
*/

// v0.2.0 changes to the struct that is being used by Clients microservice
//moved to a new file clients.go
/*
type Client struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID      `json:"workspace_id" gorm:"not null;type:uuid;index:idx_clients_tenant_org" binding:"required"`
	OwnerID   uuid.UUID      `json:"owner_id" gorm:"not null;type:uuid;index:idx_clients_owner" binding:"required"`    // Maps to ClientID in auth-manager
	ProjectID uuid.UUID      `json:"project_id" gorm:"not null;uniqueIndex"`
	Roles     []Role         `json:"roles" gorm:"many2many:client_roles;"`
	Name      string         `json:"name" gorm:"not null" binding:"required"`
	Status    string         `json:"status" gorm:"default:'Development';index:idx_clients_status"`
	Tags      pq.StringArray `json:"tags" gorm:"type:text[]"`
	Active    bool           `json:"active" gorm:"default:true"` // Align with auth-manager Client.Active
	// OIDC Integration Fields
	HydraClientID string         `json:"hydra_client_id,omitempty" gorm:"unique"`
	OIDCEnabled   bool           `json:"oidc_enabled" gorm:"default:false"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	// Tenant relationship fields (optional, for future use)
	WorkspaceDB string `json:"workspace_db,omitempty" gorm:"-"` // Not stored, populated from auth-manager
}
*/
type User struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid();uniqueIndex:idx_users_workspace_id_id"`
	ClientID         uuid.UUID      `json:"client_id" gorm:"type:uuid;not null;index"`
	WorkspaceID         uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null;index:idx_users_workspace_id;uniqueIndex:idx_users_workspace_id_id;uniqueIndex:idx_users_email_tenant"`
	ProjectID        uuid.UUID      `json:"project_id" gorm:"type:uuid;not null;index"`
	Name             string         `json:"name"`
	Username         *string        `json:"username,omitempty" gorm:"type:text"`
	Email            string         `json:"email" gorm:"type:text;not null;uniqueIndex:idx_users_email_tenant"`
	PasswordHash     string         `json:"password_hash,omitempty"`
	WorkspaceDomain     string         `json:"workspace_domain" gorm:"type:text;not null"`
	Provider         string         `json:"provider" gorm:"type:text;not null;index:idx_users_provider"`
	ProviderID       string         `json:"provider_id" gorm:"type:text;not null;index:idx_users_provider"`
	ProviderData     datatypes.JSON `json:"provider_data,omitempty" gorm:"type:jsonb"`
	AvatarURL        *string        `json:"avatar_url,omitempty" gorm:"type:text"`
	Active           bool           `json:"active" gorm:"default:true;index"`
	Groups           []Group        `json:"groups" gorm:"many2many:user_groups;"`
	MFAEnabled       bool           `json:"mfa_enabled" gorm:"default:false;not null"`
	MFAMethod        pq.StringArray `json:"mfa_method,omitempty" gorm:"type:text[]"`
	MFADefaultMethod *string        `json:"mfa_default_method,omitempty" gorm:"type:text"`
	MFAEnrolledAt    *time.Time     `json:"mfa_enrolled_at,omitempty" gorm:"type:timestamptz"`
	MFAVerified      bool           `json:"mfa_verified" gorm:"default:false;not null"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	LastLogin        *time.Time     `json:"last_login,omitempty" gorm:"type:timestamptz"`
	ExternalID       *string        `json:"external_id,omitempty" gorm:"type:text"`
	SyncSource       *string        `json:"sync_source,omitempty" gorm:"type:text"`
	LastSyncAt       *time.Time     `json:"last_sync_at,omitempty" gorm:"type:timestamptz"`
	IsSyncedUser     bool           `json:"is_synced_user" gorm:"default:false"`
}

// Duplicate custom login types removed (kept in requests.go)

// Add these models to your models package
// Following the same pattern as your existing CustomLoginInput, CustomLoginStatus, etc.

// Input models for custom login forgot password flow
// Duplicate custom forgot/reset password types removed (kept in requests.go)
// Duplicate admin password types removed (kept in requests.go)

// Add these models to your models package for admin forgot password functionality

// Input models for admin forgot password flow
type AdminForgotPasswordInput struct {
	Email string `json:"email" binding:"required,email" validate:"required,email"`
}

type AdminVerifyPasswordResetOTPInput struct {
	Email string `json:"email" binding:"required,email" validate:"required,email"`
	OTP   string `json:"otp" binding:"required" validate:"required"`
}

type AdminResetPasswordInput2 struct {
	Email       string `json:"email" binding:"required,email" validate:"required,email"`
	NewPassword string `json:"new_password" binding:"required,min=8" validate:"required,min=8"`
}

// Response models for admin forgot password flow
type AdminForgotPasswordResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

type AdminVerifyPasswordResetOTPResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

type AdminResetPasswordResponse2 struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

// Service represents a service in the system (not in sharedmodels)
type Service struct {
	ID              uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name            string         `json:"name" gorm:"not null"`
	Type            string         `json:"type"`
	URL             string         `json:"url"`
	Description     string         `json:"description"`
	Tags            pq.StringArray `json:"tags" gorm:"type:text[]"`
	ResourceID      uuid.UUID      `json:"resource_id" gorm:"type:uuid;not null"`
	AuthType        string         `json:"auth_type" gorm:"not null"`
	AuthConfig      string         `json:"auth_config"`
	VaultPath       string         `json:"vault_path"`
	CreatedBy       string         `json:"created_by" gorm:"not null"`
	AgentAccessible bool           `json:"agent_accessible" gorm:"default:true"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}
