package sharedmodels

import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

// Configuration values retrieved from environment
var (
	DBName     string
	DBHost     string
	DBUser     string
	DBPassword string
	DBPort     string
)

func init() {
	DBName = os.Getenv("DB_NAME")
	DBHost = os.Getenv("DB_HOST")
	DBUser = os.Getenv("DB_USER")
	DBPassword = os.Getenv("DB_PASSWORD")
	DBPort = os.Getenv("DB_PORT")
}

type Tenant struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID     uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;uniqueIndex"`
	TenantDB     string     `json:"tenant_db"`
	Email        string     `json:"email" gorm:"type:text;uniqueIndex;not null"`
	Username     *string    `json:"username,omitempty" gorm:"type:text"`
	PasswordHash string     `json:"password_hash,omitempty"`
	Provider     string     `gorm:"type:text;default:'local';index:idx_users_provider" json:"provider"`
	ProviderID   *string    `json:"provider_id,omitempty" gorm:"type:text"`
	Avatar       *string    `json:"avatar,omitempty" gorm:"type:text"`
	Name         string     `json:"name,omitempty"`
	Source       string     `json:"source,omitempty"`
	Status       string     `json:"status,omitempty"`
	LastLogin    *time.Time `json:"last_login,omitempty" gorm:"type:timestamptz"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	TenantDomain string     `json:"tenant_domain,omitempty" gorm:"uniqueIndex;not null"`
}

// TableName returns the table name for the Tenant model
func (Tenant) TableName() string {
	return "tenants"
}

type RegisterResponse struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	ProjectID    uuid.UUID `json:"project_id"`
	ClientID     uuid.UUID `json:"client_id"`
	EmailID      string    `json:"email_id"`
	TenantDomain string    `json:"tenant_domain"`
}

type OTPEntry struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email     string    `json:"email"`
	OTP       string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	Verified  bool      `json:"verified" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PendingRegistration struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	TenantID     uuid.UUID `json:"tenant_id" gorm:"type:uuid"`
	ProjectID    uuid.UUID `json:"project_id" gorm:"type:uuid"`
	ClientID     uuid.UUID `json:"client_id" gorm:"type:uuid"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	TenantDomain string    `json:"tenant_domain"`
}

// Updated Input/Response models using your existing structures
type InitiateRegistrationInput struct {
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required,min=10"`
	FirstName    string `json:"first_name" binding:"required"`
	LastName     string `json:"last_name" binding:"required"`
	TenantDomain string `json:"tenant_domain" binding:"required"`
}

type InitiateRegistrationResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
}

type VerifyOTPInput struct {
	Email string `json:"email" binding:"required,email"`
	OTP   string `json:"otp" binding:"required,len=6"`
}

type ResendOTPInput struct {
	Email string `json:"email" binding:"required,email"`
}

type LoginInput struct {
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required,min=10"`
	TenantDomain string `json:"tenant_domain" binding:"required"`
}

// MFAMethod represents an MFA method for a client
type MFAMethod struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID    uuid.UUID      `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID      *uuid.UUID     `json:"user_id,omitempty" gorm:"type:uuid;index"`
	MethodType  string         `json:"method_type" gorm:"type:varchar(50);not null;index"`
	DisplayName string         `json:"display_name" gorm:"type:varchar(255)"`
	Description string         `json:"description" gorm:"type:varchar(255)"`
	Recommended bool           `json:"recommended" gorm:"default:false"`
	MethodData  datatypes.JSON `json:"method_data" gorm:"type:jsonb"`
	Enabled     bool           `json:"enabled" gorm:"default:false;index"`
	IsPrimary   bool           `json:"is_primary" gorm:"default:false"`
	Verified    bool           `json:"verified" gorm:"default:false"`
	BackupCodes *string        `json:"backup_codes,omitempty" gorm:"type:varchar(255)"`
	EnrolledAt  time.Time      `json:"enrolled_at" gorm:"type:timestamptz;autoCreateTime"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty" gorm:"type:timestamptz"`
	LastUsedAt  *time.Time     `json:"last_used_at,omitempty" gorm:"type:timestamptz"`
	CreatedAt   time.Time      `json:"created_at" gorm:"type:timestamptz;autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"type:timestamptz;autoUpdateTime"`
}

// TableName returns the table name for the MFAMethod model
func (MFAMethod) TableName() string {
	return "mfa_methods"
}

// Credential stores a registered WebAuthn credential
type Credential struct {
	ID              uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID        uuid.UUID      `json:"client_id" gorm:"type:uuid;not null"`
	CredentialID    []byte         `json:"credential_id" gorm:"not null;uniqueIndex"`
	PublicKey       []byte         `json:"public_key" gorm:"not null"`
	AttestationType string         `json:"attestation_type" gorm:"not null"`
	AAGUID          *uuid.UUID     `json:"aaguid" gorm:"type:uuid"`
	SignCount       int64          `json:"sign_count" gorm:"not null;default:0"`
	BackupEligible  bool           `json:"backup_eligible" gorm:"default:false"`
	BackupState     bool           `json:"backup_state" gorm:"default:false"`
	Transports      pq.StringArray `json:"transports" gorm:"type:text[]"`
	CreatedAt       time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt       time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
}

// TableName returns the table name for the Credential model
func (Credential) TableName() string {
	return "credentials"
}

type WebAuthnCallbackInput struct {
	Email       string    `json:"email" binding:"required,email"`
	MFAVerified *bool     `json:"mfa_verified" binding:"required"`
	TenantID    uuid.UUID `json:"tenant_id" binding:"required"`
}
