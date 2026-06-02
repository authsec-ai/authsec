package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Application types for the resource_servers row.
const (
	ApplicationTypeMCPServer  = "mcp_server"
	ApplicationTypeAIAgent    = "ai_agent"
	ApplicationTypeClawbot    = "clawbot"
	ApplicationTypeAPIService = "api_service"
)

// ResourceServer is the tenant's Application row. Lives in the tenant DB.
// TenantID is a string here because prod's tenant_id is propagated as a string
// in the tenant-DB layer.
type ResourceServer struct {
	ID                       uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID                 string         `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ApplicationType          string         `json:"application_type" gorm:"type:text;not null;default:'mcp_server'"`
	LegacyClientID           *uuid.UUID     `json:"legacy_client_id,omitempty" gorm:"type:uuid"`
	Name                     string         `json:"name" gorm:"not null"`
	PublicBaseURL            string         `json:"public_base_url" gorm:"not null"`
	ProtectedBasePath        string         `json:"protected_base_path" gorm:"not null;default:'/mcp'"`
	ResourceURI              string         `json:"resource_uri" gorm:"not null;uniqueIndex"`
	ScopesSupported          pq.StringArray `json:"scopes_supported" gorm:"type:text[];default:'{}'"`
	RegistrationModes        pq.StringArray `json:"registration_modes" gorm:"type:text[];default:'{dcr,cimd,prereg}'"`
	IntrospectionSecret      string         `json:"-" gorm:"column:introspection_secret"`
	IntrospectionSecretHash  string         `json:"-" gorm:"column:introspection_secret_hash;type:text"`
	Active                   bool           `json:"active" gorm:"default:true"`
	State                    string         `json:"state" gorm:"type:text;not null;default:'pending_scan'"`
	SetupCompletedAt         *time.Time     `json:"setup_completed_at,omitempty"`
	SetupCompletedBy         *uuid.UUID     `json:"setup_completed_by,omitempty" gorm:"type:uuid"`
	Status                   string         `json:"status" gorm:"type:text;not null;default:'pending_scan'"`
	ScanGeneration           int            `json:"scan_generation" gorm:"not null;default:0"`
	LastSuccessfulGeneration int            `json:"last_successful_generation" gorm:"not null;default:0"`
	ScanInProgress           bool           `json:"-" gorm:"not null;default:false"`
	LastScanStatus           *string        `json:"last_scan_status,omitempty" gorm:"type:text"`
	LastScanError            *string        `json:"last_scan_error,omitempty" gorm:"type:text"`
	LastScanStartedAt        *time.Time     `json:"last_scan_started_at,omitempty"`
	LastScanCompletedAt      *time.Time     `json:"last_scan_completed_at,omitempty"`
	LastValidatedAt          *time.Time     `json:"last_validated_at,omitempty" gorm:"type:timestamptz"`
	LastValidationStatus     *string        `json:"last_validation_status,omitempty" gorm:"type:text"`
	LastValidationError      *string        `json:"last_validation_error,omitempty" gorm:"type:text"`
	SPIFFEID                 *string        `json:"spiffe_id,omitempty" gorm:"column:spiffe_id;type:text"`
	AgentType                *string        `json:"agent_type,omitempty" gorm:"type:text"`
	CreatedAt                time.Time      `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt                time.Time      `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt                gorm.DeletedAt `json:"-" gorm:"index"`
}

func (ResourceServer) TableName() string { return "resource_servers" }
