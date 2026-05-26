package sharedmodels

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Client represents a client in the tenant-aware system
// Inherits tenant structure from auth-manager for consistency
type Client struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID         uuid.UUID      `json:"client_id" gorm:"type:uuid;not null;uniqueIndex"`
	WorkspaceID      uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null" binding:"required"`
	ProjectID        uuid.UUID      `json:"project_id" gorm:"type:uuid;not null"`
	OwnerID          uuid.UUID      `json:"owner_id" gorm:"type:uuid;not null" binding:"required"`
	OrgID            uuid.UUID      `json:"org_id" gorm:"type:uuid;not null"`
	Name             string         `json:"name" gorm:"type:text;not null" binding:"required"`
	Email            *string        `json:"email,omitempty" gorm:"type:text"`
	Status           string         `json:"status" gorm:"type:text;default:'Active';index:idx_clients_status"`
	Tags             pq.StringArray `json:"tags" gorm:"type:text[]"`
	Active           bool           `json:"active" gorm:"default:true"`
	LastLogin        *time.Time     `json:"last_login,omitempty" gorm:"type:timestamptz"`
	MFAEnabled       bool           `json:"mfa_enabled" gorm:"default:false;not null"`
	MFAMethod        pq.StringArray `json:"mfa_method" gorm:"type:text[]"`
	MFADefaultMethod *string        `json:"mfa_default_method,omitempty" gorm:"type:text"`
	MFAEnrolledAt    *time.Time     `json:"mfa_enrolled_at,omitempty" gorm:"type:timestamptz"`
	MFAVerified      bool           `json:"mfa_verified" gorm:"default:false"`
	Roles            []Role         `json:"roles" gorm:"many2many:client_roles;"`
	// OIDC Integration Fields
	HydraClientID string `json:"hydra_client_id,omitempty" gorm:"type:text;uniqueIndex:uni_clients_hydra_client_id,where:hydra_client_id != ''"`
	OIDCEnabled   bool   `json:"oidc_enabled" gorm:"column:oidc_enabled;default:false"`
	// AI Agent Delegation Fields
	ClientType  string     `json:"client_type" gorm:"type:text;default:'application'"`
	AgentType   *string    `json:"agent_type,omitempty" gorm:"type:text"`
	SpiffeID    *string    `json:"spiffe_id,omitempty" gorm:"type:text"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	Description *string    `json:"description,omitempty" gorm:"type:text"`
	// Tenant relationship fields (optional, for future use)
	TenantDB string `json:"tenant_db,omitempty" gorm:"-"` // Not stored, populated from auth-manager
}

// ClientStatus constants
const (
	StatusActive   = "Active"
	StatusInactive = "Development"
	StatusDeleted  = "Deleted"
)

// ClientType constants
const (
	ClientTypeApplication = "application"
	ClientTypeAIAgent     = "ai_agent"
	ClientTypeM2MService  = "m2m_service"
)

// ClientListFilters for server-side filtering
type ClientListFilters struct {
	WorkspaceID uuid.UUID `form:"workspace_id" binding:"required"`
	Status      string    `form:"status"`
	Tags        string    `form:"tags"` // CSV string for tags filtering
	Name        string    `form:"name"`
	Page        int       `form:"page,default=1"`
	Limit       int       `form:"limit,default=10"`
}

// GetTagsArray parses CSV tags into array
func (f *ClientListFilters) GetTagsArray() []string {
	if f.Tags == "" {
		return []string{}
	}
	tags := strings.Split(f.Tags, ",")
	result := []string{}
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
