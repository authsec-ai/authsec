package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DelegationPolicy defines which roles can delegate trust to which AI agent types,
// with optional permission scoping and TTL caps.
type DelegationPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;uniqueIndex:idx_deleg_tenant_role_agent"`
	// WorkspaceID mirrors WorkspaceID during the workspace transition. Backfilled
	// by migration 122.
	RoleName           string          `json:"role_name" gorm:"type:text;not null;uniqueIndex:idx_deleg_tenant_role_agent"`
	AgentType          string          `json:"agent_type" gorm:"type:text;not null;uniqueIndex:idx_deleg_tenant_role_agent"`
	AllowedPermissions json.RawMessage `json:"allowed_permissions" gorm:"type:jsonb;default:'[]'"`
	MaxTTLSeconds      int             `json:"max_ttl_seconds" gorm:"default:3600"`
	Enabled            bool            `json:"enabled" gorm:"default:true"`
	// ClientID references the ai_agent resource_servers.id this policy is scoped to.
	// (Phase B: the legacy `clients` table was dropped; an agent is a resource_servers
	// row with application_type='ai_agent'. The column name stays client_id.)
	ClientID  *uuid.UUID `json:"client_id,omitempty" gorm:"type:uuid"`
	CreatedBy *uuid.UUID `json:"created_by" gorm:"type:uuid"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (DelegationPolicy) TableName() string {
	return "delegation_policies"
}

func (dp *DelegationPolicy) BeforeCreate(tx *gorm.DB) error {
	if dp.ID == uuid.Nil {
		dp.ID = uuid.New()
	}
	return nil
}

// GetAllowedPermissions parses the JSONB allowed_permissions field into a string slice.
func (dp *DelegationPolicy) GetAllowedPermissions() []string {
	if len(dp.AllowedPermissions) == 0 {
		return nil
	}
	var perms []string
	if err := json.Unmarshal(dp.AllowedPermissions, &perms); err != nil {
		return nil
	}
	return perms
}

// SetAllowedPermissions marshals a string slice into the JSONB field.
func (dp *DelegationPolicy) SetAllowedPermissions(perms []string) {
	if perms == nil {
		perms = []string{}
	}
	data, _ := json.Marshal(perms)
	dp.AllowedPermissions = data
}
