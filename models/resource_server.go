package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// ResourceServer represents an MCP server registered with AuthSec.
// This is what developers register — their MCP server (the tool provider).
// It is an OAuth 2.1 Resource Server, NOT an OAuth client.
type ResourceServer struct {
	ID                      uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID                uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index"`
	Name                    string         `json:"name" gorm:"not null"`
	PublicBaseURL           string         `json:"public_base_url" gorm:"not null"`
	ProtectedBasePath       string         `json:"protected_base_path" gorm:"not null;default:'/mcp'"`
	ResourceURI             string         `json:"resource_uri" gorm:"not null;uniqueIndex"`
	ScopesSupported         pq.StringArray `json:"scopes_supported" gorm:"type:text[];default:'{}'"`
	RegistrationModes       pq.StringArray `json:"registration_modes" gorm:"type:text[];default:'{dcr,cimd,prereg}'"`
	IntrospectionSecret     string         `json:"-" gorm:"column:introspection_secret"`               // Legacy plaintext, cleared after backfill
	IntrospectionSecretHash string         `json:"-" gorm:"column:introspection_secret_hash;type:text"` // Bcrypt hash (primary for new rows)
	Active                  bool           `json:"active" gorm:"default:true"`
	CreatedAt               time.Time      `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt               time.Time      `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt               gorm.DeletedAt `json:"-" gorm:"index"`
}

func (ResourceServer) TableName() string {
	return "resource_servers"
}

// AllowsRegistrationMode checks if the RS accepts the given client registration mode.
func (rs *ResourceServer) AllowsRegistrationMode(mode string) bool {
	for _, m := range rs.RegistrationModes {
		if m == mode {
			return true
		}
	}
	return false
}

// SupportsScopes checks if all requested scopes are in the RS's supported set.
func (rs *ResourceServer) SupportsScopes(requested []string) bool {
	supported := make(map[string]bool, len(rs.ScopesSupported))
	for _, s := range rs.ScopesSupported {
		supported[s] = true
	}
	for _, r := range requested {
		if r == "" {
			continue
		}
		if !supported[r] {
			return false
		}
	}
	return true
}
