package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

// MCPTool is the lean per-Application tool registry on the prod-mcp-v2
// backport. SDKs publish their tool list via PUT /sdk-manifest and read
// the scope mapping via GET /sdk-policy. Lives in tenant DB.
//
// Compared to the dev branch:
//   - No `discovered_at` / `last_scan_generation` (no auto-discovery)
//   - No `suggested_scopes` (the SDK declares required_scopes directly)
//   - No `is_public_acknowledged_by` (admin can flip is_public via API only)
//   - No `annotations` (kept simple)
type MCPTool struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID         string         `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ResourceServerID uuid.UUID      `json:"resource_server_id" gorm:"type:uuid;not null;index"`
	Name             string         `json:"name" gorm:"type:text;not null"`
	Title            string         `json:"title,omitempty"`
	Description      string         `json:"description,omitempty"`
	InputSchema      datatypes.JSON `json:"input_schema,omitempty" gorm:"type:jsonb"`
	IsPublic         bool           `json:"is_public" gorm:"not null;default:false"`
	RequiredScopes   pq.StringArray `json:"required_scopes" gorm:"type:text[];not null;default:'{}'"`
	InventorySource  string         `json:"inventory_source" gorm:"type:text;not null;default:'sdk_manifest'"`
	LastPublishedAt  *time.Time     `json:"last_published_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time      `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (MCPTool) TableName() string { return "mcp_tools" }
