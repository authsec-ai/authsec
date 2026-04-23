package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MCPTool represents a tool discovered from an MCP server via tools/list.
type MCPTool struct {
	ID               uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID         uuid.UUID       `json:"tenant_id" gorm:"type:uuid;not null"`
	ResourceServerID uuid.UUID       `json:"resource_server_id" gorm:"type:uuid;not null;uniqueIndex:idx_mcp_tools_rs_name"`
	Name             string          `json:"name" gorm:"type:text;not null;uniqueIndex:idx_mcp_tools_rs_name"`
	Title            string          `json:"title" gorm:"type:text"`
	Description      string          `json:"description" gorm:"type:text"`
	InputSchema      json.RawMessage `json:"input_schema" gorm:"type:jsonb"`
	Annotations      json.RawMessage `json:"annotations" gorm:"type:jsonb"`
	DiscoveredAt     time.Time       `json:"discovered_at" gorm:"not null;default:now()"`
	LastScanGeneration int           `json:"last_scan_generation" gorm:"not null;default:0"`

	// Relations
	Scopes []OAuthScope `json:"scopes,omitempty" gorm:"many2many:mcp_tool_scope_map;joinForeignKey:ToolID;joinReferences:ScopeID"`
}

func (MCPTool) TableName() string {
	return "mcp_tools"
}

// MCPToolScopeMap is the join table between tools and scopes.
type MCPToolScopeMap struct {
	ToolID      uuid.UUID `json:"tool_id" gorm:"type:uuid;primaryKey"`
	ScopeID     uuid.UUID `json:"scope_id" gorm:"type:uuid;primaryKey"`
	AutoMatched bool      `json:"auto_matched" gorm:"not null;default:true"`
}

func (MCPToolScopeMap) TableName() string {
	return "mcp_tool_scope_map"
}

// MCPToolResponse is the API response for a discovered tool.
type MCPToolResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	InputSchema json.RawMessage   `json:"input_schema,omitempty"`
	Annotations json.RawMessage   `json:"annotations,omitempty"`
	Scopes      []ScopeMapEntry   `json:"scopes"`
}

// ScopeMapEntry represents a scope mapped to a tool in the scope matrix.
type ScopeMapEntry struct {
	ScopeID     string `json:"scope_id"`
	ScopeString string `json:"scope_string"`
	DisplayName string `json:"display_name"`
	RiskLevel   string `json:"risk_level"`
	AutoMatched bool   `json:"auto_matched"`
}
