package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Inventory source constants for MCPTool.InventorySource.
const (
	InventorySourceMCPScan     = "mcp_scan"
	InventorySourceSDKManifest = "sdk_manifest"
	InventorySourceManual      = "manual"
)

// Scope map source constants for MCPToolScopeMap.Source.
const (
	ScopeMapSourceSDKSuggested  = "sdk_suggested"
	ScopeMapSourceAdminOverride = "admin_override"
)

// MCPTool represents a tool discovered from an MCP server via tools/list.
type MCPTool struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID           uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	ResourceServerID   uuid.UUID       `json:"resource_server_id" gorm:"type:uuid;not null;uniqueIndex:idx_mcp_tools_rs_name"`
	Name               string          `json:"name" gorm:"type:text;not null;uniqueIndex:idx_mcp_tools_rs_name"`
	Title              string          `json:"title" gorm:"type:text"`
	Description        string          `json:"description" gorm:"type:text"`
	InputSchema        json.RawMessage `json:"input_schema" gorm:"type:jsonb"`
	Annotations        json.RawMessage `json:"annotations" gorm:"type:jsonb"`
	DiscoveredAt       time.Time       `json:"discovered_at" gorm:"not null;default:now()"`
	LastScanGeneration int             `json:"last_scan_generation" gorm:"not null;default:0"`

	// Inventory source: 'mcp_scan' | 'sdk_manifest' | 'manual'
	InventorySource string `json:"inventory_source" gorm:"type:text;not null;default:'mcp_scan'"`

	// SuggestedScopes: advisory from SDK manifest — never runtime-effective alone.
	SuggestedScopes pq.StringArray `json:"suggested_scopes" gorm:"type:text[];not null;default:'{}'"`

	// IsPublic: callable by any token whose aud matches this RS while state=ready.
	// Empty mapping + IsPublic=false → unmapped (blocks activation).
	IsPublic bool `json:"is_public" gorm:"not null;default:false"`

	// IsPublicAcknowledgedBy: UUID of admin who set is_public=true (audit).
	IsPublicAcknowledgedBy *uuid.UUID `json:"is_public_acknowledged_by,omitempty" gorm:"type:uuid"`

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
	// Source: 'sdk_suggested' (advisory only) | 'admin_override' (runtime-effective).
	Source string `json:"source" gorm:"type:text;not null;default:'admin_override'"`
}

func (MCPToolScopeMap) TableName() string {
	return "mcp_tool_scope_map"
}

// MCPToolResponse is the API response for a discovered tool.
type MCPToolResponse struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	InputSchema     json.RawMessage `json:"input_schema,omitempty"`
	Annotations     json.RawMessage `json:"annotations,omitempty"`
	Scopes          []ScopeMapEntry `json:"scopes"`
	InventorySource string          `json:"inventory_source"`
	IsPublic        bool            `json:"is_public"`
	SuggestedScopes []string        `json:"suggested_scopes,omitempty"`
}

// ScopeMapEntry represents a scope mapped to a tool in the scope matrix.
type ScopeMapEntry struct {
	ScopeID     string `json:"scope_id"`
	ScopeString string `json:"scope_string"`
	DisplayName string `json:"display_name"`
	RiskLevel   string `json:"risk_level"`
	AutoMatched bool   `json:"auto_matched"`
	Source      string `json:"source"`
}
