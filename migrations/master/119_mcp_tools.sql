-- Migration 119: MCP Tool Discovery + Scope Mapping
-- Stores tools discovered from MCP servers via tools/list and maps them to OAuth scopes.

CREATE TABLE IF NOT EXISTS mcp_tools (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    resource_server_id  UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    title               TEXT,
    description         TEXT,
    input_schema        JSONB,
    annotations         JSONB,
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_server_id, name)
);

CREATE INDEX idx_mcp_tools_tenant ON mcp_tools(tenant_id);
CREATE INDEX idx_mcp_tools_rs ON mcp_tools(resource_server_id);

-- Maps tools to the OAuth scopes that govern them.
-- Auto-populated by naming convention matching; admin can override.
CREATE TABLE IF NOT EXISTS mcp_tool_scope_map (
    tool_id       UUID NOT NULL REFERENCES mcp_tools(id) ON DELETE CASCADE,
    scope_id      UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,
    auto_matched  BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (tool_id, scope_id)
);
