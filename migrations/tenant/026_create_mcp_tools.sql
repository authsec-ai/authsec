-- mcp_tools: lean per-Application tool registry on the prod-mcp-v2 backport.
-- Used by:
--   GET  /authsec/applications/:id/sdk-policy   (SDK reads tool->scope mapping)
--   PUT  /authsec/applications/:id/sdk-manifest (SDK publishes its tools)
--
-- Dev branch has a much richer mcp_tools table with auto-discovery, drift
-- events, scope-grant validation, manifest versioning, and a scope_map
-- side table. Backport keeps the bare minimum the SDK needs to enforce
-- scope-based authorization on tool calls:
--   - name: the MCP tool name
--   - is_public: if true, no scope required (anonymous tool)
--   - required_scopes: array of scope strings; SDK matches "any" of these
--
-- Tools are upserted by the SDK at boot when AUTHSEC_PUBLISH_MANIFEST=true.
-- Admin UI can later edit the required_scopes per row. Lives in tenant DB.

CREATE TABLE IF NOT EXISTS mcp_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    title TEXT,
    description TEXT,
    input_schema JSONB,
    is_public BOOLEAN NOT NULL DEFAULT false,
    required_scopes TEXT[] NOT NULL DEFAULT '{}',
    inventory_source TEXT NOT NULL DEFAULT 'sdk_manifest',
    last_published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mcp_tools_inventory_source_check
        CHECK (inventory_source IN ('sdk_manifest', 'manual')),
    CONSTRAINT mcp_tools_resource_server_name_uq
        UNIQUE (resource_server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_tools_tenant            ON mcp_tools(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tools_resource_server   ON mcp_tools(resource_server_id);
