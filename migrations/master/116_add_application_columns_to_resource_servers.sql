-- Migration: 116_add_application_columns_to_resource_servers.sql
-- Description: Start the Application facade while keeping resource_servers as the physical table.

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS workspace_id uuid,
    ADD COLUMN IF NOT EXISTS application_type text NOT NULL DEFAULT 'mcp_server',
    ADD COLUMN IF NOT EXISTS legacy_client_id uuid;

ALTER TABLE resource_servers
    DROP CONSTRAINT IF EXISTS resource_servers_application_type_chk;

ALTER TABLE resource_servers
    ADD CONSTRAINT resource_servers_application_type_chk
    CHECK (application_type IN ('mcp_server', 'ai_agent', 'clawbot', 'api_service'));

CREATE INDEX IF NOT EXISTS idx_resource_servers_workspace_id ON resource_servers(workspace_id);
CREATE INDEX IF NOT EXISTS idx_resource_servers_application_type ON resource_servers(application_type);
CREATE INDEX IF NOT EXISTS idx_resource_servers_legacy_client_id ON resource_servers(legacy_client_id);

UPDATE resource_servers
SET workspace_id = tenant_id
WHERE workspace_id IS NULL
  AND tenant_id IS NOT NULL;
