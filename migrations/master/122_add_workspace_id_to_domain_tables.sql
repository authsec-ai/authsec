-- Migration: 122_add_workspace_id_to_domain_tables.sql
-- Description:
--   v4 §8 — workspace_id rollout across the long-tail of domain tables. The
--   workspaces table has been the isolation boundary since migration 115, and
--   workspaces.id == tenant_id from that backfill. This migration adds
--   workspace_id columns alongside the existing tenant_id columns and
--   populates them so new code paths can read/write workspace_id without
--   needing to also write tenant_id.

ALTER TABLE delegation_tokens ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE delegation_tokens SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_delegation_tokens_workspace_id ON delegation_tokens(workspace_id);

ALTER TABLE delegation_policies ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE delegation_policies SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_delegation_policies_workspace_id ON delegation_policies(workspace_id);

ALTER TABLE oauth_scopes ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE oauth_scopes SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_workspace_id ON oauth_scopes(workspace_id);

ALTER TABLE roles ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE roles SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_roles_workspace_id ON roles(workspace_id);

ALTER TABLE permissions ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE permissions SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_permissions_workspace_id ON permissions(workspace_id);

ALTER TABLE role_bindings ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE role_bindings SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_role_bindings_workspace_id ON role_bindings(workspace_id);

ALTER TABLE resource_server_client_registrations ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE resource_server_client_registrations rscr
SET workspace_id = rs.workspace_id
FROM resource_servers rs
WHERE rscr.resource_server_id = rs.id AND rscr.workspace_id IS NULL AND rs.workspace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rs_client_reg_workspace_id ON resource_server_client_registrations(workspace_id);

ALTER TABLE mcp_tools ADD COLUMN IF NOT EXISTS workspace_id uuid;
UPDATE mcp_tools mt
SET workspace_id = rs.workspace_id
FROM resource_servers rs
WHERE mt.resource_server_id = rs.id AND mt.workspace_id IS NULL AND rs.workspace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_tools_workspace_id ON mcp_tools(workspace_id);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'auth_request_contexts' AND column_name = 'tenant_id'
    ) THEN
        EXECUTE 'ALTER TABLE auth_request_contexts ADD COLUMN IF NOT EXISTS workspace_id uuid';
        EXECUTE 'UPDATE auth_request_contexts SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL';
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_auth_request_contexts_workspace_id ON auth_request_contexts(workspace_id)';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'consent_grants'
    ) THEN
        EXECUTE 'ALTER TABLE consent_grants ADD COLUMN IF NOT EXISTS workspace_id uuid';
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'consent_grants' AND column_name = 'tenant_id'
        ) THEN
            EXECUTE 'UPDATE consent_grants SET workspace_id = tenant_id WHERE workspace_id IS NULL AND tenant_id IS NOT NULL';
        END IF;
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_consent_grants_workspace_id ON consent_grants(workspace_id)';
    END IF;
END $$;
