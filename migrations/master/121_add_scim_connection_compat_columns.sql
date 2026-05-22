-- Migration: 121_add_scim_connection_compat_columns.sql
-- Description:
--   SCIM connections are workspace-scoped in the v4 product model, but the
--   existing SCIM handlers still expect a (client_id, project_id) tuple to
--   pin user/group rows during the tenant_id → workspace_id transition.
--   These two nullable columns let an operator anchor a connection to a
--   specific legacy client_id/project_id so the existing handler logic keeps
--   working when invoked through the new opaque-connection route. The columns
--   are optional — once the handlers are rewritten to be fully
--   workspace-scoped, both can be dropped.

ALTER TABLE scim_connections
    ADD COLUMN IF NOT EXISTS default_client_id uuid,
    ADD COLUMN IF NOT EXISTS default_project_id uuid;

CREATE INDEX IF NOT EXISTS idx_scim_connections_default_client
    ON scim_connections(default_client_id)
    WHERE default_client_id IS NOT NULL;
