-- Migration: 124_oidc_providers_workspace_scope.sql
-- Description:
--   v4 OIDC IDPs are workspace-owned. Each workspace registers its own OAuth
--   client (its own Google Cloud Console / GitHub OAuth app) with credentials
--   that live in workspace-scoped Vault paths. Drop the global UNIQUE on
--   provider_name and replace with a composite per workspace.
--
--   No backward compat: there are no users, no platform-global rows worth
--   preserving. workspace_id is NOT NULL going forward.

ALTER TABLE oidc_providers
    ADD COLUMN IF NOT EXISTS workspace_id uuid,
    ADD COLUMN IF NOT EXISTS display_name text;

-- Legacy 060_create_oidc_tables.sql seeded platform-global provider rows
-- (google/github/microsoft). v4 has no platform-global provider configs:
-- the canonical source is identity_providers -> oidc_providers, owned by a
-- workspace. Drop orphan global rows before tightening workspace_id.
DELETE FROM oidc_providers op
WHERE op.workspace_id IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM identity_providers ip
      WHERE ip.provider_type = 'oidc'
        AND ip.config_ref = op.id::text
  );

-- Tighten: workspace_id must be set. If any OIDC provider row remains without a
-- workspace, failing here is correct because it cannot be safely scoped.
ALTER TABLE oidc_providers
    ALTER COLUMN workspace_id SET NOT NULL;

ALTER TABLE oidc_providers
    DROP CONSTRAINT IF EXISTS oidc_providers_provider_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS oidc_providers_provider_name_workspace_uq
    ON oidc_providers (workspace_id, provider_name);

CREATE INDEX IF NOT EXISTS idx_oidc_providers_workspace ON oidc_providers(workspace_id);
