-- Migration: 127_prune_legacy_oidc_provider_rows.sql
-- Description:
--   Repairs databases where migration 124 previously preserved legacy seeded
--   oidc_providers rows by assigning them to the first workspace. Those rows do
--   not have identity_providers wrappers and block the new canonical
--   POST /authsec/identity-providers flow on (workspace_id, provider_name).

DELETE FROM oidc_providers op
WHERE NOT EXISTS (
    SELECT 1
    FROM identity_providers ip
    WHERE ip.provider_type = 'oidc'
      AND ip.config_ref = op.id::text
);
