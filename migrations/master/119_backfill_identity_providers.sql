-- Migration: 119_backfill_identity_providers.sql
-- Description:
--   Backfill the workspace-owned identity_providers table from the legacy
--   provider-specific tables (saml_providers, sync_configurations). The legacy
--   row IDs are preserved as identity_providers.config_ref so the existing
--   provider-config lookup paths continue to resolve while the UI/API move to
--   the new model.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'saml_providers'
    ) THEN
        RAISE NOTICE 'saml_providers table not present; skipping SAML backfill';
        RETURN;
    END IF;

    INSERT INTO identity_providers (
        id, workspace_id, provider_type, display_name, config_ref, status,
        created_by_user_id, created_at, updated_at
    )
    SELECT
        gen_random_uuid(), sp.tenant_id, 'saml',
        COALESCE(NULLIF(sp.display_name, ''), 'SAML ' || substr(sp.id::text, 1, 8)),
        sp.id::text,
        CASE WHEN COALESCE(sp.is_active, true) THEN 'configured' ELSE 'disabled' END,
        COALESCE(w.owner_user_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(sp.created_at, NOW()), COALESCE(sp.updated_at, NOW())
    FROM saml_providers sp
    LEFT JOIN workspaces w ON w.id = sp.tenant_id
    WHERE NOT EXISTS (
        SELECT 1 FROM identity_providers ip
        WHERE ip.provider_type = 'saml' AND ip.config_ref = sp.id::text
    );
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sync_configurations'
    ) THEN
        RAISE NOTICE 'sync_configurations table not present; skipping AD/Entra backfill';
        RETURN;
    END IF;

    INSERT INTO identity_providers (
        id, workspace_id, provider_type, display_name, config_ref, status,
        created_by_user_id, created_at, updated_at
    )
    SELECT
        gen_random_uuid(), sc.tenant_id,
        CASE sc.sync_type
            WHEN 'active_directory' THEN 'ad'
            WHEN 'entra_id'         THEN 'entra'
            ELSE                         'ad'
        END,
        COALESCE(NULLIF(sc.config_name, ''),
                 CASE sc.sync_type
                     WHEN 'entra_id' THEN 'Entra ID'
                     ELSE 'Active Directory'
                 END || ' ' || substr(sc.id::text, 1, 8)),
        sc.id::text,
        CASE WHEN COALESCE(sc.is_active, true) THEN 'configured' ELSE 'disabled' END,
        COALESCE(w.owner_user_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(sc.created_at, NOW()), COALESCE(sc.updated_at, NOW())
    FROM sync_configurations sc
    LEFT JOIN workspaces w ON w.id = sc.tenant_id
    WHERE sc.sync_type IN ('active_directory', 'entra_id')
      AND NOT EXISTS (
          SELECT 1 FROM identity_providers ip
          WHERE ip.provider_type IN ('ad', 'entra') AND ip.config_ref = sc.id::text
      );
END $$;
