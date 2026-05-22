-- Migration: 118_backfill_clients_to_applications.sql
-- Description:
--   Backfill legacy `clients` rows into `resource_servers` as Applications,
--   recording the originating client.id in resource_servers.legacy_client_id.
--   Add `application_id` columns to delegation_tokens / delegation_policies and
--   resolve them through legacy_client_id so SPIFFE-bound flows can stop
--   referencing clients.id at the row level.
--
--   This migration is forward-only and idempotent — re-running it should not
--   produce duplicate applications. Mapping is keyed by clients.id == legacy_client_id.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Backfill clients → resource_servers (Applications)
-- ─────────────────────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'clients'
    ) THEN
        RAISE NOTICE 'clients table not present; skipping legacy backfill';
        RETURN;
    END IF;

    INSERT INTO resource_servers (
        id,
        tenant_id,
        workspace_id,
        application_type,
        legacy_client_id,
        name,
        public_base_url,
        protected_base_path,
        resource_uri,
        scopes_supported,
        registration_modes,
        introspection_secret,
        introspection_secret_hash,
        active,
        state,
        status,
        scan_generation,
        last_successful_generation,
        scan_in_progress,
        created_at,
        updated_at
    )
    SELECT
        gen_random_uuid(),
        c.tenant_id,
        c.tenant_id,
        CASE
            WHEN c.agent_type = 'clawbot'                THEN 'clawbot'
            WHEN c.client_type = 'ai_agent'              THEN 'ai_agent'
            WHEN c.client_type = 'application'           THEN 'api_service'
            ELSE 'api_service'
        END,
        c.id,
        COALESCE(NULLIF(c.name, ''), 'Application ' || substr(c.id::text, 1, 8)),
        'https://legacy-app-' || substr(c.id::text, 1, 8) || '.invalid',
        '/legacy',
        'https://legacy-app-' || substr(c.id::text, 1, 8) || '.invalid/legacy',
        ARRAY[]::text[],
        ARRAY['prereg']::text[],
        '',
        '',
        COALESCE(c.active, true),
        'needs_setup',
        'needs_setup',
        0,
        0,
        false,
        COALESCE(c.created_at, NOW()),
        COALESCE(c.updated_at, NOW())
    FROM clients c
    WHERE c.tenant_id IS NOT NULL
      AND (c.deleted_at IS NULL)
      AND COALESCE(c.client_type, 'application') IN ('application', 'ai_agent')
      AND NOT EXISTS (
          SELECT 1 FROM resource_servers rs
          WHERE rs.legacy_client_id = c.id
      );

    RAISE NOTICE 'Backfilled % legacy clients into resource_servers',
        (SELECT count(*) FROM resource_servers WHERE legacy_client_id IS NOT NULL);
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Add application_id to delegation_tokens + delegation_policies
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE delegation_tokens
    ADD COLUMN IF NOT EXISTS application_id uuid;

ALTER TABLE delegation_policies
    ADD COLUMN IF NOT EXISTS application_id uuid;

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_application_id
    ON delegation_tokens(application_id);
CREATE INDEX IF NOT EXISTS idx_delegation_policies_application_id
    ON delegation_policies(application_id);

UPDATE delegation_tokens dt
SET application_id = rs.id
FROM resource_servers rs
WHERE rs.legacy_client_id = dt.client_id
  AND dt.application_id IS NULL;

UPDATE delegation_policies dp
SET application_id = rs.id
FROM resource_servers rs
WHERE rs.legacy_client_id = dp.client_id
  AND dp.application_id IS NULL;
