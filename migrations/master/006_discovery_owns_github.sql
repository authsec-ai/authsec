-- 006_discovery_owns_github.sql
--
-- Moves GitHub discovery off the connector broker and onto its own governance
-- record, and cleans up the rows the old coupling left behind.
--
-- WHY. GitHub discovery was built on top of the connector broker because the
-- broker already had working GitHub App plumbing. Reusing the App KEY was
-- right and still stands -- a GitHub App private key grants access across every
-- installation of that App, so a second copy of it would be a second thing to
-- leak. Reusing connector ROWS as the record of the binding was not: the two
-- sides had no foreign key between them, so deleting either one left the other
-- behind. A deleted integration left a live connector; a deleted connector left
-- a source that still reported itself healthy and failed only at scan time.
-- SPEC-connectors states the boundary directly: Agentic IGA must not depend on
-- that framework.
--
-- WHAT. For every repo_scan source still bound to a connector, mint the
-- iga_integrations row that should always have held the binding, repoint the
-- source at it, and drop the connector rows that existed only to serve
-- discovery.
--
-- WHAT IS DELIBERATELY LEFT ALONE:
--   * connector_provider_apps -- this is the App KEY store, shared on purpose,
--     and the new integration references the same App id and the same Vault
--     path. Nothing in Vault is touched.
--   * connectors that no repo_scan source points at -- those are real action
--     broker connectors and none of this concerns them.
--   * discovered_agents -- findings outlive the scanner that found them. Their
--     discovery_source_id is untouched because the sources themselves survive.
--
-- Applied at boot by internal/migration/runner.go and recorded in
-- migration_logs. Data-driven and idempotent rather than keyed to specific ids,
-- so it behaves the same on a fresh install (where it matches nothing), on a
-- developer database, and on production.

-- Everything below runs as ONE unit -- a half-applied cutover is the same orphan
-- by another route -- but there is deliberately no BEGIN/COMMIT here:
-- internal/migration/runner.go already wraps each migration file in its own
-- transaction. Opening a second one ends the runner's transaction early, and
-- the runner's own commit then fails with "unexpected transaction status idle",
-- which fails the migration and stops the backend from starting at all.

-- ---------------------------------------------------------------------------
-- 1. Mint an iga_integrations row for every connector-bound repo_scan source.
-- ---------------------------------------------------------------------------
-- Deterministic ids via uuid_generate_v5 are not available here, so the row is
-- inserted with a fresh id and step 2 reads it back by installation. The
-- WHERE NOT EXISTS makes a re-run a no-op instead of a duplicate.
--
-- verified_at is set: the installation was already proven -- these sources have
-- been scanning it successfully -- and leaving it null would make StartScan
-- refuse every existing source until someone re-ran a flow that no longer
-- exists.
INSERT INTO public.iga_integrations (
    id, workspace_id, provider, provider_host,
    app_registration_id, installation_id, account_native_id,
    capability_profile, requested_permissions, granted_permissions,
    status, secret_ref, verified_at, created_by
)
SELECT
    gen_random_uuid(),
    s.workspace_id,
    'github',
    COALESCE(NULLIF(s.config->>'provider_host', ''), 'github.com'),
    a.github_app_id,
    s.config->>'installation_id',
    -- Prefer the org name the connector recorded; fall back to the owner half
    -- of the first selected repository, which is the same account.
    COALESCE(
        NULLIF(cc.external_org_name, ''),
        split_part(s.config->'repositories'->'include'->>0, '/', 1)
    ),
    jsonb_build_object('migrated_from', 'connector'),
    jsonb_build_object('contents', 'read', 'metadata', 'read'),
    jsonb_build_object('contents', 'read', 'metadata', 'read'),
    'active',
    a.vault_path,
    now(),
    'migration:006'
FROM public.discovery_sources s
JOIN public.connector_provider_apps a
    ON  a.workspace_id = s.workspace_id
    AND a.provider_key = 'github'
LEFT JOIN public.connector_connections cc
    ON  cc.connector_id = NULLIF(s.config->>'connector_id', '')::uuid
WHERE s.kind = 'repo_scan'
  AND COALESCE(s.config->>'installation_id', '') <> ''
  AND COALESCE(s.config->>'integration_id', '') = ''
  AND NOT EXISTS (
      SELECT 1 FROM public.iga_integrations i
      WHERE i.workspace_id       = s.workspace_id
        AND i.app_registration_id = a.github_app_id
        AND i.installation_id     = s.config->>'installation_id'
  );

-- ---------------------------------------------------------------------------
-- 2. Repoint each source at its new integration, and drop connector_id.
-- ---------------------------------------------------------------------------
-- The source config is the scanner's only input, so this is the statement that
-- actually moves the flow across. app_registration_id and account are recorded
-- alongside so the scanner and the console no longer need a second query to
-- name the organisation they are scanning.
UPDATE public.discovery_sources s
SET config = (s.config - 'connector_id')
             || jsonb_build_object(
                    'integration_id',      i.id::text,
                    'app_registration_id', i.app_registration_id,
                    'account',             COALESCE(i.account_native_id, '')
                ),
    updated_at = now()
FROM public.iga_integrations i
WHERE s.kind = 'repo_scan'
  AND i.workspace_id       = s.workspace_id
  AND i.installation_id    = s.config->>'installation_id'
  AND i.verified_at IS NOT NULL
  AND COALESCE(s.config->>'integration_id', '') = '';

-- ---------------------------------------------------------------------------
-- 3. Remove the connector rows that existed only to serve discovery.
-- ---------------------------------------------------------------------------
-- Scoped to connectors a repo_scan source USED to name, and only where that
-- source has now been repointed. A connector nobody referenced this way is an
-- action broker connector and is not touched. Connections go first: they hold
-- the FK.
CREATE TEMP TABLE _discovery_connectors ON COMMIT DROP AS
SELECT DISTINCT c.id
FROM public.connectors c
JOIN public.connector_connections cc ON cc.connector_id = c.id
JOIN public.discovery_sources s
    ON  s.kind = 'repo_scan'
    AND s.workspace_id = c.workspace_id
    AND cc.external_account_id = s.config->>'installation_id'
WHERE c.provider_key = 'github'
  AND COALESCE(s.config->>'integration_id', '') <> '';

DELETE FROM public.connector_connections
WHERE connector_id IN (SELECT id FROM _discovery_connectors);

DELETE FROM public.connectors
WHERE id IN (SELECT id FROM _discovery_connectors);

