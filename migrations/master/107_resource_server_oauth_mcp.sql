-- 107_resource_server_oauth_mcp.sql
--
-- Consolidated final-schema migration for the OAuth/MCP resource-server
-- subsystem. Replaces 23 incremental migrations (originally numbered
-- 105_create_resource_servers.sql through 127_clean_polluted_user_names.sql
-- on standard-oauth-flow) that were collapsed during the merge with
-- non-multi-tenant.
--
-- On a fresh DB this file produces the same final schema as applying those
-- 23 in order. Backfill / one-shot data migrations (126 viewer-role
-- backfill, 127 polluted-name cleanup) are excluded — there is no existing
-- data to migrate.
--
-- Legacy-table DROP from old 121 is intentionally NOT included: the
-- merged rbac_repository.go still queries scope_permissions (line 131),
-- so dropping it breaks runtime. If/when that query is removed, drop the
-- legacy tables in a follow-up migration.
--
-- Number 107 follows non-multi-tenant's 105_create_agent_action_tables and
-- 106_device_codes_nullable_tenant.


-- ─── from 105_create_resource_servers.sql ───────────────────────────────────────

-- Migration 105: Create resource_servers table
-- Resource servers represent MCP servers registered with AuthSec (the tool providers).
-- They are OAuth 2.1 Resource Servers, NOT OAuth clients.

CREATE TABLE IF NOT EXISTS resource_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    public_base_url TEXT NOT NULL,
    protected_base_path TEXT NOT NULL DEFAULT '/mcp',
    resource_uri TEXT NOT NULL UNIQUE,
    scopes_supported TEXT[] DEFAULT '{}',
    registration_modes TEXT[] DEFAULT '{dcr,cimd,prereg}',
    introspection_secret TEXT NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_resource_servers_tenant_id ON resource_servers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_servers_resource_uri ON resource_servers(resource_uri);

-- ─── from 106_create_mcp_oauth_clients.sql ───────────────────────────────────────

-- Migration 106: Create mcp_oauth_clients table
-- OAuth clients in the MCP plane (Codex, Claude, Cursor, Inspector).
-- Global (no tenant_id) — clients access RS via resource_server_client_registrations join table.

CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(512) UNIQUE NOT NULL,
    hydra_client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255),
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{authorization_code}',
    response_types TEXT[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'none',
    scope TEXT,
    registration_type VARCHAR(20) NOT NULL DEFAULT 'dcr',
    cimd_url TEXT,
    cimd_cached_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_client_id ON mcp_oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_hydra_client_id ON mcp_oauth_clients(hydra_client_id);

-- ─── from 107_create_resource_server_client_registrations.sql ───────────────────────────────────────

-- Migration 107: Create resource_server_client_registrations join table
-- Controls which OAuth clients are registered/allowed for which resource servers.
-- All access paths must check this table before allowing client-RS interaction.

CREATE TABLE IF NOT EXISTS resource_server_client_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id),
    oauth_client_id UUID NOT NULL REFERENCES mcp_oauth_clients(id),
    status VARCHAR(20) NOT NULL DEFAULT 'approved',
    registration_type VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(resource_server_id, oauth_client_id)
);

CREATE INDEX IF NOT EXISTS idx_rscr_rs_id ON resource_server_client_registrations(resource_server_id);
CREATE INDEX IF NOT EXISTS idx_rscr_client_id ON resource_server_client_registrations(oauth_client_id);

-- ─── from 108_create_auth_request_contexts.sql ───────────────────────────────────────

-- Migration 108: Create auth_request_contexts bridge table
-- Short-lived context stored between /oauth/authorize and hmgr login/consent.
-- Keyed by OAuth state parameter. Bound to login_challenge in hmgr.
-- TTL ~10 minutes, one-time consumption, periodic cleanup required.

CREATE TABLE IF NOT EXISTS auth_request_contexts (
    state VARCHAR(255) PRIMARY KEY,
    hydra_client_id VARCHAR(255) NOT NULL,
    resource_server_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    resource_uri TEXT NOT NULL,
    redirect_uri TEXT,
    requested_scopes TEXT,
    login_challenge VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arc_hydra_client_id ON auth_request_contexts(hydra_client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_arc_login_challenge ON auth_request_contexts(login_challenge) WHERE login_challenge IS NOT NULL;

-- ─── from 109_add_context_id_and_consent_completed.sql ───────────────────────────────────────

-- Migration 109: Add context_id (server-generated binding key) and consent_completed to auth_request_contexts
-- context_id replaces client-supplied state as the deterministic binding mechanism.
-- consent_completed separates consent from consumption (Token handler is the only consumer).

ALTER TABLE auth_request_contexts ADD COLUMN IF NOT EXISTS context_id VARCHAR(255);
ALTER TABLE auth_request_contexts ADD COLUMN IF NOT EXISTS consent_completed BOOLEAN DEFAULT false;

-- context_id must be unique for active rows
CREATE UNIQUE INDEX IF NOT EXISTS idx_arc_context_id ON auth_request_contexts(context_id) WHERE context_id IS NOT NULL;

-- ─── from 110_add_cimd_pending_redirects.sql ───────────────────────────────────────

-- Migration 110: Add pending redirect URI fields for CIMD redirect review gate.
-- When a CIMD document changes redirect_uris, they are staged here for admin approval
-- instead of being auto-applied to the Hydra client.

ALTER TABLE mcp_oauth_clients ADD COLUMN IF NOT EXISTS pending_redirect_uris TEXT[] DEFAULT '{}';
ALTER TABLE mcp_oauth_clients ADD COLUMN IF NOT EXISTS redirect_review_pending BOOLEAN DEFAULT false;

-- ─── from 111_hash_introspection_secrets.sql ───────────────────────────────────────

-- Migration 111: Add hashed introspection secret storage for resource servers.
-- New rows store only introspection_secret_hash. Legacy plaintext secrets remain readable
-- until opportunistically backfilled on first successful validation.

ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS introspection_secret_hash TEXT;
ALTER TABLE resource_servers ALTER COLUMN introspection_secret DROP NOT NULL;
ALTER TABLE resource_servers ALTER COLUMN introspection_secret SET DEFAULT '';

-- ─── from 112_expand_auth_request_context_login_challenge.sql ───────────────────────────────────────

-- Migration 112: Hydra login_challenge values can exceed varchar(255)
-- Expand the bridge column to TEXT so local and real login flows bind cleanly.

ALTER TABLE auth_request_contexts
    ALTER COLUMN login_challenge TYPE TEXT;

-- ─── from 113_add_arc_expires_at_index.sql ───────────────────────────────────────

-- Migration 113: Add index on expires_at for efficient cleanup queries.
-- CleanupExpired() runs every 10 minutes: DELETE WHERE expires_at < NOW().

CREATE INDEX IF NOT EXISTS idx_arc_expires_at ON auth_request_contexts(expires_at);

-- ─── from 114_create_pkce_verifiers.sql ───────────────────────────────────────

-- Migration 114: Create pkce_verifiers table for database-backed PKCE storage.
-- Replaces process-local sync.Map. Survives restarts and works in multi-instance deployments.

CREATE TABLE IF NOT EXISTS pkce_verifiers (
    key VARCHAR(512) PRIMARY KEY,
    verifier TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pkce_verifiers_expires_at ON pkce_verifiers(expires_at);

-- ─── from 115_add_hydra_request_uri.sql ───────────────────────────────────────

ALTER TABLE auth_request_contexts
  ADD COLUMN IF NOT EXISTS hydra_request_uri VARCHAR(512);

CREATE UNIQUE INDEX IF NOT EXISTS idx_arc_hydra_request_uri
  ON auth_request_contexts(hydra_request_uri)
  WHERE hydra_request_uri IS NOT NULL AND hydra_request_uri != '';

-- ─── from 116_add_oidc_fields_to_auth_request_context.sql ───────────────────────────────────────

-- Add OIDC parameters to auth_request_contexts for OpenID Connect Core 1.0 support.
-- nonce: binds id_token to authorization request (OIDC Core §3.1.2.1)
-- prompt: controls login/consent UI behavior (OIDC Core §3.1.2.1)
-- max_age: maximum authentication age in seconds (OIDC Core §3.1.2.1)
-- auth_time: timestamp of actual authentication event (OIDC Core §2)
ALTER TABLE auth_request_contexts
  ADD COLUMN IF NOT EXISTS nonce TEXT,
  ADD COLUMN IF NOT EXISTS prompt VARCHAR(64),
  ADD COLUMN IF NOT EXISTS max_age INTEGER,
  ADD COLUMN IF NOT EXISTS auth_time TIMESTAMP;

-- ─── from 117_add_oidc_fields_to_mcp_oauth_clients.sql ───────────────────────────────────────

-- Add OIDC provider fields to mcp_oauth_clients.
-- post_logout_redirect_uris: RP-initiated logout (OIDC RP-Initiated Logout 1.0)
-- supports_refresh_token: gate refresh_token grant per-client (OAuth 2.1 / MCP draft)
ALTER TABLE mcp_oauth_clients
  ADD COLUMN IF NOT EXISTS post_logout_redirect_uris TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS supports_refresh_token BOOLEAN DEFAULT false;

-- ─── from 118_oauth_scope_registry.sql ───────────────────────────────────────

-- Migration 118: OAuth Scope Registry
-- Creates a first-class scope catalog with metadata, hierarchy, and permission mapping.
-- Replaces the flat pq.StringArray on resource_servers.scopes_supported with a proper table.

CREATE TABLE IF NOT EXISTS oauth_scopes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    resource_server_id  UUID REFERENCES resource_servers(id) ON DELETE CASCADE,
    scope_string        TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    description         TEXT,
    icon                TEXT,
    risk_level          TEXT NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    parent_scope_id     UUID REFERENCES oauth_scopes(id) ON DELETE SET NULL,
    is_auto_discovered  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, resource_server_id, scope_string)
);

CREATE INDEX idx_oauth_scopes_tenant ON oauth_scopes(tenant_id);
CREATE INDEX idx_oauth_scopes_rs ON oauth_scopes(resource_server_id);
CREATE INDEX idx_oauth_scopes_parent ON oauth_scopes(parent_scope_id);
CREATE UNIQUE INDEX idx_oauth_scopes_tenant_global_scope
    ON oauth_scopes(tenant_id, scope_string)
    WHERE resource_server_id IS NULL;

-- Scope → Permission mapping: maps an OAuth scope to internal RBAC permissions.
-- When a user has roles granting permissions, we reverse-map to find which scopes they're entitled to.
CREATE TABLE IF NOT EXISTS oauth_scope_permissions (
    scope_id      UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (scope_id, permission_id)
);

CREATE INDEX idx_oauth_scope_perms_permission ON oauth_scope_permissions(permission_id);

-- Best-effort backfill from the legacy API scope model.
-- Global API scopes become tenant-scoped oauth_scopes with no bound resource server.
INSERT INTO oauth_scopes (
    tenant_id,
    resource_server_id,
    scope_string,
    display_name,
    description,
    risk_level,
    is_auto_discovered,
    created_at,
    updated_at
)
SELECT
    a.tenant_id,
    NULL,
    a.name,
    a.name,
    a.description,
    CASE
        WHEN LOWER(a.name) LIKE '%admin%' OR LOWER(a.name) LIKE '%delete%' THEN 'critical'
        WHEN LOWER(a.name) LIKE '%write%' OR LOWER(a.name) LIKE '%create%' OR LOWER(a.name) LIKE '%update%' THEN 'medium'
        WHEN RIGHT(a.name, 2) = ':*' THEN 'high'
        ELSE 'low'
    END,
    FALSE,
    COALESCE(a.created_at, NOW()),
    NOW()
FROM api_scopes a
WHERE a.tenant_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO oauth_scope_permissions (scope_id, permission_id)
SELECT
    os.id,
    asp.permission_id
FROM api_scope_permissions asp
JOIN api_scopes a ON a.id = asp.scope_id
JOIN oauth_scopes os
    ON os.tenant_id = a.tenant_id
   AND os.resource_server_id IS NULL
   AND os.scope_string = a.name
WHERE a.tenant_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- Best-effort backfill from scope_resource_mappings into RS-scoped oauth_scopes.
-- This preserves legacy tenant/resource scope contracts where the resource mapping
-- can be matched to a resource server name.
INSERT INTO oauth_scopes (
    tenant_id,
    resource_server_id,
    scope_string,
    display_name,
    description,
    risk_level,
    is_auto_discovered,
    created_at,
    updated_at
)
SELECT
    srm.tenant_id,
    rs.id,
    srm.scope_name,
    srm.scope_name,
    a.description,
    CASE
        WHEN LOWER(srm.scope_name) LIKE '%admin%' OR LOWER(srm.scope_name) LIKE '%delete%' THEN 'critical'
        WHEN LOWER(srm.scope_name) LIKE '%write%' OR LOWER(srm.scope_name) LIKE '%create%' OR LOWER(srm.scope_name) LIKE '%update%' THEN 'medium'
        WHEN RIGHT(srm.scope_name, 2) = ':*' THEN 'high'
        ELSE 'low'
    END,
    FALSE,
    COALESCE(srm.created_at, NOW()),
    NOW()
FROM scope_resource_mappings srm
JOIN resource_servers rs
    ON rs.tenant_id = srm.tenant_id
   AND LOWER(rs.name) = LOWER(srm.resource_name)
LEFT JOIN api_scopes a
    ON a.tenant_id = srm.tenant_id
   AND a.name = srm.scope_name
ON CONFLICT DO NOTHING;

INSERT INTO oauth_scope_permissions (scope_id, permission_id)
SELECT
    os.id,
    asp.permission_id
FROM scope_resource_mappings srm
JOIN resource_servers rs
    ON rs.tenant_id = srm.tenant_id
   AND LOWER(rs.name) = LOWER(srm.resource_name)
JOIN oauth_scopes os
    ON os.tenant_id = srm.tenant_id
   AND os.resource_server_id = rs.id
   AND os.scope_string = srm.scope_name
JOIN api_scopes a
    ON a.tenant_id = srm.tenant_id
   AND a.name = srm.scope_name
JOIN api_scope_permissions asp
    ON asp.scope_id = a.id
ON CONFLICT DO NOTHING;

-- ─── from 119_mcp_tools.sql ───────────────────────────────────────

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

-- ─── from 120_oauth_consent_grants.sql ───────────────────────────────────────

-- 120: OAuth Consent Grants - remembered consent per (user x client x RS)
-- Enables consent memory with TTL so users aren't prompted on every auth flow.

CREATE TABLE IF NOT EXISTS oauth_consent_grants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    user_id             UUID NOT NULL,
    client_id           UUID NOT NULL REFERENCES mcp_oauth_clients(id) ON DELETE CASCADE,
    resource_server_id  UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    granted_scopes      TEXT[] NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, client_id, resource_server_id)
);

CREATE INDEX IF NOT EXISTS idx_consent_grants_user_client
    ON oauth_consent_grants (user_id, client_id, resource_server_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_consent_grants_tenant
    ON oauth_consent_grants (tenant_id)
    WHERE revoked_at IS NULL;

-- ─── from 122_rs_lifecycle_and_tool_generation.sql ───────────────────────────────────────

-- Migration 122: Resource Server Lifecycle Tracking + Tool Generation Tracking
-- Adds scan lifecycle state to resource_servers and last_scan_generation to mcp_tools.
-- All DDL is idempotent (IF NOT EXISTS / conditional UPDATEs).

-- ── resource_servers: lifecycle columns ─────────────────────────────────────

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending_scan'
        CHECK (status IN ('pending_scan', 'ready', 'degraded'));

ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS scan_generation              INTEGER NOT NULL DEFAULT 0;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_successful_generation   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS scan_in_progress             BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS last_scan_status TEXT
        CHECK (last_scan_status IS NULL OR last_scan_status IN ('success', 'failure', 'partial'));

ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_scan_error          TEXT;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_scan_started_at     TIMESTAMPTZ;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_scan_completed_at   TIMESTAMPTZ;

-- Transitional approximation: active RSs with existing tools are promoted to
-- ready/gen=1. This is operationally convenient but not semantically guaranteed —
-- pre-migration data may be stale or partial. Inactive (soft-deleted) RSs are
-- intentionally left at pending_scan/gen=0.
UPDATE resource_servers rs
SET    status                    = 'ready',
       scan_generation           = 1,
       last_successful_generation = 1,
       last_scan_status          = 'success'
WHERE  active = true
  AND  deleted_at IS NULL
  AND  EXISTS (SELECT 1 FROM mcp_tools mt WHERE mt.resource_server_id = rs.id);

-- ── mcp_tools: generation tracking ──────────────────────────────────────────

ALTER TABLE mcp_tools ADD COLUMN IF NOT EXISTS last_scan_generation INTEGER NOT NULL DEFAULT 0;

-- Back-fill existing tools to match their RS's last_successful_generation.
UPDATE mcp_tools mt
SET    last_scan_generation = 1
WHERE  EXISTS (
    SELECT 1 FROM resource_servers rs
    WHERE  rs.id = mt.resource_server_id
      AND  rs.last_successful_generation = 1
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_mcp_tools_rs_generation
    ON mcp_tools(resource_server_id, last_scan_generation);

CREATE INDEX IF NOT EXISTS idx_rs_status
    ON resource_servers(status)
    WHERE active = true AND deleted_at IS NULL;

-- ─── from 123_rename_seeded_roles_to_uuid.sql ───────────────────────────────────────

-- Migration 123: Rename auto-generated role names from rs:<name>:suffix to rs-<id>:suffix
-- for RSes whose name has NOT changed since seeding.
--
-- This is a best-effort transition. Roles for RSes that were renamed before this
-- migration runs will not be matched and must be cleaned up manually.
-- See: docs/DEV_MCP_INTEGRATION_RUNBOOK.md for manual cleanup steps.

UPDATE roles r
SET name = 'rs-' || rs.id::text || ':' || split_part(r.name, ':', 3)
FROM resource_servers rs
WHERE r.tenant_id = rs.tenant_id
  AND r.name ~ ('^rs:' || rs.name || ':(admin|readonly)$')
  AND r.description LIKE '%auto-generated%';

-- ─── from 124_resource_server_onboarding_access_policy.sql ───────────────────────────────────────

-- Migration 124: Resource server onboarding access policy + validation metadata

CREATE TABLE IF NOT EXISTS resource_server_access_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    resource_server_id uuid NOT NULL UNIQUE REFERENCES resource_servers(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    default_role_id uuid REFERENCES roles(id) ON DELETE SET NULL,
    assignment_trigger text NOT NULL DEFAULT 'first_successful_login',
    assignment_source text NOT NULL DEFAULT 'default_policy',
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rs_access_policies_tenant_id
    ON resource_server_access_policies (tenant_id);

ALTER TABLE role_bindings
    ADD COLUMN IF NOT EXISTS assignment_source text NOT NULL DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS assignment_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS last_validated_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_validation_status text,
    ADD COLUMN IF NOT EXISTS last_validation_error text;

-- ─── from 125_sdk_manifest_and_inventory_source.sql ───────────────────────────────────────

-- Migration 125: SDK manifest, inventory source, RS state gate, drift events, manifest attempts
-- Additive only. Backfills existing rows per §6 of the plan.

-- ── 1. resource_servers — new columns ───────────────────────────────────────────────────────────
ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS state               TEXT NOT NULL DEFAULT 'pending_scan'
                                                    CHECK (state IN ('pending_scan','needs_setup','ready','scan_failed')),
    ADD COLUMN IF NOT EXISTS setup_completed_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS setup_completed_by  UUID REFERENCES users(id) ON DELETE SET NULL;

-- Index for fast "all needs_setup" queries (Tenant Health strip)
CREATE INDEX IF NOT EXISTS idx_resource_servers_state ON resource_servers(state);

-- ── 2. mcp_tools — new columns ──────────────────────────────────────────────────────────────────
ALTER TABLE mcp_tools
    ADD COLUMN IF NOT EXISTS inventory_source          TEXT NOT NULL DEFAULT 'mcp_scan'
                                                            CHECK (inventory_source IN ('mcp_scan','sdk_manifest','manual')),
    ADD COLUMN IF NOT EXISTS suggested_scopes          TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS is_public                 BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_public_acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- ── 3. mcp_tool_scope_map — add source column ───────────────────────────────────────────────────
ALTER TABLE mcp_tool_scope_map
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'admin_override'
                                    CHECK (source IN ('sdk_suggested','admin_override'));

-- Backfill: existing rows that were auto-matched stay sdk_suggested advisory;
-- rows explicitly not auto-matched are admin overrides.
UPDATE mcp_tool_scope_map
   SET source = CASE
                    WHEN auto_matched = true  THEN 'sdk_suggested'
                    ELSE                           'admin_override'
                END
 WHERE source = 'admin_override'; -- all rows have default; update all for correctness

-- ── 4. resource_server_drift_events (new table) ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resource_server_drift_events (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rs_id        UUID        NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    event_type   TEXT        NOT NULL CHECK (event_type IN (
                                   'scope_deleted',
                                   'tool_unmapped',
                                   'default_role_disabled',
                                   'secret_rotated'
                               )),
    event_payload JSONB,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurred_by  UUID        REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_rs_drift_events_rs_occurred
    ON resource_server_drift_events(rs_id, occurred_at DESC);

-- ── 5. resource_server_drift_event_dismissals (new table) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resource_server_drift_event_dismissals (
    event_id      UUID        NOT NULL REFERENCES resource_server_drift_events(id) ON DELETE CASCADE,
    admin_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dismissed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, admin_user_id)
);

-- ── 6. resource_server_manifest_attempts (new table) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resource_server_manifest_attempts (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rs_id            UUID        NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    attempted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status           TEXT        NOT NULL CHECK (status IN (
                                       'success',
                                       'auth_failed',
                                       'invalid_payload',
                                       'empty_tool_list',
                                       'server_error'
                                   )),
    reason           TEXT,
    tool_count       INT,
    manifest_version TEXT,
    sdk_build_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_rs_manifest_attempts_rs_at
    ON resource_server_manifest_attempts(rs_id, attempted_at DESC);

-- ── 7. Backfill resource_servers.state ───────────────────────────────────────────────────────────
--
-- RS with a committed scan + scopes + at least one scope → ready (if they had working RS before).
-- RS with a committed scan but missing the above → needs_setup.
-- RS with status='failed' or no successful scan → scan_failed / pending_scan.

UPDATE resource_servers rs
   SET state = 'ready',
       setup_completed_at = NOW()
 WHERE last_successful_generation > 0
   AND array_length(scopes_supported, 1) > 0
   AND EXISTS (
       SELECT 1 FROM oauth_scopes os
        WHERE os.resource_server_id = rs.id
        LIMIT 1
   )
   AND state = 'pending_scan'; -- only backfill rows that haven't been updated yet

UPDATE resource_servers
   SET state = 'needs_setup'
 WHERE last_successful_generation > 0
   AND state = 'pending_scan'; -- still pending → has scan but not fully configured

UPDATE resource_servers
   SET state = 'scan_failed'
 WHERE (status = 'failed' OR last_scan_status = 'failure')
   AND state = 'pending_scan';

-- All remaining pending_scan rows stay pending_scan.

-- ── 8. Backfill permission rows for existing oauth_scopes (correctness fix #5) ───────────────────
-- Insert a matching (resource=scope_string, action='access') permission if one does not exist.
INSERT INTO permissions (id, tenant_id, resource, action, description, created_at, updated_at)
SELECT
    gen_random_uuid(),
    os.tenant_id,
    os.scope_string,
    'access',
    'OAuth scope: ' || COALESCE(os.display_name, os.scope_string),
    NOW(),
    NOW()
FROM oauth_scopes os
WHERE NOT EXISTS (
    SELECT 1
      FROM permissions rp
     WHERE rp.tenant_id = os.tenant_id
       AND rp.resource   = os.scope_string
       AND rp.action     = 'access'
)
ON CONFLICT DO NOTHING;

-- Insert missing oauth_scope_permissions bridges.
INSERT INTO oauth_scope_permissions (scope_id, permission_id)
SELECT
    os.id,
    rp.id
FROM oauth_scopes os
JOIN permissions rp
  ON rp.tenant_id = os.tenant_id
 AND rp.resource   = os.scope_string
 AND rp.action     = 'access'
WHERE NOT EXISTS (
    SELECT 1
      FROM oauth_scope_permissions osp
     WHERE osp.scope_id     = os.id
       AND osp.permission_id = rp.id
)
ON CONFLICT DO NOTHING;
