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
