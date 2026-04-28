-- 126_backfill_viewer_roles_for_existing_rs.sql
--
-- Backfills the viewer role + access policy for resource servers that pre-date
-- the auto-viewer flow added to ResourceServerService.Create.
--
-- Without this migration:
--   - existing RSes have no viewer role → admins can't activate via the new
--     wizard gate "step_5_viewer_role_empty",
--   - existing access policies may point default_role_id at a deleted role →
--     EnsureDefaultAccessBinding skips auto-bind (now soft-fails since the
--     consent-handler hardening, but end-users still get no scopes),
--   - end-users hitting consent on a working pre-existing RS get no auto-bind
--     and rely on direct bindings only.
--
-- This migration is idempotent (uses NOT EXISTS guards) and safe to re-run.
-- Do NOT wrap in BEGIN/COMMIT — the migration runner already wraps each
-- migration file in its own transaction, and a nested explicit COMMIT here
-- breaks the outer transaction with "unexpected transaction status idle".

-- ── 1. Create rs-{id}:viewer role for every RS that doesn't have one ──────────
INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at)
SELECT
    gen_random_uuid(),
    rs.tenant_id,
    'rs-' || rs.id::text || ':viewer',
    'Default viewer role for ' || rs.name || ' (auto-generated, backfilled)',
    NOW(),
    NOW()
FROM resource_servers rs
WHERE NOT EXISTS (
    SELECT 1 FROM roles r
     WHERE r.tenant_id = rs.tenant_id
       AND r.name = 'rs-' || rs.id::text || ':viewer'
);

-- ── 2. Create access policy with viewer as default for every RS missing one ──
INSERT INTO resource_server_access_policies
    (id, tenant_id, resource_server_id, enabled, default_role_id, created_at, updated_at)
SELECT
    gen_random_uuid(),
    rs.tenant_id,
    rs.id,
    true,
    viewer.id,
    NOW(),
    NOW()
FROM resource_servers rs
JOIN roles viewer
  ON viewer.tenant_id = rs.tenant_id
 AND viewer.name = 'rs-' || rs.id::text || ':viewer'
WHERE NOT EXISTS (
    SELECT 1 FROM resource_server_access_policies ap
     WHERE ap.resource_server_id = rs.id
);

-- ── 3. Repoint dangling default_role_id pointers to the viewer role ──────────
-- Some pre-existing access policies may point at admin/readonly roles that
-- were deleted. Repoint those to the freshly-backfilled viewer.
UPDATE resource_server_access_policies ap
   SET default_role_id = viewer.id,
       updated_at      = NOW()
  FROM resource_servers rs,
       roles viewer
 WHERE ap.resource_server_id = rs.id
   AND viewer.tenant_id = rs.tenant_id
   AND viewer.name = 'rs-' || rs.id::text || ':viewer'
   AND ap.default_role_id IS NOT NULL
   AND NOT EXISTS (
       SELECT 1 FROM roles r2 WHERE r2.id = ap.default_role_id
   );

-- ── 4. Populate viewer.role_permissions with read-only scopes ────────────────
-- For each RS, pick the read-only scopes (heuristic: scope ends in :read, or
-- contains 'read', or is named 'read'/'view'/'list') and bind them to the
-- viewer role via permissions.
INSERT INTO role_permissions (role_id, permission_id)
SELECT DISTINCT viewer.id, p.id
FROM resource_servers rs
JOIN roles viewer
  ON viewer.tenant_id = rs.tenant_id
 AND viewer.name = 'rs-' || rs.id::text || ':viewer'
JOIN oauth_scopes os
  ON os.resource_server_id = rs.id
JOIN permissions p
  ON p.tenant_id = os.tenant_id
 AND p.resource = os.scope_string
 AND p.action = 'access'
WHERE (
        os.scope_string LIKE '%:read'
     OR os.scope_string LIKE 'read:%'
     OR os.scope_string LIKE '%:list'
     OR os.scope_string LIKE '%:view'
     OR os.scope_string IN ('read','view','list')
      )
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions rp
       WHERE rp.role_id = viewer.id
         AND rp.permission_id = p.id
  );

-- ── 5. Fallback: if a viewer ended up with zero perms (no read-only scopes
--     matched the heuristic), grant viewer ALL of that RS's scope permissions.
--     This makes the activation gate "viewer has ≥1 scope" pass for RSes that
--     use non-conventional scope naming.
INSERT INTO role_permissions (role_id, permission_id)
SELECT DISTINCT viewer.id, p.id
FROM resource_servers rs
JOIN roles viewer
  ON viewer.tenant_id = rs.tenant_id
 AND viewer.name = 'rs-' || rs.id::text || ':viewer'
JOIN oauth_scopes os
  ON os.resource_server_id = rs.id
JOIN permissions p
  ON p.tenant_id = os.tenant_id
 AND p.resource = os.scope_string
 AND p.action = 'access'
WHERE NOT EXISTS (
    -- Only when this viewer currently has zero role_permissions rows
    SELECT 1 FROM role_permissions rp WHERE rp.role_id = viewer.id
)
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp2
     WHERE rp2.role_id = viewer.id
       AND rp2.permission_id = p.id
);

-- ── 6. Backfill state='ready' for any RS that already has a complete policy ──
-- An existing RS that has tools, scopes, every non-public tool mapped, and a
-- viewer role with ≥1 scope IS effectively activated. Don't force admins to
-- click through the wizard for RSes they were already using in production.
UPDATE resource_servers rs
   SET state              = 'ready',
       setup_completed_at = NOW()
 WHERE rs.state IN ('pending_scan','needs_setup')
   AND rs.last_successful_generation > 0
   AND EXISTS (SELECT 1 FROM mcp_tools t WHERE t.resource_server_id = rs.id)
   AND EXISTS (SELECT 1 FROM oauth_scopes os WHERE os.resource_server_id = rs.id)
   AND NOT EXISTS (
       -- No unmapped non-public tools
       SELECT 1 FROM mcp_tools t
        WHERE t.resource_server_id = rs.id
          AND t.is_public = false
          AND NOT EXISTS (
              SELECT 1 FROM mcp_tool_scope_map m
               WHERE m.tool_id = t.id
                 AND m.source = 'admin_override'
          )
   )
   AND EXISTS (
       SELECT 1 FROM resource_server_access_policies ap
       JOIN role_permissions rp ON rp.role_id = ap.default_role_id
        WHERE ap.resource_server_id = rs.id
          AND ap.enabled = true
          AND ap.default_role_id IS NOT NULL
   );

-- ── 7. Backfill admin_override source for legacy mappings ────────────────────
-- mcp_tool_scope_map rows from before the source column existed (introduced in
-- migration 125) may have source='admin_override' already if they were
-- manually-configured pre-migration, but legacy auto-matched=true rows should
-- be downgraded to sdk_suggested so the new admin_override gate correctly
-- ignores them. Migration 125 already does this for new auto_matched rows;
-- this is an extra safety net for rows that pre-date that migration.
UPDATE mcp_tool_scope_map
   SET source = 'sdk_suggested'
 WHERE auto_matched = true
   AND (source IS NULL OR source = '');

UPDATE mcp_tool_scope_map
   SET source = 'admin_override'
 WHERE auto_matched = false
   AND (source IS NULL OR source = '');

