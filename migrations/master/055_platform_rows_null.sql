-- ============================================================================
-- 055: one convention for platform rows -- workspace_id IS NULL (AS-079)
--
-- ADR-0001 §6.6. Platform-owned rows live only on the tables that hold
-- platform data (permissions, roles, role_permissions, trusted_issuers,
-- oidc_providers, sod_rules: the tables 054 lets read workspace_id IS NULL
-- rows) and carry workspace_id IS NULL. The system workspace
-- 00000000-0000-0000-0000-000000000000 stays only as the registry row that
-- orphan backfills may fall back to (ADR §6.3); it owns no catalog rows.
--
-- 001_bootstrap.sql seeded permissions into the system workspace:
--   users:delete              -> already in the catalog (052); references are
--                                moved to the catalog row, the copy is removed.
--   users:read, users:write   -> moved into the catalog (workspace_id NULL) and,
--                                as 003/052 do for the rest of the catalog,
--                                granted to every workspace admin role.
--   migrations:*              -> removed. They guarded the per-workspace
--                                database service, which no longer exists;
--                                nothing checks them, and in the catalog they
--                                would be granted to every workspace admin.
-- Roles of the system workspace (none are seeded today) become platform roles
-- (workspace_id NULL) with their grants. Rows of the system workspace on any
-- other table are reported with a NOTICE, not guessed (ADR §6.3).
--
-- Finally a CHECK on permissions, roles and role_permissions refuses new
-- system-workspace rows, so the convention cannot drift back.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
DECLARE
    sys CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
    r   record;
    n   bigint;
BEGIN
    -- 1. System-workspace permissions that have a catalog twin: move every
    --    reference to the twin, then drop the copy.
    FOR r IN
        SELECT s.id AS sys_id, c.id AS cat_id
          FROM public.permissions s
          JOIN public.permissions c
            ON c.workspace_id IS NULL AND c.resource = s.resource AND c.action = s.action
         WHERE s.workspace_id = sys
    LOOP
        INSERT INTO public.role_permissions (role_id, permission_id)
        SELECT role_id, r.cat_id FROM public.role_permissions WHERE permission_id = r.sys_id
        ON CONFLICT (role_id, permission_id) DO NOTHING;
        IF to_regclass('public.oauth_scope_permissions') IS NOT NULL THEN
            EXECUTE 'INSERT INTO public.oauth_scope_permissions (scope_id, permission_id)
                     SELECT scope_id, $1 FROM public.oauth_scope_permissions WHERE permission_id = $2
                     ON CONFLICT DO NOTHING' USING r.cat_id, r.sys_id;
        END IF;
        DELETE FROM public.permissions WHERE id = r.sys_id;
    END LOOP;

    -- 2. The legacy migration-service permissions are removed with their grants.
    DELETE FROM public.permissions WHERE workspace_id = sys AND resource = 'migrations';

    -- 3. users:read / users:write join the catalog.
    UPDATE public.permissions SET workspace_id = NULL
     WHERE workspace_id = sys AND resource = 'users' AND action IN ('read', 'write');
    INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
    VALUES (gen_random_uuid(), NULL, 'users', 'read', 'Read user information', 'users:read', NOW()),
           (gen_random_uuid(), NULL, 'users', 'write', 'Create and update users', 'users:write', NOW())
    ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;
    UPDATE public.permissions SET full_permission_string = resource || ':' || action
     WHERE workspace_id IS NULL AND resource = 'users' AND full_permission_string IS NULL;

    INSERT INTO public.role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
      FROM public.roles ro
      JOIN public.permissions p
        ON p.workspace_id IS NULL AND p.resource = 'users' AND p.action IN ('read', 'write')
     WHERE ro.name = 'admin' AND ro.workspace_id IS NOT NULL AND ro.workspace_id <> sys
    ON CONFLICT (role_id, permission_id) DO NOTHING;

    -- 4. Any remaining system-workspace permission (none are known) joins the
    --    catalog unless the catalog already has it, in which case 1 handled it.
    UPDATE public.permissions SET workspace_id = NULL WHERE workspace_id = sys;

    -- 5. System-workspace roles become platform roles, with their grants.
    UPDATE public.role_permissions SET workspace_id = NULL
     WHERE role_id IN (SELECT id FROM public.roles WHERE workspace_id = sys);
    UPDATE public.roles SET workspace_id = NULL WHERE workspace_id = sys;
    UPDATE public.role_permissions SET workspace_id = NULL WHERE workspace_id = sys;

    -- 6. Report, do not guess: system-workspace rows left anywhere else.
    FOR r IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace s ON s.oid = c.relnamespace AND s.nspname = 'public'
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
         WHERE c.relkind = 'r'
         ORDER BY 1
    LOOP
        EXECUTE format('SELECT count(*) FROM public.%I WHERE workspace_id::text = %L', r.relname, sys::text) INTO n;
        IF n > 0 THEN
            RAISE NOTICE 'platform rows: % has % row(s) in the system workspace; left in place', r.relname, n;
        END IF;
    END LOOP;
END $$;

-- 7. Keep the convention: no catalog row in the system workspace.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['permissions', 'roles', 'role_permissions'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = ('public.' || t)::regclass
                          AND conname = 'ck_' || t || '_platform_is_null') THEN
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (workspace_id IS DISTINCT FROM %L::uuid)',
                t, 'ck_' || t || '_platform_is_null', '00000000-0000-0000-0000-000000000000');
        END IF;
    END LOOP;
END $$;
