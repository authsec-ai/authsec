-- ============================================================================
-- 054: Postgres row-level security on every workspace-owned table
--
-- ADR-0001 §4.4: defense in depth under the application's own scoping.
--
--   * tenancy_current_workspace() reads the transaction-local setting
--     app.workspace_id that internal/tenancy sets (SET LOCAL via set_config).
--   * Every public table with a workspace_id column gets ENABLE + FORCE RLS
--     and the policy tenancy_isolation:
--       - setting absent  -> no restriction (code not yet on the scoped
--                            layer keeps working; the ratchet tracks it)
--       - setting present -> only rows of that workspace are visible and
--                            writable; on the platform catalog tables listed
--                            below, workspace_id IS NULL rows stay readable.
--   * Role authsec_tenant (NOLOGIN) has DML on all tables but no BYPASSRLS.
--     internal/tenancy switches to it with SET LOCAL ROLE inside scoped
--     transactions, so the policy applies even when the application connects
--     as a superuser or as the table owner. Creating the role needs
--     CREATEROLE; without it the migration notes it and continues, and the
--     operator runs scripts/create-tenant-role.sql once.
--
-- Future tenant tables: call SELECT public.tenancy_enable_rls('public.<t>')
-- in the migration that creates them. tests/integration/flows asserts that
-- every table with workspace_id has the policy.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.tenancy_current_workspace() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('app.workspace_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION public.tenancy_enable_rls(tbl regclass) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    col_type text;
    ws       text;
    null_ok  boolean;
BEGIN
    SELECT format_type(a.atttypid, a.atttypmod) INTO col_type
      FROM pg_attribute a
     WHERE a.attrelid = tbl AND a.attname = 'workspace_id' AND NOT a.attisdropped;
    IF col_type IS NULL THEN
        RAISE EXCEPTION 'tenancy_enable_rls: % has no workspace_id column', tbl;
    END IF;

    -- Compare as the column's type (two legacy tables store text).
    IF col_type = 'uuid' THEN
        ws := 'public.tenancy_current_workspace()';
    ELSE
        ws := 'public.tenancy_current_workspace()::text';
    END IF;

    -- Platform catalog tables keep their shared (workspace_id IS NULL) rows
    -- readable; everywhere else NULL rows are not a tenant's to see.
    null_ok := tbl::text IN ('permissions', 'roles', 'role_permissions',
                             'trusted_issuers', 'oidc_providers', 'sod_rules');

    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('DROP POLICY IF EXISTS tenancy_isolation ON %s', tbl);
    EXECUTE format(
        'CREATE POLICY tenancy_isolation ON %s
           USING (public.tenancy_current_workspace() IS NULL%s OR workspace_id = %s)
           WITH CHECK (public.tenancy_current_workspace() IS NULL OR workspace_id = %s)',
        tbl, CASE WHEN null_ok THEN ' OR workspace_id IS NULL' ELSE '' END, ws, ws);
END;
$$;

DO $$
DECLARE
    t regclass;
BEGIN
    FOR t IN
        SELECT c.oid::regclass
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
         ORDER BY 1
    LOOP
        PERFORM public.tenancy_enable_rls(t);
    END LOOP;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authsec_tenant') THEN
        BEGIN
            CREATE ROLE authsec_tenant NOLOGIN NOBYPASSRLS;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'authsec_tenant not created (no CREATEROLE); run scripts/create-tenant-role.sql';
            RETURN;
        END;
    END IF;
    GRANT USAGE ON SCHEMA public TO authsec_tenant;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authsec_tenant;
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO authsec_tenant;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authsec_tenant;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO authsec_tenant;
    BEGIN
        EXECUTE format('GRANT authsec_tenant TO %I', current_user);
    EXCEPTION WHEN others THEN
        RAISE NOTICE 'could not grant authsec_tenant to %: %', current_user, SQLERRM;
    END;
END $$;
