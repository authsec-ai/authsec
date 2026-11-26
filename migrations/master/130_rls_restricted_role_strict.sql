-- ============================================================================
-- 130: RLS fails closed for the restricted role (ADR-0001 §4.4, Phase 6)
--
-- The tenancy_isolation policy let every row through when app.workspace_id
-- was unset (the ADR's transitional clause), for every role. The scoped layer
-- (internal/tenancy) always sets app.workspace_id and switches to
-- authsec_tenant, so a statement of that role without the setting would be a
-- bug -- and it saw every workspace's rows. Now:
--
--   - authsec_tenant without app.workspace_id sees and writes nothing;
--   - with it set, every role sees only that workspace (unchanged);
--   - other roles without it keep the transitional allowance. Those are the
--     application's own connections outside the scoped layer and platform
--     jobs; ADR §4.4's authsec_platform BYPASSRLS role replaces this once the
--     production role layout is confirmed (a superuser deploy step).
--
-- tenancy_enable_rls is redefined and re-applied to every table that has the
-- policy. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.tenancy_unscoped_allowed() RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT public.tenancy_current_workspace() IS NULL
       AND current_user <> 'authsec_tenant'
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
           USING (public.tenancy_unscoped_allowed()%s OR workspace_id = %s)
           WITH CHECK (public.tenancy_unscoped_allowed() OR workspace_id = %s)',
        tbl,
        CASE WHEN null_ok THEN ' OR (workspace_id IS NULL AND public.tenancy_current_workspace() IS NOT NULL)' ELSE '' END,
        ws, ws);
END;
$$;

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT DISTINCT format('%I.%I', schemaname, tablename) AS tbl
          FROM pg_policies
         WHERE policyname = 'tenancy_isolation' AND schemaname = 'public'
    LOOP
        PERFORM public.tenancy_enable_rls(r.tbl::regclass);
    END LOOP;
END $$;
