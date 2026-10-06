-- ============================================================================
-- 046: tenancy backfill -- attribute the columns added in 045
--
-- ADR-0001 §6 step 3 (AS-051). Fills workspace_id deterministically from the
-- parent row only. Rows that cannot be attributed stay NULL and are reported
-- in tenancy_backfill_orphans with a reason. Nothing is guessed and nothing is
-- assigned to a customer workspace or to the system workspace.
--
-- Rules (an attributed workspace must exist in workspaces):
--   credentials              client_id -> tenancy_workspace_for_user_ref
--                            (users.id, else a users.client_id shared by users
--                            of exactly one workspace)
--   mfa_methods              user_id and client_id through the same rule; if
--                            both resolve they must agree
--   services                 created_by (the creator's client id, text) through
--                            the same rule; non-uuid created_by is an orphan
--   role_permissions         roles.workspace_id. A NULL role workspace is a
--                            platform role: the row stays NULL by design and is
--                            NOT an orphan
--   oauth_scope_permissions  oauth_scopes.workspace_id
--   mcp_tool_scope_map       mcp_tools.workspace_id, only when the scope is in
--                            the same workspace (else: cross-workspace link)
--   spire_workloads          one distinct workspace among: the SPIFFE path
--                            /workspaces/<ws>/... or /tenants/<ws>/...,
--                            service_accounts.spiffe_id and
--                            application_spiffe_identities.spiffe_id
--   spire_oidc_tokens        one distinct workspace among spire_workloads,
--                            service_accounts and application_spiffe_identities
--                            with the same SPIFFE ID
--   spire_policies,          no ownership source exists (the policy engine was
--   spire_role_bindings      never workspace-scoped): reported as orphans
--   spire_policy_rules       the parent policy's workspace
--   spire_policy_subjects,   the parent rule's workspace
--   _resources, _actions,
--   _conditions
--
-- The work lives in tenancy_backfill_workspace_ids() so an operator can re-run
-- it after resolving orphans; each run only touches NULL rows, refreshes the
-- orphan list, and returns per table the rows it filled and the rows still
-- unattributed. Idempotent.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.tenancy_backfill_workspace_ids()
RETURNS TABLE (table_name text, filled bigint, orphans bigint)
LANGUAGE plpgsql
AS $fn$
#variable_conflict use_column
DECLARE
    n bigint;
    before jsonb := '{}'::jsonb;
    cnt bigint;
    uuid_re CONSTANT text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
BEGIN
    -- ---------------------------------------------------------------- credentials
    IF to_regclass('public.credentials') IS NOT NULL THEN
        WITH r AS (
            SELECT c.id, public.tenancy_workspace_for_user_ref(c.client_id) AS ws
              FROM public.credentials c
             WHERE c.workspace_id IS NULL)
        UPDATE public.credentials c SET workspace_id = r.ws
          FROM r WHERE c.id = r.id AND r.ws IS NOT NULL;
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'credentials'
           AND NOT EXISTS (SELECT 1 FROM public.credentials c
                            WHERE c.id::text = o.row_id AND c.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'credentials', c.id::text,
               CASE
                   WHEN EXISTS (SELECT 1 FROM public.users u WHERE u.id = c.client_id)
                       THEN 'user has no existing workspace'
                   WHEN EXISTS (SELECT 1 FROM public.users u WHERE u.client_id = c.client_id)
                       THEN 'client_id is shared by users of several workspaces or users without one'
                   ELSE 'client_id matches no user'
               END
          FROM public.credentials c
         WHERE c.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'credentials'; filled := n;
        SELECT count(*) INTO orphans FROM public.credentials c WHERE c.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- mfa_methods
    IF to_regclass('public.mfa_methods') IS NOT NULL THEN
        WITH r AS (
            SELECT m.id,
                   public.tenancy_workspace_for_user_ref(m.user_id)   AS wu,
                   public.tenancy_workspace_for_user_ref(m.client_id) AS wc
              FROM public.mfa_methods m
             WHERE m.workspace_id IS NULL)
        UPDATE public.mfa_methods m SET workspace_id = COALESCE(r.wu, r.wc)
          FROM r
         WHERE m.id = r.id
           AND COALESCE(r.wu, r.wc) IS NOT NULL
           AND (r.wu IS NULL OR r.wc IS NULL OR r.wu = r.wc);
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'mfa_methods'
           AND NOT EXISTS (SELECT 1 FROM public.mfa_methods m
                            WHERE m.id::text = o.row_id AND m.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'mfa_methods', m.id::text,
               CASE
                   WHEN public.tenancy_workspace_for_user_ref(m.user_id) IS NOT NULL
                    AND public.tenancy_workspace_for_user_ref(m.client_id) IS NOT NULL
                       THEN 'user_id and client_id resolve to different workspaces'
                   WHEN EXISTS (SELECT 1 FROM public.users u WHERE u.id IN (m.user_id, m.client_id))
                       THEN 'user has no existing workspace'
                   ELSE 'user_id/client_id match no user'
               END
          FROM public.mfa_methods m
         WHERE m.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'mfa_methods'; filled := n;
        SELECT count(*) INTO orphans FROM public.mfa_methods m WHERE m.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- services
    IF to_regclass('public.services') IS NOT NULL THEN
        WITH r AS (
            SELECT s.id,
                   CASE WHEN s.created_by ~ uuid_re
                        THEN public.tenancy_workspace_for_user_ref(s.created_by::uuid)
                   END AS ws
              FROM public.services s
             WHERE s.workspace_id IS NULL)
        UPDATE public.services s SET workspace_id = r.ws
          FROM r WHERE s.id = r.id AND r.ws IS NOT NULL;
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'services'
           AND NOT EXISTS (SELECT 1 FROM public.services s
                            WHERE s.id::text = o.row_id AND s.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'services', s.id::text,
               CASE
                   WHEN NOT (s.created_by ~ uuid_re) THEN 'created_by is not a user or client id'
                   ELSE 'created_by matches no user with an existing workspace'
               END
          FROM public.services s
         WHERE s.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'services'; filled := n;
        SELECT count(*) INTO orphans FROM public.services s WHERE s.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- role_permissions
    IF to_regclass('public.role_permissions') IS NOT NULL THEN
        UPDATE public.role_permissions rp SET workspace_id = r.workspace_id
          FROM public.roles r
          JOIN public.workspaces w ON w.id = r.workspace_id
         WHERE rp.workspace_id IS NULL AND r.id = rp.role_id;
        GET DIAGNOSTICS n = ROW_COUNT;

        -- A NULL row whose role is a platform role (roles.workspace_id IS NULL)
        -- is platform-owned, not an orphan.
        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'role_permissions'
           AND NOT EXISTS (SELECT 1 FROM public.role_permissions rp
                             JOIN public.roles r ON r.id = rp.role_id
                            WHERE rp.role_id::text || ':' || rp.permission_id::text = o.row_id
                              AND rp.workspace_id IS NULL AND r.workspace_id IS NOT NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'role_permissions', rp.role_id::text || ':' || rp.permission_id::text,
               'role workspace does not exist'
          FROM public.role_permissions rp
          JOIN public.roles r ON r.id = rp.role_id
         WHERE rp.workspace_id IS NULL AND r.workspace_id IS NOT NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'role_permissions'; filled := n;
        SELECT count(*) INTO orphans
          FROM public.role_permissions rp JOIN public.roles r ON r.id = rp.role_id
         WHERE rp.workspace_id IS NULL AND r.workspace_id IS NOT NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- oauth_scope_permissions
    IF to_regclass('public.oauth_scope_permissions') IS NOT NULL THEN
        UPDATE public.oauth_scope_permissions sp SET workspace_id = s.workspace_id
          FROM public.oauth_scopes s
          JOIN public.workspaces w ON w.id = s.workspace_id
         WHERE sp.workspace_id IS NULL AND s.id = sp.scope_id;
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'oauth_scope_permissions'
           AND NOT EXISTS (SELECT 1 FROM public.oauth_scope_permissions sp
                            WHERE sp.scope_id::text || ':' || sp.permission_id::text = o.row_id
                              AND sp.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'oauth_scope_permissions', sp.scope_id::text || ':' || sp.permission_id::text,
               'scope workspace does not exist'
          FROM public.oauth_scope_permissions sp
         WHERE sp.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'oauth_scope_permissions'; filled := n;
        SELECT count(*) INTO orphans FROM public.oauth_scope_permissions sp WHERE sp.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- mcp_tool_scope_map
    IF to_regclass('public.mcp_tool_scope_map') IS NOT NULL THEN
        UPDATE public.mcp_tool_scope_map m SET workspace_id = t.workspace_id
          FROM public.mcp_tools t
          JOIN public.workspaces w ON w.id = t.workspace_id,
               public.oauth_scopes s
         WHERE m.workspace_id IS NULL
           AND t.id = m.tool_id
           AND s.id = m.scope_id
           AND s.workspace_id = t.workspace_id;
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'mcp_tool_scope_map'
           AND NOT EXISTS (SELECT 1 FROM public.mcp_tool_scope_map m
                            WHERE m.tool_id::text || ':' || m.scope_id::text = o.row_id
                              AND m.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'mcp_tool_scope_map', m.tool_id::text || ':' || m.scope_id::text,
               CASE
                   WHEN t.workspace_id IS DISTINCT FROM s.workspace_id
                       THEN 'tool and scope belong to different workspaces'
                   ELSE 'tool workspace does not exist'
               END
          FROM public.mcp_tool_scope_map m
          LEFT JOIN public.mcp_tools t ON t.id = m.tool_id
          LEFT JOIN public.oauth_scopes s ON s.id = m.scope_id
         WHERE m.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'mcp_tool_scope_map'; filled := n;
        SELECT count(*) INTO orphans FROM public.mcp_tool_scope_map m WHERE m.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- spire_workloads
    IF to_regclass('public.spire_workloads') IS NOT NULL THEN
        WITH wl AS (
            SELECT w.id,
                   regexp_replace(COALESCE(w.spiffe_id, ''), '^spiffe://[^/]+', '') AS path
              FROM public.spire_workloads w
             WHERE w.workspace_id IS NULL),
        cand AS (
            SELECT wl.id, substring(wl.path FROM '^/(?:workspaces|tenants)/([0-9a-fA-F-]{36})(?:/|$)')::uuid AS ws
              FROM wl
             WHERE wl.path ~ '^/(?:workspaces|tenants)/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)'
            UNION
            SELECT wl.id, sa.workspace_id
              FROM wl JOIN public.service_accounts sa
                ON wl.path <> ''
               AND regexp_replace(sa.spiffe_id, '^spiffe://[^/]+', '') = wl.path
            UNION
            SELECT wl.id, a.workspace_id
              FROM wl JOIN public.application_spiffe_identities a
                ON wl.path <> ''
               AND regexp_replace(a.spiffe_id, '^spiffe://[^/]+', '') = wl.path),
        one AS (
            SELECT c.id, min(c.ws::text)::uuid AS ws
              FROM cand c LEFT JOIN public.workspaces w ON w.id = c.ws
             GROUP BY c.id
            HAVING count(DISTINCT c.ws) = 1 AND count(w.id) = count(*))
        UPDATE public.spire_workloads w SET workspace_id = one.ws
          FROM one WHERE w.id = one.id;
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'spire_workloads'
           AND NOT EXISTS (SELECT 1 FROM public.spire_workloads w
                            WHERE w.id::text = o.row_id AND w.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'spire_workloads', w.id::text,
               'no single workspace from the SPIFFE path, service accounts or application identities'
          FROM public.spire_workloads w
         WHERE w.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'spire_workloads'; filled := n;
        SELECT count(*) INTO orphans FROM public.spire_workloads w WHERE w.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- spire_oidc_tokens
    IF to_regclass('public.spire_oidc_tokens') IS NOT NULL THEN
        WITH tk AS (
            SELECT t.id,
                   regexp_replace(COALESCE(t.spiffe_id, ''), '^spiffe://[^/]+', '') AS path
              FROM public.spire_oidc_tokens t
             WHERE t.workspace_id IS NULL),
        cand AS (
            SELECT tk.id, w.workspace_id AS ws
              FROM tk JOIN public.spire_workloads w
                ON tk.path <> ''
               AND regexp_replace(w.spiffe_id, '^spiffe://[^/]+', '') = tk.path
             WHERE w.workspace_id IS NOT NULL
            UNION
            SELECT tk.id, sa.workspace_id
              FROM tk JOIN public.service_accounts sa
                ON tk.path <> ''
               AND regexp_replace(sa.spiffe_id, '^spiffe://[^/]+', '') = tk.path
            UNION
            SELECT tk.id, a.workspace_id
              FROM tk JOIN public.application_spiffe_identities a
                ON tk.path <> ''
               AND regexp_replace(a.spiffe_id, '^spiffe://[^/]+', '') = tk.path),
        one AS (
            SELECT c.id, min(c.ws::text)::uuid AS ws
              FROM cand c LEFT JOIN public.workspaces w ON w.id = c.ws
             GROUP BY c.id
            HAVING count(DISTINCT c.ws) = 1 AND count(w.id) = count(*))
        UPDATE public.spire_oidc_tokens t SET workspace_id = one.ws
          FROM one WHERE t.id = one.id;
        GET DIAGNOSTICS n = ROW_COUNT;

        DELETE FROM public.tenancy_backfill_orphans o
         WHERE o.table_name = 'spire_oidc_tokens'
           AND NOT EXISTS (SELECT 1 FROM public.spire_oidc_tokens t
                            WHERE t.id::text = o.row_id AND t.workspace_id IS NULL);
        INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
        SELECT 'spire_oidc_tokens', t.id::text,
               'no single workspace owns the token SPIFFE ID'
          FROM public.spire_oidc_tokens t
         WHERE t.workspace_id IS NULL
        ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
        DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now();

        table_name := 'spire_oidc_tokens'; filled := n;
        SELECT count(*) INTO orphans FROM public.spire_oidc_tokens t WHERE t.workspace_id IS NULL;
        RETURN NEXT;
    END IF;

    -- ---------------------------------------------------------------- spire policy engine
    -- spire_policies and spire_role_bindings have no ownership source; their
    -- children inherit from the parent (so they stay NULL while it does).
    DECLARE
        t text;
    BEGIN
        FOREACH t IN ARRAY ARRAY[
            'spire_policies', 'spire_role_bindings', 'spire_policy_rules',
            'spire_policy_subjects', 'spire_policy_resources', 'spire_policy_actions',
            'spire_policy_conditions'
        ] LOOP
            IF to_regclass('public.' || t) IS NOT NULL THEN
                EXECUTE format('SELECT count(*) FROM public.%I x WHERE x.workspace_id IS NULL', t) INTO cnt;
                before := before || jsonb_build_object(t, cnt);
            END IF;
        END LOOP;
    END;
    IF to_regclass('public.spire_policy_rules') IS NOT NULL
       AND to_regclass('public.spire_policies') IS NOT NULL THEN
        UPDATE public.spire_policy_rules r SET workspace_id = p.workspace_id
          FROM public.spire_policies p
         WHERE r.workspace_id IS NULL AND p.id = r.policy_id AND p.workspace_id IS NOT NULL;
    END IF;
    IF to_regclass('public.spire_policy_rules') IS NOT NULL THEN
        IF to_regclass('public.spire_policy_subjects') IS NOT NULL THEN
            UPDATE public.spire_policy_subjects x SET workspace_id = r.workspace_id
              FROM public.spire_policy_rules r
             WHERE x.workspace_id IS NULL AND r.id = x.rule_id AND r.workspace_id IS NOT NULL;
        END IF;
        IF to_regclass('public.spire_policy_resources') IS NOT NULL THEN
            UPDATE public.spire_policy_resources x SET workspace_id = r.workspace_id
              FROM public.spire_policy_rules r
             WHERE x.workspace_id IS NULL AND r.id = x.rule_id AND r.workspace_id IS NOT NULL;
        END IF;
        IF to_regclass('public.spire_policy_actions') IS NOT NULL THEN
            UPDATE public.spire_policy_actions x SET workspace_id = r.workspace_id
              FROM public.spire_policy_rules r
             WHERE x.workspace_id IS NULL AND r.id = x.rule_id AND r.workspace_id IS NOT NULL;
        END IF;
        IF to_regclass('public.spire_policy_conditions') IS NOT NULL THEN
            UPDATE public.spire_policy_conditions x SET workspace_id = r.workspace_id
              FROM public.spire_policy_rules r
             WHERE x.workspace_id IS NULL AND r.id = x.rule_id AND r.workspace_id IS NOT NULL;
        END IF;
    END IF;

    DECLARE
        t text;
        reason text;
    BEGIN
        FOREACH t IN ARRAY ARRAY[
            'spire_policies', 'spire_role_bindings', 'spire_policy_rules',
            'spire_policy_subjects', 'spire_policy_resources', 'spire_policy_actions',
            'spire_policy_conditions'
        ] LOOP
            IF to_regclass('public.' || t) IS NULL THEN
                CONTINUE;
            END IF;
            reason := CASE
                WHEN t IN ('spire_policies', 'spire_role_bindings')
                    THEN 'no ownership source: the SPIRE policy engine was never workspace-scoped'
                ELSE 'parent policy is not attributed'
            END;
            EXECUTE format(
                'DELETE FROM public.tenancy_backfill_orphans o
                  WHERE o.table_name = %L
                    AND NOT EXISTS (SELECT 1 FROM public.%I x
                                     WHERE x.id::text = o.row_id AND x.workspace_id IS NULL)',
                t, t);
            EXECUTE format(
                'INSERT INTO public.tenancy_backfill_orphans (table_name, row_id, reason)
                 SELECT %L, x.id::text, %L FROM public.%I x WHERE x.workspace_id IS NULL
                 ON CONFLICT ON CONSTRAINT tenancy_backfill_orphans_pkey
                 DO UPDATE SET reason = EXCLUDED.reason, recorded_at = now()',
                t, reason, t);
            table_name := t;
            EXECUTE format('SELECT count(*) FROM public.%I x WHERE x.workspace_id IS NULL', t) INTO orphans;
            filled := COALESCE((before ->> t)::bigint, 0) - orphans;
            RETURN NEXT;
        END LOOP;
    END;
END
$fn$;

COMMENT ON FUNCTION public.tenancy_backfill_workspace_ids() IS
    'Fills NULL workspace_id on the tables expanded in 045 from their parents '
    'and refreshes tenancy_backfill_orphans. Safe to re-run.';

SELECT * FROM public.tenancy_backfill_workspace_ids();
