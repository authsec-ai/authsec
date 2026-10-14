-- ============================================================================
-- 105: tenancy contract (safe form) -- workspace FKs and NOT NULL for new writes
--
-- ADR-0001 §6 step 4 (AS-051, AS-052). Every constraint here is added
-- NOT VALID: Postgres enforces it for rows written from now on and does not
-- scan existing rows, so legacy data cannot fail this migration. The operator
-- validates them later with scripts/tenancy-validate.sql once its violation
-- counts are zero.
--
-- 1. FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
--    NOT VALID, on the tenant tables that had a workspace_id but no FK of
--    either kind (schema-inventory §0) and on the columns added in 045.
--    CASCADE matches the neighbouring tables and WorkspaceRepository.DeleteTenant
--    (database/workspace_repository.go), which deletes a handful of tables and
--    relies on cascades for the rest. An UPDATE that leaves workspace_id unchanged is not
--    re-checked, so legacy rows that point at a deleted workspace stay
--    writable until they are cleaned up.
--    Not added:
--      audit_events, spire_audit_logs -- workspace_id is text (a type change
--        is a separate expand/contract);
--      pending_registrations -- during admin signup workspace_id holds the id
--        the workspace will get once the OTP is verified, so no workspaces row
--        exists yet (database/otp_repository.go); the row is consumed when
--        the workspace is created.
--
-- 2. Composite FKs that pin a join row to its parent's workspace:
--      role_permissions        (workspace_id, role_id)  -> roles(workspace_id, id)
--      oauth_scope_permissions (scope_id, workspace_id) -> oauth_scopes(id, workspace_id)
--      mcp_tool_scope_map      (tool_id, workspace_id)  -> mcp_tools(id, workspace_id)
--      mcp_tool_scope_map      (scope_id, workspace_id) -> oauth_scopes(id, workspace_id)
--    plus the missing oauth_scope_permissions.permission_id -> permissions(id).
--    The 045 triggers fill workspace_id from the parent, so a row whose
--    supplied workspace disagrees with its parent is rejected here.
--
-- 3. workspace_id must be set on new writes, for the tenant tables where NULL
--    has no meaning: users, delegation_policies, delegation_tokens, services,
--    credentials, mfa_methods, oauth_scope_permissions, mcp_tool_scope_map,
--    spire_workloads.
--      * Table has no NULL row (after 046): CHECK (workspace_id IS NOT NULL)
--        NOT VALID, named ck_<table>_tenancy_ws_nn.
--      * Table still has NULL rows (orphans): a CHECK would also reject any
--        UPDATE of those legacy rows (Postgres re-checks a CHECK on every
--        updated row, NOT VALID or not), which could break sign-in for an
--        unattributed user or credential. Such a table gets trigger
--        trg_tenancy_require_ws instead: it rejects INSERTs with a NULL
--        workspace_id and UPDATEs that clear one, and leaves legacy NULL rows
--        writable. tenancy-validate.sql prints the CHECK to add, and the
--        trigger to drop, once the orphans are resolved.
--
-- Exceptions -- NULL deliberately means platform-owned or not-yet-known, so no
-- NOT NULL rule (each still gets the FK where the column is uuid):
--   roles                   NULL = platform/global role (idx_roles_global_*)
--   permissions             NULL = global permission catalog (003/005)
--   role_permissions        NULL = grant on a platform role
--   oidc_providers          NULL = platform provider offered to every workspace
--   sod_rules               NULL = global seeded rule
--   trusted_issuers         NULL = platform issuer (044)
--   audit_events            NULL = pre-auth event (also text, no FK)
--   spire_audit_logs        written by unauthenticated SPIRE routes (text, no FK)
--   oidc_states             NULL = platform-level login
--   device_codes            NULL until the user approves at /authorize (RFC 8628)
--   iga_webhook_deliveries  NULL until the installation is resolved (by design)
--   spire_policies, spire_policy_rules/_subjects/_resources/_actions/
--   _conditions, spire_role_bindings, spire_oidc_tokens
--                           the embedded SPIRE engine (off by default,
--                           ENABLE_EMBEDDED_SPIRE) writes these from
--                           unauthenticated routes and seeds platform default
--                           policies; it has to be scoped before NULL can be
--                           refused
--   mcp_oauth_clients       home_workspace_id NULL = platform or not-yet-adopted
--                           DCR/CIMD client (see 045)
--
-- Idempotent: every constraint and trigger is looked up by name first, and a
-- table or column missing on a drifted database is skipped with a NOTICE.
-- ============================================================================

-- Rejects a NULL workspace_id on INSERT, and an UPDATE that clears it.
CREATE OR REPLACE FUNCTION public.tenancy_require_workspace_id()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF NEW.workspace_id IS NULL
       AND (TG_OP = 'INSERT' OR OLD.workspace_id IS NOT NULL) THEN
        RAISE EXCEPTION 'tenancy: %.workspace_id is required', TG_TABLE_NAME
            USING ERRCODE = 'not_null_violation';
    END IF;
    RETURN NEW;
END
$fn$;

-- 1. Direct FKs to workspaces.
DO $$
DECLARE
    t text;
    att smallint;
    cname text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        -- had workspace_id, no FK of either kind (schema-inventory §0)
        'users', 'roles', 'permissions', 'groups', 'service_accounts',
        'resource_servers', 'workload_identity_providers',
        'cloud_connector', 'cloud_identity', 'cloud_secret', 'cloud_resource',
        'cloud_permission', 'cloud_workload', 'cloud_usage', 'cloud_assume_edge',
        'cloud_scan_checkpoint', 'discovery_scan_runs', 'discovery_rule_catalogs',
        'connector_oauth_states', 'connector_provider_apps', 'sync_configurations',
        'native_tokens', 'auth_request_contexts',
        'saml_requests', 'saml_callback_states', 'oidc_states', 'device_codes',
        'delegation_policies', 'delegation_tokens', 'agent_action_audit_log',
        'auth_issuance_audit', 'authorization_decision_logs', 'connector_action_audit',
        -- added in 045
        'services', 'credentials', 'mfa_methods',
        'role_permissions', 'oauth_scope_permissions', 'mcp_tool_scope_map',
        'spire_oidc_tokens', 'spire_policies', 'spire_policy_rules',
        'spire_policy_subjects', 'spire_policy_resources', 'spire_policy_actions',
        'spire_policy_conditions', 'spire_role_bindings', 'spire_workloads'
    ] LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            RAISE NOTICE 'tenancy contract: table % does not exist, skipped', t;
            CONTINUE;
        END IF;
        SELECT a.attnum INTO att
          FROM pg_attribute a
         WHERE a.attrelid = ('public.' || t)::regclass
           AND a.attname = 'workspace_id' AND NOT a.attisdropped
           AND a.atttypid = 'uuid'::regtype;
        IF att IS NULL THEN
            RAISE NOTICE 'tenancy contract: %.workspace_id missing or not uuid, skipped', t;
            CONTINUE;
        END IF;
        cname := 'fk_' || t || '_tenancy_ws';
        -- Skip when this FK, or any FK from workspace_id to workspaces, exists.
        IF EXISTS (SELECT 1 FROM pg_constraint k
                    WHERE k.conrelid = ('public.' || t)::regclass
                      AND (k.conname = cname
                           OR (k.contype = 'f'
                               AND k.confrelid = 'public.workspaces'::regclass
                               AND k.conkey = ARRAY[att]))) THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (workspace_id) '
            'REFERENCES public.workspaces(id) ON DELETE CASCADE NOT VALID',
            t, cname);
    END LOOP;
END $$;

-- 2. Composite FKs for the join tables.
DO $$
DECLARE
    spec text[];
BEGIN
    FOREACH spec SLICE 1 IN ARRAY ARRAY[
        -- table, constraint, local columns, parent, parent columns
        ARRAY['role_permissions', 'fk_role_permissions_tenancy_role',
              'workspace_id, role_id', 'roles', 'workspace_id, id'],
        ARRAY['oauth_scope_permissions', 'fk_oauth_scope_permissions_tenancy_scope',
              'scope_id, workspace_id', 'oauth_scopes', 'id, workspace_id'],
        ARRAY['mcp_tool_scope_map', 'fk_mcp_tool_scope_map_tenancy_tool',
              'tool_id, workspace_id', 'mcp_tools', 'id, workspace_id'],
        ARRAY['mcp_tool_scope_map', 'fk_mcp_tool_scope_map_tenancy_scope',
              'scope_id, workspace_id', 'oauth_scopes', 'id, workspace_id'],
        ARRAY['oauth_scope_permissions', 'fk_oauth_scope_permissions_tenancy_perm',
              'permission_id', 'permissions', 'id']
    ] LOOP
        IF to_regclass('public.' || spec[1]) IS NULL OR to_regclass('public.' || spec[4]) IS NULL THEN
            RAISE NOTICE 'tenancy contract: % or % missing, % skipped', spec[1], spec[4], spec[2];
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_attribute a
                        WHERE a.attrelid = ('public.' || spec[1])::regclass
                          AND a.attname = 'workspace_id' AND NOT a.attisdropped) THEN
            CONTINUE;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_constraint k
                    WHERE k.conrelid = ('public.' || spec[1])::regclass AND k.conname = spec[2]) THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (%s) '
            'REFERENCES public.%I (%s) ON DELETE CASCADE NOT VALID',
            spec[1], spec[2], spec[3], spec[4], spec[5]);
    END LOOP;
END $$;

-- 3. workspace_id required on new writes.
DO $$
DECLARE
    t text;
    cname text;
    has_null boolean;
    has_trigger boolean;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'users', 'delegation_policies', 'delegation_tokens',
        'services', 'credentials', 'mfa_methods',
        'oauth_scope_permissions', 'mcp_tool_scope_map', 'spire_workloads'
    ] LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            RAISE NOTICE 'tenancy contract: table % does not exist, skipped', t;
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_attribute a
                        WHERE a.attrelid = ('public.' || t)::regclass
                          AND a.attname = 'workspace_id' AND NOT a.attisdropped) THEN
            CONTINUE;
        END IF;
        cname := 'ck_' || t || '_tenancy_ws_nn';
        has_trigger := EXISTS (SELECT 1 FROM pg_trigger g
                                WHERE g.tgrelid = ('public.' || t)::regclass
                                  AND g.tgname = 'trg_tenancy_require_ws');
        IF EXISTS (SELECT 1 FROM pg_constraint k
                    WHERE k.conrelid = ('public.' || t)::regclass AND k.conname = cname) THEN
            IF has_trigger THEN
                EXECUTE format('DROP TRIGGER trg_tenancy_require_ws ON public.%I', t);
            END IF;
            CONTINUE;
        END IF;
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE workspace_id IS NULL)', t)
           INTO has_null;
        IF has_null THEN
            RAISE NOTICE 'tenancy contract: % has rows without workspace_id; guarding new writes with a trigger', t;
            EXECUTE format(
                'CREATE OR REPLACE TRIGGER trg_tenancy_require_ws BEFORE INSERT OR UPDATE ON public.%I '
                'FOR EACH ROW EXECUTE FUNCTION public.tenancy_require_workspace_id()', t);
        ELSE
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (workspace_id IS NOT NULL) NOT VALID',
                t, cname);
            IF has_trigger THEN
                EXECUTE format('DROP TRIGGER trg_tenancy_require_ws ON public.%I', t);
            END IF;
        END IF;
    END LOOP;
END $$;
