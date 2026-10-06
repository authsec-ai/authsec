-- ============================================================================
-- 045: tenancy expand -- workspace_id on tenant data that had none
--
-- ADR-0001 §6 step 2 (AS-051). Adds a NULLABLE workspace_id to tenant data
-- that carried no workspace at all:
--   services, credentials (WebAuthn), mfa_methods,
--   role_permissions, oauth_scope_permissions, mcp_tool_scope_map,
--   spire_oidc_tokens, spire_policies, spire_policy_rules,
--   spire_policy_subjects, spire_policy_resources, spire_policy_actions,
--   spire_policy_conditions, spire_role_bindings, spire_workloads.
-- spire_audit_logs already has a (text) workspace_id and is not touched.
--
-- mcp_oauth_clients gets NO owner_workspace_id. Its home_workspace_id already
-- records the owning workspace: it is set at creation for workspace-created
-- clients (service accounts, machine access, discovery claims) and stamped
-- once, guarded by "WHERE home_workspace_id IS NULL", on first bind for
-- DCR/CIMD clients (services/oauth_as_service.go BindClientToRS). NULL means
-- a platform client (e.g. the hosted login UI) or a DCR/CIMD client that is
-- not adopted yet; those serve several workspaces by design, and
-- authorization comes from the approved resource_server_client_registrations
-- row in the resource server's workspace. A second column with the same
-- meaning would only drift.
--
-- Also adds:
--   * tenancy_backfill_orphans -- rows 046 cannot attribute are reported
--     here, never guessed and never assigned to a customer workspace;
--   * tenancy_workspace_for_user_ref(uuid) -- the single attribution rule for
--     rows keyed by a legacy user/client id (credentials, mfa_methods,
--     services.created_by);
--   * fill triggers, so rows written by existing code from now on are
--     attributed with the same rule the backfill uses. The join tables take
--     the workspace of their parent; credentials and mfa_methods take the
--     workspace of their user. A supplied workspace_id is never overwritten:
--     if it disagrees with the parent, the composite FKs added in 047 reject
--     the row.
--
-- Additive and idempotent: nullable columns, a new table, functions and
-- triggers. Tables missing on a drifted database are skipped, not failed.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.tenancy_backfill_orphans (
    table_name  text        NOT NULL,
    row_id      text        NOT NULL,
    reason      text        NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (table_name, row_id)
);

COMMENT ON TABLE public.tenancy_backfill_orphans IS
    'Rows the tenancy backfill (046) could not attribute to a workspace. '
    'Resolve each (fix the row or delete it), then re-run '
    'SELECT * FROM public.tenancy_backfill_workspace_ids(); and '
    'scripts/tenancy-validate.sql.';

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'services', 'credentials', 'mfa_methods',
        'role_permissions', 'oauth_scope_permissions', 'mcp_tool_scope_map',
        'spire_oidc_tokens', 'spire_policies', 'spire_policy_rules',
        'spire_policy_subjects', 'spire_policy_resources', 'spire_policy_actions',
        'spire_policy_conditions', 'spire_role_bindings', 'spire_workloads'
    ] LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            RAISE NOTICE 'tenancy expand: table % does not exist, skipped', t;
            CONTINUE;
        END IF;
        EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS workspace_id uuid', t);
    END LOOP;
END $$;

-- The workspace of the user a legacy reference points at.
--   1. ref is a users.id: that user's workspace;
--   2. otherwise ref is a users.client_id: the workspace shared by every user
--      with that client_id, only when there is exactly one and none is NULL.
-- The workspace must exist. Anything else returns NULL (unattributable).
CREATE OR REPLACE FUNCTION public.tenancy_workspace_for_user_ref(ref uuid)
RETURNS uuid
LANGUAGE sql
STABLE
AS $fn$
    SELECT CASE
        WHEN ref IS NULL THEN NULL
        WHEN EXISTS (SELECT 1 FROM public.users u WHERE u.id = ref) THEN (
            SELECT u.workspace_id
              FROM public.users u
              JOIN public.workspaces w ON w.id = u.workspace_id
             WHERE u.id = ref)
        ELSE (
            SELECT CASE
                       WHEN count(*) > 0
                        AND count(*) = count(w.id)
                        AND count(DISTINCT u.workspace_id) = 1
                       THEN min(u.workspace_id::text)::uuid
                   END
              FROM public.users u
              LEFT JOIN public.workspaces w ON w.id = u.workspace_id
             WHERE u.client_id = ref)
    END
$fn$;

-- credentials: keyed by client_id, which the write paths fill with users.id
-- (controllers/admin/workspace_admin_controller.go, repository/repository.go).
CREATE OR REPLACE FUNCTION public.tenancy_fill_ws_credentials()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF NEW.workspace_id IS NULL
       AND (TG_OP = 'INSERT' OR NEW.client_id IS DISTINCT FROM OLD.client_id) THEN
        NEW.workspace_id := public.tenancy_workspace_for_user_ref(NEW.client_id);
    END IF;
    RETURN NEW;
END
$fn$;

-- mfa_methods: user_id when set, else client_id. If both resolve and
-- disagree the row stays unattributed.
CREATE OR REPLACE FUNCTION public.tenancy_fill_ws_mfa_methods()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
DECLARE
    wu uuid;
    wc uuid;
BEGIN
    IF NEW.workspace_id IS NULL
       AND (TG_OP = 'INSERT'
            OR NEW.client_id IS DISTINCT FROM OLD.client_id
            OR NEW.user_id IS DISTINCT FROM OLD.user_id) THEN
        wu := public.tenancy_workspace_for_user_ref(NEW.user_id);
        wc := public.tenancy_workspace_for_user_ref(NEW.client_id);
        IF wu IS NULL OR wc IS NULL OR wu = wc THEN
            NEW.workspace_id := COALESCE(wu, wc);
        END IF;
    END IF;
    RETURN NEW;
END
$fn$;

-- role_permissions: the role's workspace. NULL for a platform (global) role.
-- The permission must be platform-owned (NULL or the system workspace) or
-- belong to the same workspace as the role.
CREATE OR REPLACE FUNCTION public.tenancy_fill_ws_role_permissions()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
DECLARE
    pws uuid;
BEGIN
    IF NEW.workspace_id IS NULL
       AND (TG_OP = 'INSERT' OR NEW.role_id IS DISTINCT FROM OLD.role_id) THEN
        SELECT r.workspace_id INTO NEW.workspace_id FROM public.roles r WHERE r.id = NEW.role_id;
    END IF;
    IF TG_OP = 'INSERT' OR NEW.permission_id IS DISTINCT FROM OLD.permission_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
        SELECT p.workspace_id INTO pws FROM public.permissions p WHERE p.id = NEW.permission_id;
        IF pws IS NOT NULL
           AND pws <> '00000000-0000-0000-0000-000000000000'::uuid
           AND pws IS DISTINCT FROM NEW.workspace_id THEN
            RAISE EXCEPTION 'tenancy: permission % belongs to another workspace than role %',
                NEW.permission_id, NEW.role_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$fn$;

-- oauth_scope_permissions: the scope's workspace, same permission rule.
CREATE OR REPLACE FUNCTION public.tenancy_fill_ws_oauth_scope_permissions()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
DECLARE
    pws uuid;
BEGIN
    IF NEW.workspace_id IS NULL
       AND (TG_OP = 'INSERT' OR NEW.scope_id IS DISTINCT FROM OLD.scope_id) THEN
        SELECT s.workspace_id INTO NEW.workspace_id FROM public.oauth_scopes s WHERE s.id = NEW.scope_id;
    END IF;
    IF TG_OP = 'INSERT' OR NEW.permission_id IS DISTINCT FROM OLD.permission_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
        SELECT p.workspace_id INTO pws FROM public.permissions p WHERE p.id = NEW.permission_id;
        IF pws IS NOT NULL
           AND pws <> '00000000-0000-0000-0000-000000000000'::uuid
           AND pws IS DISTINCT FROM NEW.workspace_id THEN
            RAISE EXCEPTION 'tenancy: permission % belongs to another workspace than scope %',
                NEW.permission_id, NEW.scope_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$fn$;

-- mcp_tool_scope_map: the tool's workspace. The composite FKs in 047 then
-- require the scope to be in that same workspace.
CREATE OR REPLACE FUNCTION public.tenancy_fill_ws_mcp_tool_scope_map()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF NEW.workspace_id IS NULL
       AND (TG_OP = 'INSERT' OR NEW.tool_id IS DISTINCT FROM OLD.tool_id) THEN
        SELECT t.workspace_id INTO NEW.workspace_id FROM public.mcp_tools t WHERE t.id = NEW.tool_id;
    END IF;
    RETURN NEW;
END
$fn$;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'credentials', 'mfa_methods',
        'role_permissions', 'oauth_scope_permissions', 'mcp_tool_scope_map'
    ] LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'CREATE OR REPLACE TRIGGER trg_tenancy_fill_ws BEFORE INSERT OR UPDATE ON public.%I '
            'FOR EACH ROW EXECUTE FUNCTION public.%I()',
            t, 'tenancy_fill_ws_' || t);
    END LOOP;
END $$;
