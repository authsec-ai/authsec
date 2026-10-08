-- ============================================================================
-- 106: tenancy indexes and per-workspace uniques
--
-- ADR-0001 §6 steps 4-5 (AS-052, AS-060).
--
-- 1. A workspace_id-leading index on every table with a uuid workspace_id that
--    has none (idx_<table>_tenancy_ws). Found from the catalog, so tables that
--    exist only through 027-042, or that drifted, are covered too. Plain
--    CREATE INDEX: the runner wraps each migration in a transaction, where
--    CONCURRENTLY is not allowed.
--
-- 2. Global uniques replaced by per-workspace ones. The new unique is created
--    first; it is strictly weaker than the global one it replaces, so existing
--    data satisfies it. Each step checks for duplicates anyway and skips with
--    a NOTICE (leaving the global unique in place) if it finds any.
--      totp_backup_codes            UNIQUE (code)
--        -> UNIQUE (workspace_id, user_id, code)
--      workspace_totp_backup_codes  UNIQUE (code)
--        -> UNIQUE (workspace_id, user_id, code)
--         Backup codes are per-user secrets; every lookup is by
--         (code, user_id, workspace_id). A global unique made two users'
--         codes collide across workspaces and the violation an oracle.
--      workspace_device_tokens      UNIQUE (device_token) dropped; the
--         existing UNIQUE (device_token, workspace_id) (fk_workspace_device_token)
--         stays. Lookups are by (device_token, workspace_id); nothing uses
--         ON CONFLICT (device_token) on this table (the ON CONFLICT in
--         database/ciba_auth_repository.go is on device_tokens, unchanged).
--
--    Kept global, on purpose -- code resolves these before a workspace is known,
--    so a per-workspace unique would make the lookup ambiguous across tenants:
--      resource_servers.resource_uri (idx_resource_servers_resource_uri_active)
--         The OAuth AS resolves the RFC 8707 resource / token audience by URI
--         alone: ResourceServerService.GetByResourceURI, called from
--         oauth_as_controller.go (authorize, token, introspection, discovery)
--         and connector_broker_controller.go; CreateResourceServer pre-checks
--         the URI globally. Per-workspace URIs need those to resolve through
--         the client's registration first.
--      workload_identity_providers.issuer (uq_wip_issuer)
--         services/client_auth.go authenticateSPIFFESVID picks the provider by
--         the SVID's iss alone, then binds to that provider's workspace.
--      service_accounts.spiffe_id (uq_sa_spiffe),
--      application_spiffe_identities.spiffe_id
--         The legacy global SPIFFE_OIDC_ISSUER path maps an SVID sub to a
--         service account across workspaces; spire_controller upserts
--         application identities by spiffe_id. AuthSec-minted IDs embed the
--         workspace, so collisions need federated IDs.
--      trusted_issuers.iss -- ID-JAG validation looks the issuer up first.
--      spire_workloads.spiffe_id, spire_policies.name -- the SPIRE engine
--         looks them up globally.
--
-- Idempotent.
-- ============================================================================

-- 1. workspace_id-leading index where missing.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.relname, a.attnum
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
          JOIN pg_attribute a ON a.attrelid = c.oid
                             AND a.attname = 'workspace_id'
                             AND NOT a.attisdropped
                             AND a.atttypid = 'uuid'::regtype
         WHERE c.relkind = 'r'
           AND NOT EXISTS (SELECT 1 FROM pg_index i
                            WHERE i.indrelid = c.oid AND i.indkey[0] = a.attnum)
         ORDER BY c.relname
    LOOP
        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON public.%I (workspace_id)',
                       'idx_' || r.relname || '_tenancy_ws', r.relname);
    END LOOP;
END $$;

-- 2a. TOTP backup codes: per user within a workspace.
DO $$
DECLARE
    t text;
    uq text;
    old text;
    dup boolean;
BEGIN
    FOREACH t IN ARRAY ARRAY['totp_backup_codes', 'workspace_totp_backup_codes'] LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            RAISE NOTICE 'tenancy uniques: table % does not exist, skipped', t;
            CONTINUE;
        END IF;
        uq := 'uq_' || t || '_ws_user_code';
        old := t || '_code_key';
        IF NOT EXISTS (SELECT 1 FROM pg_constraint k
                        WHERE k.conrelid = ('public.' || t)::regclass AND k.conname = uq) THEN
            EXECUTE format(
                'SELECT EXISTS (SELECT 1 FROM public.%I GROUP BY workspace_id, user_id, code HAVING count(*) > 1)',
                t) INTO dup;
            IF dup THEN
                RAISE NOTICE 'tenancy uniques: % has duplicate (workspace_id, user_id, code); global unique kept', t;
                CONTINUE;
            END IF;
            EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I UNIQUE (workspace_id, user_id, code)', t, uq);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_constraint k
                    WHERE k.conrelid = ('public.' || t)::regclass AND k.conname = old) THEN
            EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', t, old);
        END IF;
    END LOOP;
END $$;

-- 2b. workspace_device_tokens: drop the redundant global unique.
DO $$
DECLARE
    dup boolean;
BEGIN
    IF to_regclass('public.workspace_device_tokens') IS NULL THEN
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint k
                    WHERE k.conrelid = 'public.workspace_device_tokens'::regclass
                      AND k.conname = 'fk_workspace_device_token') THEN
        SELECT EXISTS (SELECT 1 FROM public.workspace_device_tokens
                        GROUP BY device_token, workspace_id HAVING count(*) > 1) INTO dup;
        IF dup THEN
            RAISE NOTICE 'tenancy uniques: workspace_device_tokens has duplicate (device_token, workspace_id); global unique kept';
            RETURN;
        END IF;
        ALTER TABLE public.workspace_device_tokens
            ADD CONSTRAINT fk_workspace_device_token UNIQUE (device_token, workspace_id);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint k
                WHERE k.conrelid = 'public.workspace_device_tokens'::regclass
                  AND k.conname = 'workspace_device_tokens_device_token_key') THEN
        ALTER TABLE public.workspace_device_tokens
            DROP CONSTRAINT workspace_device_tokens_device_token_key;
    END IF;
END $$;
