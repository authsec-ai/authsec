-- ============================================================================
-- Forward delta: adds the identity/audit + workspace-provider-app tables to a
-- LIVE database without a wipe. Run once (idempotent):
--     psql "$DATABASE_URL" -f connector_identity_credstore.sql
--
-- Pairs with the code that adds:
--   - connector_action_audit  (durable who/act/token/outcome per broker action)
--   - connector_provider_apps (per-workspace OAuth app: client_id in PG, secret in Vault)
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- connector_action_audit ---------------------------------------------------
CREATE TABLE IF NOT EXISTS public.connector_action_audit (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    connector_id    uuid,
    action_key      text NOT NULL,
    outcome         text NOT NULL,               -- 'allow' | 'deny'
    deny_reason     text,
    subject_type    text,                        -- 'user' | 'service_account'
    subject_id      uuid,                        -- the principal (sub) — who
    actor_client_id text,                        -- the acting agent (act) — on behalf of
    actor_spiffe_id text,
    token_family    text,                        -- m2m | xaa | ciba — which token
    token_jti       text,
    http_status     int,
    latency_ms      bigint,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_action_audit_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_connector_action_audit_ws        ON public.connector_action_audit(workspace_id);
CREATE INDEX IF NOT EXISTS idx_connector_action_audit_connector ON public.connector_action_audit(connector_id, created_at DESC);

-- connector_provider_apps ---------------------------------------------------
CREATE TABLE IF NOT EXISTS public.connector_provider_apps (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    provider_key  text NOT NULL,
    client_id     text NOT NULL,
    redirect_uri  text NOT NULL,
    vault_path    text NOT NULL,               -- Vault location of client_secret
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_provider_apps_pkey PRIMARY KEY (id),
    CONSTRAINT connector_provider_apps_ws_provider_key UNIQUE (workspace_id, provider_key)
);

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.connector_action_audit')  AS action_audit,
       to_regclass('public.connector_provider_apps') AS provider_apps;
