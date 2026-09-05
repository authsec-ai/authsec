-- ============================================================================
-- AuthSec v4 — Master DB Bootstrap
-- ============================================================================
-- A single, self-contained schema definition for a fresh AuthSec database.
-- Brings up the entire v4 schema in one transaction: tables (80), constraints,
-- indexes, triggers, the 7 trigger functions that fire on UPDATE, and seeds
-- the system workspace + base permissions. After this file runs, the DB is ready
-- to accept the first admin signup.
--
-- This is NOT a pg_dump output — it's a hand-curated single-state schema.
-- Every column lives in its CREATE TABLE statement (no ALTER TABLE ADD COLUMN
-- anywhere in this file). Future schema evolution lands as 002_*.sql,
-- 003_*.sql files alongside this one; the migration runner applies them
-- incrementally on top of an already-bootstrapped database.
--
-- GORM/SQL schema ownership:
--   The Go migration runner (internal/migration/runner.go) needs the
--   `migration_logs` table to exist before it can record migration outcomes,
--   so cmd/main.go calls `migration.AutoMigrateMigrationLogs(config.DB)` via
--   GORM BEFORE running this file. That is the ONLY table GORM is allowed to
--   manage. Everything else — including the spire_* family — is owned here.
-- ============================================================================

-- Only set what's actually needed:
--   * check_function_bodies = off lets us CREATE FUNCTION before its
--     referenced tables exist (some trigger fns reference late tables)
SET check_function_bodies = false;

-- *not* creating schema, since initdb creates it

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.update_device_codes_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.update_oidc_providers_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.update_oidc_user_identities_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.update_voice_identity_links_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.update_voice_sessions_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.agent_action_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    action_request_id uuid,
    agent_id character varying(255) NOT NULL,
    agent_name character varying(255),
    user_id uuid NOT NULL,
    user_email character varying(255) NOT NULL,
    action character varying(255) NOT NULL,
    resource character varying(255) NOT NULL,
    detail text,
    metadata jsonb DEFAULT '{}'::jsonb,
    risk_score integer NOT NULL,
    risk_level character varying(20) NOT NULL,
    final_status character varying(50) NOT NULL,
    decided_by jsonb DEFAULT '[]'::jsonb,
    requested_at bigint NOT NULL,
    decided_at bigint,
    execution_duration_ms bigint,
    created_at bigint NOT NULL,
    CONSTRAINT agent_action_audit_log_pkey PRIMARY KEY (id)
);

CREATE TABLE public.agent_action_decisions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action_request_id uuid NOT NULL,
    approver_user_id uuid NOT NULL,
    approver_email character varying(255) NOT NULL,
    decision character varying(20) NOT NULL,
    reason text,
    biometric_verified boolean DEFAULT false,
    created_at bigint NOT NULL,
    CONSTRAINT agent_action_decisions_pkey PRIMARY KEY (id),
    CONSTRAINT uq_agent_action_decision_per_user UNIQUE (action_request_id, approver_user_id)
);

CREATE TABLE public.agent_action_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action_req_id character varying(255) NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    user_email character varying(255) NOT NULL,
    agent_id character varying(255) NOT NULL,
    agent_name character varying(255),
    agent_framework character varying(100),
    session_id character varying(255),
    action character varying(255) NOT NULL,
    resource character varying(255) NOT NULL,
    detail text,
    metadata jsonb DEFAULT '{}'::jsonb,
    risk_score integer NOT NULL,
    risk_level character varying(20) NOT NULL,
    risk_factors jsonb DEFAULT '[]'::jsonb,
    matched_policy_id uuid,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    approval_type character varying(20),
    required_approvals integer DEFAULT 1,
    received_approvals integer DEFAULT 0,
    ciba_auth_req_id character varying(255),
    device_token_id uuid,
    expires_at bigint NOT NULL,
    created_at bigint NOT NULL,
    decided_at bigint,
    last_polled_at bigint,
    CONSTRAINT agent_action_requests_action_req_id_key UNIQUE (action_req_id),
    CONSTRAINT agent_action_requests_pkey PRIMARY KEY (id)
);

CREATE TABLE public.agent_guard_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    auto_approve_below integer DEFAULT 30,
    require_approval_above integer DEFAULT 31,
    require_multi_approval_above integer DEFAULT 81,
    approval_timeout_seconds integer DEFAULT 300,
    polling_interval_seconds integer DEFAULT 5,
    business_hours_start integer DEFAULT 9,
    business_hours_end integer DEFAULT 17,
    business_hours_timezone character varying(50) DEFAULT 'UTC'::character varying,
    default_approver_user_id uuid,
    require_biometric boolean DEFAULT true,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT agent_guard_settings_pkey PRIMARY KEY (id),
    CONSTRAINT agent_guard_settings_workspace_id_key UNIQUE (workspace_id)
);

CREATE TABLE public.audit_events (
    id bigint NOT NULL,
    request_id text,
    workspace_id text,
    -- actor_realm separates "which login surface" (admin / enduser / service /
    -- system) from workspace identity. Previously workspace_id was overloaded
    -- with the literals "admin"/"enduser"; that pollution is gone — workspace_id
    -- now holds a real workspace UUID or is empty for pre-auth events.
    actor_realm text,
    user_id text,
    action text,
    resource text,
    resource_id text,
    method text,
    path text,
    user_agent text,
    client_ip text,
    status_code bigint,
    duration bigint,
    old_values jsonb,
    new_values jsonb,
    error text,
    "timestamp" timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT audit_events_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;

-- Authorization decision logs — dedicated table for PDP audit trail.
-- Records every allow/deny decision made by the ScopeResolver at consent time.
-- Enterprise buyers expect this for compliance and incident investigation.
CREATE TABLE public.authorization_decision_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    request_id text,
    user_id uuid,
    oauth_client_id uuid,
    resource_server_id uuid,
    action text,
    requested_scopes text[],
    granted_scopes text[],
    blocked_scopes text[],
    decision text NOT NULL,
    reason text,
    policy_snapshot jsonb,
    ip_address text,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT authorization_decision_logs_decision_chk CHECK (decision IN ('allow', 'deny', 'partial'))
);

CREATE INDEX idx_authz_decision_workspace ON public.authorization_decision_logs(workspace_id);
CREATE INDEX idx_authz_decision_user ON public.authorization_decision_logs(user_id);
CREATE INDEX idx_authz_decision_rs ON public.authorization_decision_logs(resource_server_id);
CREATE INDEX idx_authz_decision_created ON public.authorization_decision_logs(created_at DESC);

CREATE TABLE public.auth_request_contexts (
    state character varying(255) NOT NULL,
    hydra_client_id character varying(255) NOT NULL,
    resource_server_id uuid NOT NULL,
    resource_uri text NOT NULL,
    redirect_uri text,
    requested_scopes text,
    login_challenge text,
    expires_at timestamp with time zone NOT NULL,
    consumed boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    context_id character varying(255),
    consent_completed boolean DEFAULT false,
    hydra_request_uri character varying(512),
    nonce text,
    prompt character varying(64),
    max_age integer,
    auth_time timestamp without time zone,
    workspace_id uuid NOT NULL,
    CONSTRAINT auth_request_contexts_pkey PRIMARY KEY (state)
);

CREATE TABLE public.ciba_auth_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    auth_req_id character varying(255) NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    user_email character varying(255) NOT NULL,
    client_id uuid,
    device_token_id uuid NOT NULL,
    binding_message character varying(255),
    scopes jsonb DEFAULT '[]'::jsonb,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    biometric_verified boolean DEFAULT false,
    expires_at bigint NOT NULL,
    created_at bigint NOT NULL,
    responded_at bigint,
    last_polled_at bigint,
    CONSTRAINT ciba_auth_requests_auth_req_id_key UNIQUE (auth_req_id),
    CONSTRAINT ciba_auth_requests_pkey PRIMARY KEY (id)
);

-- Phase B: public.clients table removed. Legacy v3 concept that conflated
-- "MCP server" (now resource_servers) with "OAuth client" (now mcp_oauth_clients).
-- Agent + delegation + client-management flows that still query it are documented
-- in RESIDUAL_AGENTS_WORK.md as known-broken pending migration.

CREATE TABLE public.credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    attestation_type character varying(255),
    aaguid uuid,
    sign_count bigint DEFAULT 0,
    transports text[],
    backup_eligible boolean DEFAULT false,
    backup_state boolean DEFAULT false,
    rp_id character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT credentials_credential_id_key UNIQUE (credential_id),
    CONSTRAINT credentials_pkey PRIMARY KEY (id)
);

CREATE TABLE public.delegation_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_name text NOT NULL,
    agent_type text NOT NULL,
    allowed_permissions jsonb DEFAULT '[]'::jsonb,
    max_ttl_seconds integer DEFAULT 3600 NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    client_id uuid,
    workspace_id uuid,
    CONSTRAINT delegation_policies_pkey PRIMARY KEY (id),
    CONSTRAINT uq_deleg_policy_workspace_role_agent UNIQUE (workspace_id, role_name, agent_type)
);

CREATE TABLE public.delegation_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    policy_id uuid,
    token text NOT NULL,
    spiffe_id text NOT NULL,
    permissions jsonb DEFAULT '[]'::jsonb NOT NULL,
    audience jsonb DEFAULT '[]'::jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    delegated_by uuid NOT NULL,
    ttl_seconds integer NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_deleg_token_status CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'revoked'::text]))),
    workspace_id uuid,
    CONSTRAINT delegation_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT uq_delegation_token_client UNIQUE (workspace_id, client_id)
);

CREATE TABLE public.device_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid,
    client_id uuid,
    device_code character varying(128) NOT NULL,
    user_code character varying(16) NOT NULL,
    verification_uri text NOT NULL,
    verification_uri_complete text,
    user_id uuid,
    user_email text,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb,
    device_info jsonb,
    expires_at bigint NOT NULL,
    last_polled_at bigint,
    authorized_at bigint,
    created_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    updated_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    workspace_domain text,
    access_token text,
    CONSTRAINT chk_device_codes_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'authorized'::character varying, 'denied'::character varying, 'expired'::character varying, 'consumed'::character varying])::text[]))),
    CONSTRAINT device_codes_device_code_key UNIQUE (device_code),
    CONSTRAINT device_codes_pkey PRIMARY KEY (id),
    CONSTRAINT device_codes_user_code_key UNIQUE (user_code)
);

CREATE TABLE public.device_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    device_token character varying(500) NOT NULL,
    platform character varying(20) NOT NULL,
    device_name character varying(100),
    device_model character varying(100),
    app_version character varying(20),
    os_version character varying(20),
    is_active boolean DEFAULT true NOT NULL,
    last_used bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT device_tokens_device_token_key UNIQUE (device_token),
    CONSTRAINT device_tokens_pkey PRIMARY KEY (id)
);

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    -- Every group is owned by exactly one workspace. There are no platform/global
    -- groups: group creation always sets workspace_id and the user_groups FK is
    -- composite on (group_id, workspace_id).
    workspace_id uuid NOT NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_workspace_id_id_key UNIQUE (workspace_id, id),
    CONSTRAINT uni_groups_workspace_name UNIQUE (workspace_id, name)
);

CREATE TABLE public.mcp_oauth_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id character varying(512) NOT NULL,
    hydra_client_id character varying(255) NOT NULL,
    client_name character varying(255),
    redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    grant_types text[] DEFAULT '{authorization_code}'::text[] NOT NULL,
    response_types text[] DEFAULT '{code}'::text[] NOT NULL,
    token_endpoint_auth_method character varying(50) DEFAULT 'none'::character varying,
    scope text,
    registration_type character varying(20) DEFAULT 'dcr'::character varying NOT NULL,
    cimd_url text,
    cimd_cached_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    pending_redirect_uris text[] DEFAULT '{}'::text[],
    redirect_review_pending boolean DEFAULT false,
    post_logout_redirect_uris text[] DEFAULT '{}'::text[],
    supports_refresh_token boolean DEFAULT false,
    is_confidential boolean DEFAULT false,
    sync_status text DEFAULT 'active'::text NOT NULL,
    sync_last_error text,
    sync_last_error_at timestamp with time zone,
    client_kind            VARCHAR(32) NOT NULL DEFAULT 'human_app'
                           CHECK (client_kind IN ('human_app','agent','m2m','cli')),
    software_id            VARCHAR(255),
    software_version       VARCHAR(64),
    last_token_issued_at   TIMESTAMPTZ,
    tags                   TEXT[] NOT NULL DEFAULT '{}'::text[],
    registration_access_token_hash VARCHAR(64),
    -- Home workspace: stamped at registration when the workspace is known
    -- (DCR with resource / prereg) or adopted on first lazy bind at /authorize.
    -- NULL = unbound (fresh DCR-without-resource or CIMD client). Lazy binds to
    -- an RS in a DIFFERENT workspace create the registration as
    -- pending_approval instead of approved. FK added in the constraints
    -- section below (workspaces is created later in this file).
    home_workspace_id      UUID,
    -- Authoritative confidential-client state (specifics (g)). Runtime auth, metadata,
    -- and the promotion endpoint read ONLY this array. Legacy token_endpoint_auth_method
    -- + is_confidential become derived mirrors; nothing writes them directly.
    allowed_token_endpoint_auth_methods text[] NOT NULL DEFAULT ARRAY['none'::text],
    CONSTRAINT mcp_oauth_clients_sync_status_chk CHECK (sync_status IN ('active', 'sync_error', 'pending_delete')),
    CONSTRAINT mcp_oauth_clients_client_id_key UNIQUE (client_id),
    CONSTRAINT mcp_oauth_clients_hydra_client_id_key UNIQUE (hydra_client_id),
    -- The accountable human for this agent, and its governance state.
    -- governance_status is what a HUMAN decided about the agent's authority; it is
    -- orthogonal to discovered_agents.runtime_status, which is what we OBSERVED
    -- about its workload. An agent can be governance-active and runtime-gone.
    owner_user_id uuid,
    governance_status text NOT NULL DEFAULT 'ungoverned'
        CONSTRAINT mcp_oauth_clients_governance_status_chk
        CHECK (governance_status IN ('ungoverned', 'active', 'suspended', 'deprovisioned')),
    CONSTRAINT mcp_oauth_clients_pkey PRIMARY KEY (id)
);

-- Pre-seeded demo OAuth client (registration_type='prereg') — used by the hosted
-- login UI to self-initiate OAuth flows in dev/test. NOT used by direct login flows.
INSERT INTO public.mcp_oauth_clients (
    id,
    client_id,
    hydra_client_id,
    client_name,
    redirect_uris,
    grant_types,
    response_types,
    token_endpoint_auth_method,
    scope,
    registration_type,
    sync_status,
    sync_last_error,
    created_at,
    updated_at
) VALUES (
    'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    'authsec-login-ui',
    'authsec-login-ui',
    'AuthSec Login UI',
    ARRAY['http://localhost:3000/oidc/auth/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['code'],
    'none',
    'openid profile email offline_access',
    'prereg',
    -- Seed as 'sync_error' (NOT 'active') so the Hydra reconciler picks this row up
    -- on its next tick and creates the matching Hydra client. tick() only scans
    -- sync_status IN ('sync_error','pending_delete'); an 'active' seed would be
    -- skipped forever and the Hydra client would never be created.
    'sync_error',
    'awaiting initial hydra client creation by reconciler',
    NOW(),
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- Agent Identity Phase 2: confidential-client credential stores
-- These tables back the allowed_token_endpoint_auth_methods array on
-- mcp_oauth_clients. The promotion endpoint writes here; authenticateClient
-- reads here. RFC 7592 PUT remains immutable (cannot change auth methods).
-- ─────────────────────────────────────────────────────────────────────────────

-- Client secrets for client_secret_basic / client_secret_post.
-- secret_hash is bcrypt. At most one active (revoked_at IS NULL) secret per client.
CREATE TABLE public.oauth_client_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    secret_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT oauth_client_secrets_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_client_secrets_client_fkey
        FOREIGN KEY (client_id) REFERENCES public.mcp_oauth_clients(id) ON DELETE CASCADE
);
CREATE INDEX idx_oauth_client_secrets_active ON public.oauth_client_secrets(client_id)
    WHERE revoked_at IS NULL;

-- Client JWKS for private_key_jwt. One row per client (uq).
-- jwks_uri takes precedence; jwks is the last-fetched copy (refresh cache).
CREATE TABLE public.oauth_client_jwks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    jwks_uri text,
    jwks jsonb,
    last_fetched_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oauth_client_jwks_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_client_jwks_client_uq UNIQUE (client_id),
    CONSTRAINT oauth_client_jwks_client_fkey
        FOREIGN KEY (client_id) REFERENCES public.mcp_oauth_clients(id) ON DELETE CASCADE
);

-- Replay cache for private_key_jwt client assertions (jti uniqueness).
-- Rows expire naturally; a periodic cleaner can prune expires_at < NOW().
CREATE TABLE public.client_assertion_replay_cache (
    client_id text NOT NULL,
    jti text NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT client_assertion_replay_cache_pkey PRIMARY KEY (client_id, jti)
);
CREATE INDEX idx_client_assertion_replay_exp ON public.client_assertion_replay_cache(expires_at);

CREATE TABLE public.mcp_tool_scope_map (
    tool_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    auto_matched boolean DEFAULT true NOT NULL,
    source text DEFAULT 'admin_override'::text NOT NULL,
    CONSTRAINT mcp_tool_scope_map_source_check CHECK ((source = ANY (ARRAY['sdk_suggested'::text, 'admin_override'::text]))),
    CONSTRAINT mcp_tool_scope_map_pkey PRIMARY KEY (tool_id, scope_id)
);

CREATE TABLE public.mcp_tools (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    resource_server_id uuid NOT NULL,
    name text NOT NULL,
    title text,
    description text,
    input_schema jsonb,
    annotations jsonb,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    last_scan_generation integer DEFAULT 0 NOT NULL,
    inventory_source text DEFAULT 'mcp_scan'::text NOT NULL,
    suggested_scopes text[] DEFAULT '{}'::text[] NOT NULL,
    is_public boolean DEFAULT false NOT NULL,
    is_public_acknowledged_by uuid,
    CONSTRAINT mcp_tools_inventory_source_check CHECK ((inventory_source = ANY (ARRAY['mcp_scan'::text, 'sdk_manifest'::text, 'manual'::text]))),
    CONSTRAINT mcp_tools_pkey PRIMARY KEY (id),
    CONSTRAINT mcp_tools_id_workspace_uq UNIQUE (id, workspace_id),
    CONSTRAINT mcp_tools_resource_server_id_name_key UNIQUE (resource_server_id, name)
);

CREATE TABLE public.mfa_methods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid,
    method_type character varying(50) NOT NULL,
    display_name character varying(255),
    description character varying(255),
    recommended boolean DEFAULT false,
    method_data jsonb,
    enabled boolean DEFAULT false,
    method_subtype character varying(255),
    is_primary boolean DEFAULT false,
    verified boolean DEFAULT false,
    backup_codes text,
    enrolled_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT mfa_methods_client_id_method_type_key UNIQUE (client_id, method_type),
    CONSTRAINT mfa_methods_pkey PRIMARY KEY (id)
);

-- migration_logs table is created by the Go migration runner via GORM AutoMigrate
-- BEFORE this bootstrap runs (internal/migration/db_utils.go:AutoMigrateMigrationLogs).
-- DO NOT add a CREATE TABLE for it here — it would collide and abort the bootstrap.

CREATE TABLE public.oauth_consent_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    oauth_client_id uuid NOT NULL,
    resource_server_id uuid NOT NULL,
    granted_scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_consent_grants_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_consent_grants_workspace_user_client_rs_uq UNIQUE (workspace_id, user_id, oauth_client_id, resource_server_id)
);

CREATE TABLE public.oauth_scope_permissions (
    scope_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    CONSTRAINT oauth_scope_permissions_pkey PRIMARY KEY (scope_id, permission_id)
);

CREATE TABLE public.oauth_scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    resource_server_id uuid,
    scope_string text NOT NULL,
    display_name text NOT NULL,
    description text,
    icon text,
    risk_level text DEFAULT 'low'::text NOT NULL,
    parent_scope_id uuid,
    is_auto_discovered boolean DEFAULT false NOT NULL,
    source text DEFAULT 'discovered'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_scopes_risk_level_check CHECK ((risk_level = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text]))),
    CONSTRAINT oauth_scopes_source_check CHECK ((source = ANY (ARRAY['discovered'::text, 'preset'::text, 'manifest'::text, 'manual'::text]))),
    CONSTRAINT oauth_scopes_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_scopes_id_workspace_uq UNIQUE (id, workspace_id),
    CONSTRAINT oauth_scopes_workspace_id_resource_server_id_scope_string_key UNIQUE (workspace_id, resource_server_id, scope_string)
);

CREATE TABLE public.oidc_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_name character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret_vault_path character varying(255) NOT NULL,
    authorization_url character varying(500) NOT NULL,
    token_url character varying(500) NOT NULL,
    userinfo_url character varying(500) NOT NULL,
    scopes text DEFAULT 'openid email profile'::text,
    icon_url character varying(500),
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    workspace_id uuid,  -- NULL = platform-level provider available to all workspaces
    display_name_override text,
    redirect_uri text,
    CONSTRAINT oidc_providers_pkey PRIMARY KEY (id)
);

-- Platform OIDC providers: none seeded by default.
-- Workspace admins can configure providers via the Authentication page.

CREATE TABLE public.oidc_states (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    state_token character varying(255) NOT NULL,
    workspace_id uuid,              -- NULL for platform-level login (before workspace exists)
    workspace_domain character varying(255),
    provider_name character varying(50) NOT NULL,
    action character varying(20) NOT NULL,
    code_verifier character varying(128),
    redirect_after character varying(500),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    request_host character varying(255),
    application_id uuid,
    signed_state text,
    login_challenge text,
    CONSTRAINT oidc_states_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_states_state_token_key UNIQUE (state_token)
);

CREATE TABLE public.oidc_user_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider_name character varying(50) NOT NULL,
    provider_user_id character varying(255) NOT NULL,
    email character varying(255),
    profile_data jsonb DEFAULT '{}'::jsonb,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT oidc_user_identities_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_user_identities_workspace_provider_unique UNIQUE (workspace_id, provider_name, provider_user_id),
    CONSTRAINT oidc_user_identities_workspace_user_provider_unique UNIQUE (workspace_id, user_id, provider_name)
);

CREATE TABLE public.otp_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    otp character varying(10) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    verified boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT otp_entries_pkey PRIMARY KEY (id)
);

CREATE TABLE public.pending_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    password_hash text NOT NULL,
    first_name character varying(100) DEFAULT ''::character varying,
    last_name character varying(100) DEFAULT ''::character varying,
    workspace_id uuid NOT NULL,
    -- project_id is legacy (projects table is Phase E to delete); nullable so
    -- registrations without a project still succeed.
    project_id uuid,
    -- client_id removed (Phase A): OAuth client is global, not workspace-owned.
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    workspace_domain character varying(255) NOT NULL,
    CONSTRAINT pending_registrations_pkey PRIMARY KEY (id)
);

CREATE TABLE public.permissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    resource text NOT NULL,
    action text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    full_permission_string text,
    workspace_id uuid,
    CONSTRAINT permissions_pkey PRIMARY KEY (id),
    CONSTRAINT permissions_id_workspace_uq UNIQUE (id, workspace_id),
    CONSTRAINT permissions_workspace_resource_action_key UNIQUE (workspace_id, resource, action)
);

CREATE TABLE public.pkce_verifiers (
    key character varying(512) NOT NULL,
    verifier text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT pkce_verifiers_pkey PRIMARY KEY (key)
);

CREATE TABLE public.resource_server_access_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    resource_server_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    default_role_id uuid,
    assignment_trigger text DEFAULT 'first_successful_login'::text NOT NULL,
    assignment_source text DEFAULT 'default_policy'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_server_access_policies_pkey PRIMARY KEY (id),
    CONSTRAINT resource_server_access_policies_resource_server_id_key UNIQUE (resource_server_id)
);

CREATE TABLE public.resource_server_client_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    resource_server_id uuid NOT NULL,
    oauth_client_id uuid NOT NULL,
    status character varying(20) DEFAULT 'approved'::character varying NOT NULL,
    registration_type character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    workspace_id uuid NOT NULL,
    CONSTRAINT resource_server_client_regist_resource_server_id_oauth_clie_key UNIQUE (resource_server_id, oauth_client_id),
    CONSTRAINT resource_server_client_registrations_pkey PRIMARY KEY (id)
);

CREATE TABLE public.resource_server_drift_event_dismissals (
    event_id uuid NOT NULL,
    admin_user_id uuid NOT NULL,
    dismissed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_server_drift_event_dismissals_pkey PRIMARY KEY (event_id, admin_user_id)
);

CREATE TABLE public.resource_server_drift_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rs_id uuid NOT NULL,
    event_type text NOT NULL,
    event_payload jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    occurred_by uuid,
    CONSTRAINT resource_server_drift_events_event_type_check CHECK ((event_type = ANY (ARRAY['scope_deleted'::text, 'tool_unmapped'::text, 'default_role_disabled'::text, 'secret_rotated'::text]))),
    CONSTRAINT resource_server_drift_events_pkey PRIMARY KEY (id)
);

CREATE TABLE public.resource_server_manifest_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rs_id uuid NOT NULL,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL,
    status text NOT NULL,
    reason text,
    tool_count integer,
    manifest_version text,
    sdk_build_id text,
    CONSTRAINT resource_server_manifest_attempts_status_check CHECK ((status = ANY (ARRAY['success'::text, 'auth_failed'::text, 'invalid_payload'::text, 'empty_tool_list'::text, 'server_error'::text]))),
    CONSTRAINT resource_server_manifest_attempts_pkey PRIMARY KEY (id)
);

CREATE TABLE public.resource_servers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    public_base_url text NOT NULL,
    protected_base_path text DEFAULT '/mcp'::text NOT NULL,
    resource_uri text NOT NULL,
    scopes_supported text[] DEFAULT '{}'::text[],
    registration_modes text[] DEFAULT '{dcr,cimd,prereg}'::text[],
    introspection_secret text DEFAULT ''::text,
    active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    introspection_secret_hash text,
    status text DEFAULT 'pending_scan'::text NOT NULL,
    scan_generation integer DEFAULT 0 NOT NULL,
    last_successful_generation integer DEFAULT 0 NOT NULL,
    scan_in_progress boolean DEFAULT false NOT NULL,
    last_scan_status text,
    last_scan_error text,
    last_scan_started_at timestamp with time zone,
    last_scan_completed_at timestamp with time zone,
    last_validated_at timestamp with time zone,
    last_validation_status text,
    last_validation_error text,
    state text DEFAULT 'pending_scan'::text NOT NULL,
    setup_completed_at timestamp with time zone,
    setup_completed_by uuid,
    CONSTRAINT resource_servers_last_scan_status_check CHECK (((last_scan_status IS NULL) OR (last_scan_status = ANY (ARRAY['success'::text, 'failure'::text, 'partial'::text])))),
    CONSTRAINT resource_servers_state_check CHECK ((state = ANY (ARRAY['pending_scan'::text, 'needs_setup'::text, 'ready'::text, 'scan_failed'::text]))),
    CONSTRAINT resource_servers_status_check CHECK ((status = ANY (ARRAY['pending_scan'::text, 'ready'::text, 'degraded'::text]))),
    application_type text DEFAULT 'mcp_server'::text NOT NULL,
    legacy_client_id uuid,
    -- ai_agent state (RESIDUAL #40): an "agent" is a resource_servers row with
    -- application_type='ai_agent'. These columns hold its SPIRE identity + type.
    spiffe_id text,
    agent_type text,
    -- PRM (RFC 9728) manual-override escape hatch (plan §7): when a resource
    -- server can't serve /.well-known/oauth-protected-resource cleanly (un-patchable
    -- server / awkward proxy), an operator supplies scopes_supported manually.
    -- prm_source flips to 'manual_override' with prm_override_expires_at; a
    -- reconciler re-attempts the real fetch and auto-clears on success, or sets
    -- metadata_stale=true on expiry (existing tokens keep working; new scope
    -- changes are blocked until metadata refreshes).
    prm_source text DEFAULT 'fetched'::text NOT NULL,
    prm_override_expires_at timestamp with time zone,
    metadata_stale boolean DEFAULT false NOT NULL,
    -- managed: system-owned RS not created by an admin (e.g. the per-workspace
    -- Connector Broker). The Applications UI lists only managed=false rows.
    managed boolean DEFAULT false NOT NULL,
    CONSTRAINT resource_servers_prm_source_chk CHECK (prm_source IN ('fetched', 'manual_override')),
    CONSTRAINT resource_servers_application_type_chk CHECK (application_type IN ('mcp_server', 'ai_agent', 'clawbot', 'api_service', 'connector_broker')),
    -- governance ownership: certification routes a review to the owner of the thing
    -- the entitlement grants access to, so without this there is nobody to review.
    owner_user_id uuid,
    -- risk_tier drives certification frequency and review ordering.
    risk_tier text NOT NULL DEFAULT 'medium'
        CONSTRAINT resource_servers_risk_tier_chk
        CHECK (risk_tier IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT resource_servers_pkey PRIMARY KEY (id),
    CONSTRAINT resource_servers_id_workspace_uq UNIQUE (id, workspace_id),
    CONSTRAINT resource_servers_workspace_resource_uri_uq UNIQUE (workspace_id, resource_uri)
);

CREATE TABLE public.risk_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(500),
    action_pattern character varying(255) NOT NULL,
    resource_pattern character varying(255) DEFAULT '*'::character varying,
    environment_pattern character varying(100) DEFAULT '*'::character varying,
    base_score integer DEFAULT 50 NOT NULL,
    scope_bulk_threshold integer DEFAULT 100,
    scope_bulk_modifier integer DEFAULT 30,
    pii_modifier integer DEFAULT 20,
    financial_modifier integer DEFAULT 40,
    off_hours_modifier integer DEFAULT 10,
    first_time_modifier integer DEFAULT 10,
    auto_approve_below integer,
    require_approval_above integer,
    require_multi_approval_above integer,
    is_active boolean DEFAULT true NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT risk_policies_pkey PRIMARY KEY (id)
);

CREATE TABLE public.role_assignment_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_at timestamp with time zone,
    reviewed_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT role_assignment_requests_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[]))),
    CONSTRAINT role_assignment_requests_pkey PRIMARY KEY (id)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Agent Identity Phase 1: service_accounts
-- Non-human machine principals. PK is (workspace_id, id) so the SA is always
-- workspace-scoped. Two global partial-unique indexes enforce the one-credential-
-- one-principal rule: a confidential client or SPIFFE ID can back at most one SA
-- across all workspaces.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE public.service_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    status text NOT NULL DEFAULT 'disabled'
        CONSTRAINT service_accounts_status_chk CHECK (status IN ('active', 'disabled', 'suspended')),
    oauth_client_id uuid,
    spiffe_id text,
    -- spiffe_match_type: how the validator matches an incoming SVID `sub` to this
    -- workload. 'exact' (default) = sub must equal spiffe_id; 'prefix' = sub must
    -- start with spiffe_id (reserved for federated fleets — exact is shipped today).
    spiffe_match_type text NOT NULL DEFAULT 'exact'
        CONSTRAINT service_accounts_spiffe_match_chk CHECK (spiffe_match_type IN ('exact', 'prefix')),
    -- workload_provider_id: for a FEDERATED (bring-your-own SPIRE) workload, the
    -- workload_identity_providers row whose trust domain issued this spiffe_id.
    -- NULL for AuthSec-managed (locally minted) workloads.
    workload_provider_id uuid,
    -- external_subject: for OIDC-federated workloads (e.g. GitHub Actions), the
    -- token `sub` (or provider.subject_claim) that maps to this workload.
    external_subject text,
    -- owner/contact for triage (plan Journey 3); informational only.
    owner_email text,
    owner_team text,
    -- last time this workload successfully authenticated (any method).
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_accounts_pkey PRIMARY KEY (workspace_id, id)
);

CREATE UNIQUE INDEX uq_sa_client ON public.service_accounts (oauth_client_id) WHERE oauth_client_id IS NOT NULL;
CREATE UNIQUE INDEX uq_sa_spiffe ON public.service_accounts (spiffe_id)       WHERE spiffe_id IS NOT NULL;
CREATE INDEX idx_sa_workspace_id ON public.service_accounts (workspace_id);
CREATE INDEX idx_sa_external_subject ON public.service_accounts (external_subject) WHERE external_subject IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- workload_identity_providers — registered external token issuers a workload may
-- authenticate with, replacing the single global SPIFFE_OIDC_ISSUER env:
--   kind='spiffe' → a SPIRE trust domain (multi-cluster / "already have SPIRE")
--   kind='oidc'   → a generic OIDC issuer (GitHub Actions / CI federation)
-- The token validator resolves the provider by the presented token's `iss`,
-- verifies the signature against its JWKS (discovered or jwks_uri), checks the
-- audience, then maps the subject to a service_account (spiffe_id for spiffe,
-- external_subject for oidc). Issuer is unique instance-wide.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE public.workload_identity_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL DEFAULT 'spiffe'
        CONSTRAINT wip_kind_chk CHECK (kind IN ('spiffe', 'oidc')),
    issuer text NOT NULL,
    jwks_uri text,
    trust_domain text,
    allowed_audiences text[] NOT NULL DEFAULT '{}',
    subject_claim text NOT NULL DEFAULT 'sub',
    status text NOT NULL DEFAULT 'active'
        CONSTRAINT wip_status_chk CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workload_identity_providers_pkey PRIMARY KEY (id)
);
CREATE UNIQUE INDEX uq_wip_issuer ON public.workload_identity_providers (issuer);
CREATE INDEX idx_wip_workspace ON public.workload_identity_providers (workspace_id);

CREATE TABLE public.role_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    service_account_id uuid,
    role_id uuid NOT NULL,
    scope_type text DEFAULT '*'::text,
    scope_id uuid,
    conditions jsonb DEFAULT '{}'::jsonb,
    expires_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    role_name text,
    username text,
    assignment_source text DEFAULT 'manual'::text NOT NULL,
    assignment_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    group_id uuid,
    CONSTRAINT check_principal CHECK ((((((user_id IS NOT NULL))::integer + ((group_id IS NOT NULL))::integer) + ((service_account_id IS NOT NULL))::integer) = 1)),
    workspace_id uuid NOT NULL,
    CONSTRAINT chk_rb_sa_workspace CHECK (service_account_id IS NULL OR workspace_id IS NOT NULL),
    CONSTRAINT fk_rb_service_account FOREIGN KEY (workspace_id, service_account_id)
        REFERENCES public.service_accounts(workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT role_bindings_pkey PRIMARY KEY (id)
);

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    is_system boolean DEFAULT false,
    workspace_id uuid,
    CONSTRAINT roles_pkey PRIMARY KEY (id),
    CONSTRAINT roles_workspace_id_id_key UNIQUE (workspace_id, id),
    CONSTRAINT roles_workspace_id_name_key UNIQUE (workspace_id, name)
);

CREATE TABLE public.saml_callback_states (
    id text NOT NULL,
    redirect_to text NOT NULL,
    user_email character varying(255),
    user_name character varying(255),
    provider_name character varying(255),
    workspace_id uuid NOT NULL,
    client_id uuid,
    login_challenge text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL,
    CONSTRAINT saml_callback_states_pkey PRIMARY KEY (id)
);

CREATE TABLE public.saml_requests (
    id text NOT NULL,
    login_challenge text NOT NULL,
    workspace_id uuid NOT NULL,
    client_id uuid,
    provider_name text NOT NULL,
    relay_state text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL,
    CONSTRAINT saml_requests_pkey PRIMARY KEY (id)
);

CREATE TABLE public.saml_sp_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    certificate text NOT NULL,
    private_key text NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL,
    CONSTRAINT saml_sp_certificates_pkey PRIMARY KEY (id),
    CONSTRAINT saml_sp_certificates_workspace_id_key UNIQUE (workspace_id)
);

CREATE TABLE public.services (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    url text,
    description text,
    tags text[] DEFAULT '{}'::text[],
    resource_id uuid,
    auth_type text,
    auth_config text,
    vault_path text,
    created_by text NOT NULL,
    agent_accessible boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT services_pkey PRIMARY KEY (id)
);

CREATE TABLE public.spire_audit_logs (
    id bigint NOT NULL,
    request_id text,
    workspace_id text,
    subject text,
    resource text,
    action text,
    decision text,
    reason text,
    policy_id bigint,
    rule_id bigint,
    context text,
    ip_address text,
    user_agent text,
    "timestamp" timestamp with time zone,
    CONSTRAINT spire_audit_logs_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_audit_logs_id_seq OWNED BY public.spire_audit_logs.id;

CREATE INDEX idx_spire_audit_logs_workspace ON public.spire_audit_logs(workspace_id);

CREATE TABLE public.spire_oidc_tokens (
    id bigint NOT NULL,
    jwt_id text,
    subject text,
    spiffe_id text,
    token_type text,
    audience text,
    scope text,
    expires_at timestamp with time zone,
    created_at timestamp with time zone,
    revoked boolean,
    CONSTRAINT spire_oidc_tokens_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_oidc_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_oidc_tokens_id_seq OWNED BY public.spire_oidc_tokens.id;

CREATE TABLE public.spire_policies (
    id bigint NOT NULL,
    name text,
    description text,
    version text,
    engine text,
    author text,
    tags text,
    labels text,
    annotations text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    active boolean,
    CONSTRAINT spire_policies_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_policies_id_seq OWNED BY public.spire_policies.id;

CREATE TABLE public.spire_policy_actions (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    value text,
    CONSTRAINT spire_policy_actions_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_policy_actions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_policy_actions_id_seq OWNED BY public.spire_policy_actions.id;

CREATE TABLE public.spire_policy_conditions (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    operator text,
    key text,
    value text,
    metadata text,
    CONSTRAINT spire_policy_conditions_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_policy_conditions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_policy_conditions_id_seq OWNED BY public.spire_policy_conditions.id;

CREATE TABLE public.spire_policy_resources (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    value text,
    pattern text,
    CONSTRAINT spire_policy_resources_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_policy_resources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_policy_resources_id_seq OWNED BY public.spire_policy_resources.id;

CREATE TABLE public.spire_policy_rules (
    id bigint NOT NULL,
    policy_id bigint,
    name text,
    effect text,
    priority bigint,
    attributes text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT spire_policy_rules_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_policy_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_policy_rules_id_seq OWNED BY public.spire_policy_rules.id;

CREATE TABLE public.spire_policy_subjects (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    value text,
    pattern text,
    CONSTRAINT spire_policy_subjects_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_policy_subjects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_policy_subjects_id_seq OWNED BY public.spire_policy_subjects.id;

CREATE TABLE public.spire_role_bindings (
    id bigint NOT NULL,
    subject text,
    role text,
    resource text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT spire_role_bindings_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_role_bindings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_role_bindings_id_seq OWNED BY public.spire_role_bindings.id;

CREATE TABLE public.spire_workloads (
    id bigint NOT NULL,
    spiffe_id text,
    owner text,
    CONSTRAINT spire_workloads_pkey PRIMARY KEY (id)
);

CREATE SEQUENCE public.spire_workloads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.spire_workloads_id_seq OWNED BY public.spire_workloads.id;

CREATE TABLE public.sync_configurations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    client_id uuid NOT NULL,
    project_id uuid,
    sync_type character varying(50) NOT NULL,
    config_name character varying(255) NOT NULL,
    description text,
    is_active boolean DEFAULT true NOT NULL,
    ad_server character varying(500),
    ad_username character varying(500),
    ad_password text,
    ad_base_dn character varying(500),
    ad_filter text,
    ad_use_ssl boolean DEFAULT true,
    ad_skip_verify boolean DEFAULT false,
    entra_workspace_id character varying(500),
    entra_client_id character varying(500),
    entra_client_secret text,
    entra_scopes text,
    entra_skip_verify boolean DEFAULT false,
    last_sync_at timestamp with time zone,
    last_sync_status character varying(50),
    last_sync_error text,
    last_sync_users_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    CONSTRAINT sync_configurations_sync_type_check CHECK (((sync_type)::text = ANY ((ARRAY['active_directory'::character varying, 'entra_id'::character varying])::text[]))),
    CONSTRAINT sync_configurations_pkey PRIMARY KEY (id),
    CONSTRAINT sync_configurations_workspace_id_config_name_key UNIQUE (workspace_id, config_name)
);

-- sync_runs — one row per directory sync attempt (manual or scheduled).
CREATE TABLE public.sync_runs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id         UUID NOT NULL,
    sync_config_id       UUID NOT NULL REFERENCES public.sync_configurations(id) ON DELETE CASCADE,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at          TIMESTAMPTZ,
    status               VARCHAR(32) NOT NULL CHECK (status IN ('running','success','failed','dry_run')),
    dry_run              BOOLEAN NOT NULL DEFAULT FALSE,
    users_created        INT NOT NULL DEFAULT 0,
    users_updated        INT NOT NULL DEFAULT 0,
    users_failed         INT NOT NULL DEFAULT 0,
    users_skipped        INT NOT NULL DEFAULT 0,
    error_text           TEXT,
    triggered_by_user_id UUID,
    triggered_by_kind    VARCHAR(32) NOT NULL DEFAULT 'manual'
);
CREATE INDEX idx_sync_runs_config ON public.sync_runs(sync_config_id, started_at DESC);
CREATE INDEX idx_sync_runs_workspace ON public.sync_runs(workspace_id, started_at DESC);

CREATE TABLE public.workspace_ciba_auth_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    auth_req_id character varying(255) NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    user_email character varying(255) NOT NULL,
    client_id uuid,
    device_token_id uuid NOT NULL,
    binding_message character varying(255),
    scopes jsonb DEFAULT '[]'::jsonb,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    biometric_verified boolean DEFAULT false,
    expires_at bigint NOT NULL,
    created_at bigint NOT NULL,
    responded_at bigint,
    last_polled_at bigint,
    CONSTRAINT workspace_ciba_auth_requests_auth_req_id_key UNIQUE (auth_req_id),
    CONSTRAINT workspace_ciba_auth_requests_pkey PRIMARY KEY (id)
);

CREATE TABLE public.workspace_device_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    device_token character varying(500) NOT NULL,
    platform character varying(20) NOT NULL,
    device_name character varying(100),
    device_model character varying(100),
    app_version character varying(20),
    os_version character varying(20),
    is_active boolean DEFAULT true NOT NULL,
    last_used bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT fk_workspace_device_token UNIQUE (device_token, workspace_id),
    CONSTRAINT workspace_device_tokens_device_token_key UNIQUE (device_token),
    CONSTRAINT workspace_device_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT uq_workspace_device_id UNIQUE (id, workspace_id)
);

CREATE TABLE public.workspace_domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    domain character varying(255) NOT NULL,
    kind character varying(32) DEFAULT 'custom'::character varying NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    verification_method character varying(32) DEFAULT 'dns_txt'::character varying NOT NULL,
    verification_token character varying(255) NOT NULL,
    verification_txt_name character varying(255),
    verification_txt_value character varying(255),
    verified_at timestamp with time zone,
    last_checked_at timestamp with time zone,
    failure_reason text,
    ingress_created boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    CONSTRAINT workspace_domains_pkey PRIMARY KEY (id)
);

CREATE TABLE public.workspace_end_user_states (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    plan_tier text,
    rate_limit_override jsonb,
    first_consent_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    suspended_at timestamp with time zone,
    suspended_by uuid,
    suspended_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_teus_status CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text]))),
    CONSTRAINT workspace_end_user_states_pkey PRIMARY KEY (workspace_id, user_id)
);

-- Phase C: dropped CREATE TABLE public.tenant_hydra_clients

-- Phase 6: dropped CREATE TABLE public.tenant_mappings


-- workspace_user_memberships: REMOVED. Replaced by workspace_memberships (role-based).
-- The role_id FK on workspace_memberships provides the same expressiveness via roles table.

CREATE TABLE public.workspace_totp_backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    code character varying(64) NOT NULL,
    is_used boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    used_at bigint,
    CONSTRAINT workspace_totp_backup_codes_code_key UNIQUE (code),
    CONSTRAINT workspace_totp_backup_codes_pkey PRIMARY KEY (id)
);

CREATE TABLE public.workspace_totp_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    secret character varying(64) NOT NULL,
    device_name character varying(100),
    device_type character varying(50) DEFAULT 'generic'::character varying,
    last_used bigint,
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT false,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_totp_secrets_pkey PRIMARY KEY (id),
    CONSTRAINT workspace_totp_secrets_user_id_workspace_id_is_primary_key UNIQUE (user_id, workspace_id, is_primary)
);

-- Phase 6: dropped CREATE TABLE public.tenants


CREATE TABLE public.totp_backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    code character varying(64) NOT NULL,
    is_used boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    used_at bigint,
    CONSTRAINT totp_backup_codes_code_key UNIQUE (code),
    CONSTRAINT totp_backup_codes_pkey PRIMARY KEY (id)
);

CREATE TABLE public.totp_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    secret character varying(64) NOT NULL,
    device_name character varying(100) NOT NULL,
    device_type character varying(50) DEFAULT 'generic'::character varying,
    last_used bigint,
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT totp_secrets_pkey PRIMARY KEY (id)
);

CREATE TABLE public.user_groups (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    group_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by uuid,
    CONSTRAINT user_groups_pkey PRIMARY KEY (workspace_id, user_id, group_id)
);

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    -- client_id: legacy field, nullable. User identity is (workspace_id, email).
    -- Full removal tracked in Phase G (final sweep) after all repo references cleared.
    client_id uuid,
    workspace_id uuid,
    project_id uuid,
    email character varying(255) NOT NULL,
    name character varying(255) DEFAULT 'Not Provided'::character varying,
    username character varying(255) DEFAULT 'Not Provided'::character varying,
    password_hash text DEFAULT ''::text,
    workspace_domain character varying(255) DEFAULT ''::character varying,
    provider character varying(100) DEFAULT 'local'::character varying,
    provider_id character varying(255),
    provider_data jsonb DEFAULT '{}'::jsonb,
    avatar_url text,
    active boolean DEFAULT true,
    -- Leaver bookkeeping. The JML reconcile is idempotent and needs no cursor; these
    -- exist so an operator can SEE that a leaver was processed, and when, without
    -- reading the audit log.
    access_revoked_at timestamptz,
    access_revoked_summary text NOT NULL DEFAULT '',
    mfa_enabled boolean DEFAULT false,
    mfa_method text[],
    mfa_default_method character varying(50),
    mfa_enrolled_at timestamp with time zone,
    mfa_verified boolean DEFAULT false,
    external_id character varying(255),
    sync_source character varying(100),
    last_sync_at timestamp with time zone,
    is_synced_user boolean DEFAULT false,
    last_login timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    role_name character varying(255),
    temporary_password boolean DEFAULT false,
    temporary_password_expires_at timestamp with time zone,
    password_change_required boolean DEFAULT false,
    invited_by uuid,
    invited_at timestamp with time zone,
    is_primary_admin boolean DEFAULT false,
    failed_login_attempts integer DEFAULT 0,
    account_locked_at timestamp with time zone,
    password_reset_required boolean DEFAULT false,
    is_active boolean DEFAULT true,
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_workspace_id_id_key UNIQUE (workspace_id, id)
);

CREATE TABLE public.voice_identity_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    voice_platform character varying(50) NOT NULL,
    voice_user_id text NOT NULL,
    voice_user_name text,
    user_id uuid NOT NULL,
    user_email text NOT NULL,
    is_active boolean DEFAULT true,
    link_method character varying(50),
    last_used_at bigint,
    linked_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    created_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    updated_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    CONSTRAINT uq_voice_identity_workspace_platform_user UNIQUE (workspace_id, voice_platform, voice_user_id),
    CONSTRAINT voice_identity_links_pkey PRIMARY KEY (id)
);

CREATE TABLE public.voice_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    client_id uuid,
    session_token character varying(128) NOT NULL,
    voice_otp character varying(10) NOT NULL,
    otp_attempts integer DEFAULT 0,
    voice_platform character varying(50),
    voice_user_id text,
    device_info jsonb,
    user_id uuid,
    user_email text,
    status character varying(20) DEFAULT 'initiated'::character varying NOT NULL,
    linked_device_code character varying(128),
    scopes jsonb DEFAULT '[]'::jsonb,
    expires_at bigint NOT NULL,
    verified_at bigint,
    created_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    updated_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint,
    CONSTRAINT chk_voice_otp_attempts CHECK (((otp_attempts >= 0) AND (otp_attempts <= 5))),
    CONSTRAINT chk_voice_sessions_status CHECK (((status)::text = ANY ((ARRAY['initiated'::character varying, 'verified'::character varying, 'expired'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT voice_sessions_pkey PRIMARY KEY (id),
    CONSTRAINT voice_sessions_session_token_key UNIQUE (session_token)
);

CREATE TABLE public.webauthn_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    session_key character varying(255) NOT NULL,
    challenge text NOT NULL,
    user_id bytea NOT NULL,
    user_verification character varying(50),
    extensions bytea,
    cred_params bytea,
    allowed_credential_ids bytea,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (id),
    CONSTRAINT webauthn_sessions_session_key_key UNIQUE (session_key)
);
--
-- =====================================================================
-- v4 IDP + Workspace plane
-- =====================================================================
-- The pg_dump snapshot above was taken before the v4 IDP migrations were
-- applied to the source database. The tables below ARE part of v4 and the
-- backend will 500 on any IDP/SAML/SCIM/workspace endpoint without them.
-- Consolidated from migrations 115, 117, 124, 125, 126, plus the saml_providers
-- shape used by internal/hydra/models/saml_methods.go.
--

CREATE TABLE public.workspaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text UNIQUE,
    owner_user_id uuid,
    workspace_type text NOT NULL DEFAULT 'personal',
    workspace_domain text,
    email text,
    password_hash text,
    provider text DEFAULT 'local',
    source text,
    status text DEFAULT 'active',
    vault_mount text,
    ca_cert text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspaces_type_chk CHECK (workspace_type IN ('personal', 'team')),
    CONSTRAINT workspaces_slug_reserved_chk CHECK (
        slug IS NULL OR lower(slug) NOT IN (
            'admin', 'api', 'auth', 'oauth', 'scim', 'login', 'support', 'www', 'root', 'system'
        )
    )
);

CREATE INDEX idx_workspaces_owner_user_id ON public.workspaces(owner_user_id);

-- Phase A: workspace_domain is the canonical Host-header lookup key.
-- Must be unique so WorkspaceFromHost returns exactly one workspace per hostname.
CREATE UNIQUE INDEX idx_workspaces_workspace_domain ON public.workspaces (LOWER(workspace_domain)) WHERE workspace_domain IS NOT NULL;

CREATE TABLE public.workspace_memberships (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'active',
    source text NOT NULL DEFAULT 'manual',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspace_memberships_status_chk CHECK (status IN ('active', 'invited', 'suspended', 'left')),
    CONSTRAINT workspace_memberships_source_chk CHECK (source IN ('signup', 'invite', 'scim', 'oidc_jit', 'saml_jit', 'api', 'manual')),
    CONSTRAINT workspace_memberships_workspace_user_uq UNIQUE (workspace_id, user_id)
);

CREATE INDEX idx_workspace_memberships_user_id ON public.workspace_memberships(user_id);
CREATE INDEX idx_workspace_memberships_role_id ON public.workspace_memberships(role_id);

-- identity_providers — canonical v4 IDP table. Each row is workspace-owned
-- and points to a concrete config row (oidc_providers, saml_providers, etc.)
-- via config_ref.
CREATE TABLE public.identity_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    provider_type text NOT NULL,
    display_name text NOT NULL,
    oidc_provider_id uuid,
    saml_provider_id uuid,
    config_ref text,
    status text NOT NULL DEFAULT 'configured',
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT identity_providers_type_chk
        CHECK (provider_type IN ('oidc', 'saml', 'ad', 'entra', 'scim')),
    CONSTRAINT identity_providers_config_ref_chk CHECK (
        (provider_type = 'oidc' AND oidc_provider_id IS NOT NULL AND saml_provider_id IS NULL) OR
        (provider_type = 'saml' AND saml_provider_id IS NOT NULL AND oidc_provider_id IS NULL) OR
        (provider_type IN ('ad', 'entra', 'scim'))
    ),
    CONSTRAINT identity_providers_id_workspace_uq UNIQUE (id, workspace_id),
    CONSTRAINT identity_providers_oidc_fkey FOREIGN KEY (oidc_provider_id) REFERENCES public.oidc_providers(id) ON DELETE SET NULL
);

CREATE INDEX idx_identity_providers_workspace ON public.identity_providers(workspace_id);
CREATE INDEX idx_identity_providers_type      ON public.identity_providers(provider_type);

-- application_identity_provider_policies — opt-in restriction of which IDPs
-- a given application (resource_servers row) accepts.
CREATE TABLE public.application_identity_provider_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    identity_provider_id uuid NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT application_identity_provider_policies_uq UNIQUE (application_id, identity_provider_id),
    CONSTRAINT app_idp_policies_rs_workspace_fkey FOREIGN KEY (application_id, workspace_id) REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT app_idp_policies_idp_workspace_fkey FOREIGN KEY (identity_provider_id, workspace_id) REFERENCES public.identity_providers(id, workspace_id) ON DELETE CASCADE
);

CREATE INDEX idx_app_idp_policies_workspace ON public.application_identity_provider_policies(workspace_id);

-- scim_connections — workspace-scoped SCIM 2.0 connection tokens. Optional
-- back-reference to identity_providers if the SCIM source is itself an IDP.
CREATE TABLE public.scim_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    identity_provider_id uuid REFERENCES public.identity_providers(id) ON DELETE SET NULL,
    token_hash text NOT NULL,
    -- Rotation: previous token stays valid for 5 min after rotate so the IdP
    -- can swap without downtime. previous_token_expires_at is the cutoff.
    previous_token_hash       text,
    previous_token_expires_at timestamptz,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT scim_connections_status_chk CHECK (status IN ('active', 'revoked', 'disabled')),
    default_client_id uuid,
    default_project_id uuid
);

CREATE INDEX idx_scim_connections_workspace          ON public.scim_connections(workspace_id);
CREATE INDEX idx_scim_connections_identity_provider  ON public.scim_connections(identity_provider_id);

-- scim_events — per-request audit log for SCIM 2.0 operations. Written by the
-- SCIMEventLogger middleware after every request on the /scim/v2/c/:id/... path.
CREATE TABLE public.scim_events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    scim_connection_id UUID NOT NULL REFERENCES public.scim_connections(id) ON DELETE CASCADE,
    ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    method             VARCHAR(8)  NOT NULL,
    path               TEXT        NOT NULL,
    resource_type      VARCHAR(16) NOT NULL DEFAULT '',
    resource_id        TEXT,
    status_code        INT         NOT NULL,
    error_text         TEXT,
    ip_address         VARCHAR(64),
    user_agent         TEXT
);
CREATE INDEX idx_scim_events_conn ON public.scim_events(scim_connection_id, ts DESC);
CREATE INDEX idx_scim_events_workspace ON public.scim_events(workspace_id, ts DESC);

-- application_spiffe_identities — workspace-scoped SPIFFE ID ↔ Application
-- binding. Used by the agent-guard plane.
CREATE TABLE public.application_spiffe_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- Composite FK: the application this SPIFFE identity binds to must live in the
    -- SAME workspace. Matches resource_servers' UNIQUE (id, workspace_id).
    application_id uuid NOT NULL,
    CONSTRAINT fk_app_spiffe_application FOREIGN KEY (application_id, workspace_id)
        REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE,
    spiffe_id text NOT NULL UNIQUE,
    trust_domain text NOT NULL,
    selectors jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'attestation_pending',
    last_attested_at timestamptz,
    last_token_issued_at timestamptz,
    last_error text,
    last_error_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT application_spiffe_identities_status_chk CHECK (status IN ('active', 'revoked', 'disabled', 'attestation_pending', 'attested', 'token_issued', 'failed'))
);

CREATE INDEX idx_app_spiffe_workspace   ON public.application_spiffe_identities(workspace_id);
CREATE INDEX idx_app_spiffe_application ON public.application_spiffe_identities(application_id);

-- saml_providers — referenced by identity_providers.config_ref for SAML IDPs.
-- v4 shape: workspace-scoped via workspace_id (no client_id; per-Application
-- restriction lives in application_identity_provider_policies).
CREATE TABLE public.saml_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    provider_name varchar(255) NOT NULL,
    display_name varchar(255) NOT NULL,
    entity_id varchar(500) NOT NULL,
    sso_url varchar(500) NOT NULL,
    slo_url varchar(500),
    certificate text NOT NULL,
    metadata_url varchar(500),
    name_id_format varchar(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mapping jsonb,
    is_active boolean DEFAULT true,
    sort_order int DEFAULT 0,
    sp_entity_id text,                  -- our SP entity ID (audience restriction check)
    sp_acs_url text,                    -- our assertion consumer service URL (destination check)
    want_assertions_signed boolean DEFAULT true,
    created_at timestamptz DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_saml_provider_unique UNIQUE (workspace_id, provider_name),
    CONSTRAINT saml_providers_id_workspace_uq UNIQUE (id, workspace_id)
);

CREATE INDEX idx_saml_providers_workspace_id ON public.saml_providers(workspace_id);

-- ---------------------------------------------------------------------------
-- Agent Identity (Phase 0) — NativeSealer token families (M2M + XAA/ID-JAG + CIBA).
-- AuthSec mints these RS256 `at+jwt` tokens itself (iss = OAUTH_ISSUER_URL),
-- separate from the Hydra-sealed interactive flows. These tables are the
-- authoritative metadata + replay/revocation stores for native tokens.
--   * native_tokens        — metadata-only registry (no raw tokens); authoritative
--                            for introspection (workspace/subject/rs/family/scope).
--   * id_jag_replay_cache  — one-shot redemption guard for ID-JAGs, keyed per issuer.
--   * revoked_tokens       — revocation source of truth (native_tokens.revoked_at is
--                            display-only; if they disagree, revoked_tokens wins).
-- No FKs on native_tokens.workspace_id/resource_server_id by design: the row is
-- append-only audit metadata whose lifecycle is independent of those entities.
-- ---------------------------------------------------------------------------
CREATE TABLE public.native_tokens (
    jti uuid PRIMARY KEY,
    iss text NOT NULL,                       -- = OAUTH_ISSUER_URL; keeps table honest with revoked_tokens(iss,…)
    workspace_id uuid NOT NULL,
    token_family text NOT NULL CHECK (token_family IN ('xaa', 'm2m', 'ciba')),
    subject_type text NOT NULL,              -- 'user' | 'service_account'
    subject_id uuid NOT NULL,
    actor_client_id text,                    -- XAA/CIBA: the acting agent client
    actor_spiffe_id text,
    client_id text NOT NULL,                 -- authenticating client_id (claim)
    resource_server_id uuid NOT NULL,
    aud text NOT NULL,                       -- = resource_servers.resource_uri
    scope text NOT NULL,
    source_grant_jti text,                   -- XAA: the redeemed ID-JAG jti
    source_grant_iss text,                   -- XAA: iss of the redeemed ID-JAG (for issuer bulk-revoke)
    rar_id uuid,                             -- CIBA: server-side RAR reference (RFC 9396)
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz                   -- display/audit only; revoked_tokens is authoritative
);

CREATE INDEX idx_native_tokens_expires_at    ON public.native_tokens(expires_at);
CREATE INDEX idx_native_tokens_workspace_id  ON public.native_tokens(workspace_id);
CREATE INDEX idx_native_tokens_source_grant      ON public.native_tokens(source_grant_jti) WHERE source_grant_jti IS NOT NULL;
CREATE INDEX idx_native_tokens_source_grant_iss  ON public.native_tokens(source_grant_iss) WHERE source_grant_iss IS NOT NULL;
CREATE INDEX idx_native_tokens_client_id         ON public.native_tokens(client_id);

-- jti is unique only PER ISSUER → key on (iss, jti). A redeemed ID-JAG is recorded
-- here as *seen* (replay guard), never as *revoked*.
CREATE TABLE public.id_jag_replay_cache (
    iss text NOT NULL,
    jti text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (iss, jti)
);

CREATE INDEX idx_id_jag_replay_expires_at ON public.id_jag_replay_cache(expires_at);

-- Revocation meaning differs by kind → key on (iss, kind, jti). For AuthSec-minted
-- access tokens iss = OAUTH_ISSUER_URL; for external ID-JAGs iss is the trusted issuer.
CREATE TABLE public.revoked_tokens (
    iss text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('id_jag', 'access_token')),
    jti text NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now(),
    reason text,
    expires_at timestamptz NOT NULL,         -- prune after the underlying token would have expired
    PRIMARY KEY (iss, kind, jti)
);

CREATE INDEX idx_revoked_tokens_expires_at ON public.revoked_tokens(expires_at);

-- ---------------------------------------------------------------------------
-- Indexes for v4 columns that were inlined into their CREATE TABLE statements
-- above. Placed here (after the v4 IDP block) so that every referenced table
-- already exists at index-creation time.
-- ---------------------------------------------------------------------------
CREATE INDEX idx_resource_servers_workspace_id          ON public.resource_servers(workspace_id);
CREATE INDEX idx_resource_servers_application_type      ON public.resource_servers(application_type);
CREATE INDEX idx_resource_servers_legacy_client_id      ON public.resource_servers(legacy_client_id);
CREATE INDEX idx_rs_access_policies_workspace_id        ON public.resource_server_access_policies(workspace_id);
CREATE INDEX idx_mcp_oauth_clients_sync_status          ON public.mcp_oauth_clients(sync_status) WHERE sync_status <> 'active';
CREATE INDEX idx_scim_connections_default_client        ON public.scim_connections(default_client_id) WHERE default_client_id IS NOT NULL;
CREATE INDEX idx_oidc_providers_workspace               ON public.oidc_providers(workspace_id);
CREATE UNIQUE INDEX oidc_providers_provider_name_workspace_uq ON public.oidc_providers (workspace_id, provider_name) WHERE workspace_id IS NOT NULL;
CREATE UNIQUE INDEX oidc_providers_provider_name_platform_uq ON public.oidc_providers (provider_name) WHERE workspace_id IS NULL;
CREATE INDEX idx_delegation_tokens_workspace_id         ON public.delegation_tokens(workspace_id);
CREATE INDEX idx_delegation_policies_workspace_id       ON public.delegation_policies(workspace_id);
CREATE INDEX idx_oauth_scopes_workspace_id              ON public.oauth_scopes(workspace_id);
CREATE INDEX idx_roles_workspace_id                     ON public.roles(workspace_id);
CREATE INDEX idx_permissions_workspace_id               ON public.permissions(workspace_id);
CREATE INDEX idx_role_bindings_workspace_id             ON public.role_bindings(workspace_id);
CREATE INDEX idx_rs_client_reg_workspace_id             ON public.resource_server_client_registrations(workspace_id);
CREATE INDEX idx_mcp_tools_workspace_id                 ON public.mcp_tools(workspace_id);
CREATE INDEX idx_auth_request_contexts_workspace_id     ON public.auth_request_contexts(workspace_id);

-- Reusable scope vocabulary templates (workspace-scoped). Catalog entries do
-- not grant runtime access on their own — they are templates that can be
-- attached to an application, which materialises an oauth_scopes row.
--

CREATE TABLE public.scope_catalog_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    key text NOT NULL,
    display_name text NOT NULL,
    description text,
    risk_level text DEFAULT 'low'::text NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT scope_catalog_entries_pkey PRIMARY KEY (id)
);

-- OWNER intentionally not set here; pg_dump used `OWNER TO -` (anonymous)
-- everywhere else in this file, so the table inherits the role that ran the
-- bootstrap (authdev on dev, authsec on prod). Hard-coding either name breaks
-- the opposite environment.

CREATE UNIQUE INDEX idx_scope_catalog_workspace_key
    ON public.scope_catalog_entries USING btree (workspace_id, key);

CREATE INDEX idx_scope_catalog_workspace_id
    ON public.scope_catalog_entries USING btree (workspace_id);

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);

ALTER TABLE ONLY public.spire_audit_logs ALTER COLUMN id SET DEFAULT nextval('public.spire_audit_logs_id_seq'::regclass);

ALTER TABLE ONLY public.spire_oidc_tokens ALTER COLUMN id SET DEFAULT nextval('public.spire_oidc_tokens_id_seq'::regclass);

ALTER TABLE ONLY public.spire_policies ALTER COLUMN id SET DEFAULT nextval('public.spire_policies_id_seq'::regclass);

ALTER TABLE ONLY public.spire_policy_actions ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_actions_id_seq'::regclass);

ALTER TABLE ONLY public.spire_policy_conditions ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_conditions_id_seq'::regclass);

ALTER TABLE ONLY public.spire_policy_resources ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_resources_id_seq'::regclass);

ALTER TABLE ONLY public.spire_policy_rules ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_rules_id_seq'::regclass);

ALTER TABLE ONLY public.spire_policy_subjects ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_subjects_id_seq'::regclass);

ALTER TABLE ONLY public.spire_role_bindings ALTER COLUMN id SET DEFAULT nextval('public.spire_role_bindings_id_seq'::regclass);

ALTER TABLE ONLY public.spire_workloads ALTER COLUMN id SET DEFAULT nextval('public.spire_workloads_id_seq'::regclass);

-- migration_logs primary key is managed by GORM AutoMigrate (see comment above).

CREATE UNIQUE INDEX groups_name_workspace_unique ON public.groups USING btree (name, workspace_id);

CREATE INDEX idx_agent_action_agent ON public.agent_action_requests USING btree (agent_id);

CREATE INDEX idx_agent_action_expires ON public.agent_action_requests USING btree (expires_at);

CREATE INDEX idx_agent_action_req_id ON public.agent_action_requests USING btree (action_req_id);

CREATE INDEX idx_agent_action_session ON public.agent_action_requests USING btree (session_id);

CREATE INDEX idx_agent_action_status ON public.agent_action_requests USING btree (status);

CREATE INDEX idx_agent_action_workspace ON public.agent_action_requests USING btree (workspace_id);

CREATE INDEX idx_agent_action_user ON public.agent_action_requests USING btree (user_id);

CREATE INDEX idx_agent_action_user_status ON public.agent_action_requests USING btree (user_id, status);

CREATE INDEX idx_agent_audit_action ON public.agent_action_audit_log USING btree (action);

CREATE INDEX idx_agent_audit_agent ON public.agent_action_audit_log USING btree (agent_id);

CREATE INDEX idx_agent_audit_created ON public.agent_action_audit_log USING btree (created_at);

CREATE INDEX idx_agent_audit_risk ON public.agent_action_audit_log USING btree (risk_level);

CREATE INDEX idx_agent_audit_status ON public.agent_action_audit_log USING btree (final_status);

CREATE INDEX idx_agent_audit_workspace ON public.agent_action_audit_log USING btree (workspace_id);

CREATE INDEX idx_agent_audit_user ON public.agent_action_audit_log USING btree (user_id);

CREATE INDEX idx_agent_decision_approver ON public.agent_action_decisions USING btree (approver_user_id);

CREATE INDEX idx_agent_decision_request ON public.agent_action_decisions USING btree (action_request_id);

CREATE UNIQUE INDEX idx_arc_context_id ON public.auth_request_contexts USING btree (context_id) WHERE (context_id IS NOT NULL);

CREATE INDEX idx_arc_expires_at ON public.auth_request_contexts USING btree (expires_at);

CREATE INDEX idx_arc_hydra_client_id ON public.auth_request_contexts USING btree (hydra_client_id);

CREATE UNIQUE INDEX idx_arc_hydra_request_uri ON public.auth_request_contexts USING btree (hydra_request_uri) WHERE ((hydra_request_uri IS NOT NULL) AND ((hydra_request_uri)::text <> ''::text));

CREATE UNIQUE INDEX idx_arc_login_challenge ON public.auth_request_contexts USING btree (login_challenge) WHERE (login_challenge IS NOT NULL);

CREATE INDEX idx_audit_events_action ON public.audit_events USING btree (action);

CREATE INDEX idx_audit_events_request_id ON public.audit_events USING btree (request_id);

CREATE INDEX idx_audit_events_resource ON public.audit_events USING btree (resource);

CREATE INDEX idx_audit_events_workspace_id ON public.audit_events USING btree (workspace_id);

CREATE INDEX idx_audit_events_timestamp ON public.audit_events USING btree ("timestamp");

CREATE INDEX idx_audit_events_user_id ON public.audit_events USING btree (user_id);

CREATE INDEX idx_backup_workspace ON public.totp_backup_codes USING btree (workspace_id);

CREATE INDEX idx_backup_used ON public.totp_backup_codes USING btree (is_used);

CREATE INDEX idx_backup_user ON public.totp_backup_codes USING btree (user_id);

CREATE INDEX idx_ciba_auth_expires ON public.ciba_auth_requests USING btree (expires_at);

CREATE INDEX idx_ciba_auth_status ON public.ciba_auth_requests USING btree (status);

CREATE INDEX idx_ciba_auth_workspace ON public.ciba_auth_requests USING btree (workspace_id);

CREATE INDEX idx_ciba_auth_user ON public.ciba_auth_requests USING btree (user_id);

-- Phase B: idx_clients_* indexes removed with the public.clients table.

CREATE INDEX idx_consent_grants_workspace ON public.oauth_consent_grants USING btree (workspace_id) WHERE (revoked_at IS NULL);

CREATE INDEX idx_consent_grants_user_client ON public.oauth_consent_grants USING btree (user_id, oauth_client_id, resource_server_id) WHERE (revoked_at IS NULL);

CREATE INDEX idx_credentials_created_at ON public.credentials USING btree (created_at);

CREATE INDEX idx_credentials_updated_at ON public.credentials USING btree (updated_at);

CREATE INDEX idx_deleg_policy_client_id ON public.delegation_policies USING btree (client_id);

CREATE INDEX idx_deleg_policy_lookup ON public.delegation_policies USING btree (workspace_id, role_name, agent_type, enabled);

CREATE INDEX idx_deleg_policy_workspace_id ON public.delegation_policies USING btree (workspace_id);

CREATE INDEX idx_deleg_token_expires ON public.delegation_tokens USING btree (expires_at) WHERE (status = 'active'::text);

CREATE INDEX idx_deleg_token_lookup ON public.delegation_tokens USING btree (workspace_id, client_id, status);

CREATE INDEX idx_deleg_token_policy ON public.delegation_tokens USING btree (policy_id);

CREATE INDEX idx_device_codes_device_code ON public.device_codes USING btree (device_code);

CREATE INDEX idx_device_codes_expires_at ON public.device_codes USING btree (expires_at);

CREATE INDEX idx_device_codes_status ON public.device_codes USING btree (status);

CREATE INDEX idx_device_codes_workspace_id ON public.device_codes USING btree (workspace_id);

CREATE INDEX idx_device_codes_user_code ON public.device_codes USING btree (user_code);

CREATE INDEX idx_device_codes_user_id ON public.device_codes USING btree (user_id);

CREATE INDEX idx_device_tokens_active ON public.device_tokens USING btree (is_active);

CREATE INDEX idx_device_tokens_workspace ON public.device_tokens USING btree (workspace_id);

CREATE INDEX idx_device_tokens_token ON public.device_tokens USING btree (device_token);

CREATE INDEX idx_device_tokens_user ON public.device_tokens USING btree (user_id);

CREATE INDEX idx_groups_created_at ON public.groups USING btree (created_at);

CREATE INDEX idx_groups_name ON public.groups USING btree (name);

CREATE INDEX idx_groups_workspace_id ON public.groups USING btree (workspace_id);

CREATE INDEX idx_groups_workspace_name ON public.groups USING btree (workspace_id, name);

CREATE INDEX idx_groups_updated_at ON public.groups USING btree (updated_at);

CREATE INDEX idx_mcp_oauth_clients_client_id ON public.mcp_oauth_clients USING btree (client_id);

CREATE INDEX idx_mcp_oauth_clients_hydra_client_id ON public.mcp_oauth_clients USING btree (hydra_client_id);

CREATE INDEX idx_mcp_oauth_clients_software_id ON public.mcp_oauth_clients(software_id) WHERE software_id IS NOT NULL;

CREATE INDEX idx_mcp_oauth_clients_home_ws ON public.mcp_oauth_clients(home_workspace_id) WHERE home_workspace_id IS NOT NULL;

CREATE INDEX idx_mcp_tools_rs ON public.mcp_tools USING btree (resource_server_id);

CREATE INDEX idx_mcp_tools_rs_generation ON public.mcp_tools USING btree (resource_server_id, last_scan_generation);

CREATE INDEX idx_mcp_tools_workspace ON public.mcp_tools USING btree (workspace_id);

CREATE INDEX idx_mfa_methods_client_id ON public.mfa_methods USING btree (client_id);

CREATE INDEX idx_mfa_methods_enabled ON public.mfa_methods USING btree (enabled);

CREATE INDEX idx_mfa_methods_type ON public.mfa_methods USING btree (method_type);

CREATE INDEX idx_mfa_methods_user_id ON public.mfa_methods USING btree (user_id);

-- migration_logs indexes — created defensively only if the table exists.
-- migration_logs is created by GORM AutoMigrate before this SQL runs.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'migration_logs') THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_migration_logs_workspace_id ON public.migration_logs USING btree (workspace_id)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_migration_logs_version ON public.migration_logs USING btree (version)';
  END IF;
END $$;

CREATE INDEX idx_oauth_scope_perms_permission ON public.oauth_scope_permissions USING btree (permission_id);

CREATE INDEX idx_oauth_scopes_parent ON public.oauth_scopes USING btree (parent_scope_id);

CREATE INDEX idx_oauth_scopes_rs ON public.oauth_scopes USING btree (resource_server_id);

CREATE INDEX idx_oauth_scopes_workspace ON public.oauth_scopes USING btree (workspace_id);

CREATE UNIQUE INDEX idx_oauth_scopes_workspace_global_scope ON public.oauth_scopes USING btree (workspace_id, scope_string) WHERE (resource_server_id IS NULL);

CREATE INDEX idx_oidc_identities_provider_user ON public.oidc_user_identities USING btree (provider_name, provider_user_id);

CREATE INDEX idx_oidc_identities_workspace ON public.oidc_user_identities USING btree (workspace_id);

CREATE INDEX idx_oidc_identities_user ON public.oidc_user_identities USING btree (workspace_id, user_id);

CREATE INDEX idx_oidc_providers_active ON public.oidc_providers USING btree (is_active);

CREATE INDEX idx_oidc_states_expires ON public.oidc_states USING btree (expires_at);

CREATE INDEX idx_oidc_states_token ON public.oidc_states USING btree (state_token);

CREATE INDEX idx_otp_entries_email ON public.otp_entries USING btree (email);

CREATE INDEX idx_otp_entries_expires_at ON public.otp_entries USING btree (expires_at);

CREATE INDEX idx_otp_entries_verified ON public.otp_entries USING btree (verified);

CREATE INDEX idx_pending_registrations_email ON public.pending_registrations USING btree (email);

CREATE INDEX idx_pending_registrations_expires_at ON public.pending_registrations USING btree (expires_at);

CREATE INDEX idx_pending_registrations_workspace_id ON public.pending_registrations USING btree (workspace_id);

CREATE UNIQUE INDEX idx_permissions_global_id ON public.permissions USING btree (id) WHERE (workspace_id IS NULL);

CREATE UNIQUE INDEX idx_permissions_global_resource_action ON public.permissions USING btree (resource, action) WHERE (workspace_id IS NULL);

CREATE UNIQUE INDEX idx_permissions_workspace_resource_action_unique ON public.permissions USING btree (workspace_id, resource, action);

CREATE INDEX idx_pkce_verifiers_expires_at ON public.pkce_verifiers USING btree (expires_at);

CREATE INDEX idx_rb_workspace_group ON public.role_bindings USING btree (workspace_id, group_id) WHERE (group_id IS NOT NULL);

-- Atomic approve-with-role (plan §1) creates RS-scoped bindings
-- (scope_type='resource_server', scope_id=rs.id). These partial unique indexes
-- make the grant idempotent and race-proof: two admins approving the identical
-- connection+role+subject can no longer create duplicate bindings (the insert
-- uses ON CONFLICT DO NOTHING). Scoped to scope_type='resource_server' so
-- tenant-wide / wildcard bindings are unaffected.
CREATE UNIQUE INDEX uq_rb_user_rs
    ON public.role_bindings (workspace_id, role_id, scope_id, user_id)
    WHERE scope_type = 'resource_server' AND user_id IS NOT NULL;
CREATE UNIQUE INDEX uq_rb_sa_rs
    ON public.role_bindings (workspace_id, role_id, scope_id, service_account_id)
    WHERE scope_type = 'resource_server' AND service_account_id IS NOT NULL;

CREATE INDEX idx_resource_servers_resource_uri ON public.resource_servers USING btree (resource_uri);

CREATE UNIQUE INDEX idx_resource_servers_resource_uri_active
    ON public.resource_servers (resource_uri);

-- Composite unique for (id, workspace_id) — enables composite FK references

CREATE INDEX idx_resource_servers_state ON public.resource_servers USING btree (state);

-- idx_resource_servers_workspace_id already created at line 1544 (v4 block)

CREATE INDEX idx_risk_policies_action ON public.risk_policies USING btree (action_pattern);

CREATE INDEX idx_risk_policies_active ON public.risk_policies USING btree (is_active);

CREATE UNIQUE INDEX idx_risk_policies_name_workspace ON public.risk_policies USING btree (workspace_id, name);

CREATE INDEX idx_risk_policies_workspace ON public.risk_policies USING btree (workspace_id);

CREATE INDEX idx_role_assignment_requests_role_id ON public.role_assignment_requests USING btree (role_id);

CREATE INDEX idx_role_assignment_requests_status ON public.role_assignment_requests USING btree (status);

CREATE INDEX idx_role_assignment_requests_workspace_id ON public.role_assignment_requests USING btree (workspace_id);

CREATE INDEX idx_role_assignment_requests_user_id ON public.role_assignment_requests USING btree (user_id);

CREATE INDEX idx_role_bindings_user_workspace ON public.role_bindings USING btree (user_id, workspace_id);

CREATE INDEX idx_role_permissions_permission_id ON public.role_permissions USING btree (permission_id);

CREATE INDEX idx_role_permissions_role_id ON public.role_permissions USING btree (role_id);

CREATE INDEX idx_roles_created_at ON public.roles USING btree (created_at);

CREATE UNIQUE INDEX idx_roles_global_id ON public.roles USING btree (id) WHERE (workspace_id IS NULL);

CREATE UNIQUE INDEX idx_roles_global_name ON public.roles USING btree (name) WHERE (workspace_id IS NULL);

CREATE INDEX idx_roles_name ON public.roles USING btree (name);

-- idx_roles_workspace_id already created in v4 block (line ~1555)

CREATE INDEX idx_roles_workspace_name ON public.roles USING btree (workspace_id, name);

CREATE INDEX idx_roles_updated_at ON public.roles USING btree (updated_at);

-- idx_rs_access_policies_workspace_id already created in v4 block (line ~1547)

CREATE INDEX idx_rs_drift_events_rs_occurred ON public.resource_server_drift_events USING btree (rs_id, occurred_at DESC);

CREATE INDEX idx_rs_manifest_attempts_rs_at ON public.resource_server_manifest_attempts USING btree (rs_id, attempted_at DESC);

CREATE INDEX idx_rs_status ON public.resource_servers USING btree (status) WHERE (active = true);

CREATE INDEX idx_rscr_client_id ON public.resource_server_client_registrations USING btree (oauth_client_id);

CREATE INDEX idx_rscr_rs_id ON public.resource_server_client_registrations USING btree (resource_server_id);

CREATE INDEX idx_saml_callback_states_expires_at ON public.saml_callback_states USING btree (expires_at);

CREATE INDEX idx_saml_callback_states_login_challenge ON public.saml_callback_states USING btree (login_challenge);

CREATE INDEX idx_saml_callback_states_workspace_id ON public.saml_callback_states USING btree (workspace_id);

CREATE INDEX idx_saml_requests_client_id ON public.saml_requests USING btree (client_id);

CREATE INDEX idx_saml_requests_expires_at ON public.saml_requests USING btree (expires_at);

CREATE INDEX idx_saml_requests_login_challenge ON public.saml_requests USING btree (login_challenge);

CREATE INDEX idx_saml_requests_workspace_id ON public.saml_requests USING btree (workspace_id);

CREATE INDEX idx_saml_sp_certificates_expires_at ON public.saml_sp_certificates USING btree (expires_at);

CREATE INDEX idx_saml_sp_certificates_workspace_id ON public.saml_sp_certificates USING btree (workspace_id);

CREATE INDEX idx_services_agent_accessible ON public.services USING btree (agent_accessible);

CREATE INDEX idx_services_created_by ON public.services USING btree (created_by);

CREATE INDEX idx_services_resource_id ON public.services USING btree (resource_id);

CREATE INDEX idx_services_type ON public.services USING btree (type);

CREATE UNIQUE INDEX idx_spire_oidc_tokens_jwt_id ON public.spire_oidc_tokens USING btree (jwt_id);

CREATE UNIQUE INDEX idx_spire_policies_name ON public.spire_policies USING btree (name);

CREATE UNIQUE INDEX idx_spire_workloads_spiffe_id ON public.spire_workloads USING btree (spiffe_id);

CREATE INDEX idx_sync_configs_active ON public.sync_configurations USING btree (is_active);

CREATE INDEX idx_sync_configs_client_id ON public.sync_configurations USING btree (client_id);

CREATE INDEX idx_sync_configs_sync_type ON public.sync_configurations USING btree (sync_type);

CREATE INDEX idx_sync_configs_workspace_id ON public.sync_configurations USING btree (workspace_id);

CREATE INDEX idx_sync_configs_workspace_type ON public.sync_configurations USING btree (workspace_id, sync_type);

CREATE INDEX idx_workspace_backup_code ON public.workspace_totp_backup_codes USING btree (code);

CREATE INDEX idx_workspace_backup_created_at ON public.workspace_totp_backup_codes USING btree (created_at);

CREATE INDEX idx_workspace_backup_workspace ON public.workspace_totp_backup_codes USING btree (workspace_id);

CREATE INDEX idx_workspace_backup_used ON public.workspace_totp_backup_codes USING btree (is_used);

CREATE INDEX idx_workspace_backup_user ON public.workspace_totp_backup_codes USING btree (user_id);

CREATE INDEX idx_workspace_backup_user_unused ON public.workspace_totp_backup_codes USING btree (user_id, is_used);

CREATE INDEX idx_workspace_ciba_auth_req_id ON public.workspace_ciba_auth_requests USING btree (auth_req_id);

CREATE INDEX idx_workspace_ciba_created_at ON public.workspace_ciba_auth_requests USING btree (created_at);

CREATE INDEX idx_workspace_ciba_expires_at ON public.workspace_ciba_auth_requests USING btree (expires_at);

CREATE INDEX idx_workspace_ciba_status ON public.workspace_ciba_auth_requests USING btree (status);

CREATE INDEX idx_workspace_ciba_workspace ON public.workspace_ciba_auth_requests USING btree (workspace_id);

CREATE INDEX idx_workspace_ciba_user ON public.workspace_ciba_auth_requests USING btree (user_id);

CREATE INDEX idx_workspace_ciba_user_status ON public.workspace_ciba_auth_requests USING btree (user_id, status);

CREATE INDEX idx_workspace_device_token_active ON public.workspace_device_tokens USING btree (is_active);

CREATE INDEX idx_workspace_device_token_device_token ON public.workspace_device_tokens USING btree (device_token);

CREATE INDEX idx_workspace_device_token_workspace ON public.workspace_device_tokens USING btree (workspace_id);

CREATE INDEX idx_workspace_device_token_user ON public.workspace_device_tokens USING btree (user_id);

CREATE UNIQUE INDEX idx_workspace_domains_domain_unique ON public.workspace_domains USING btree (domain);

CREATE INDEX idx_workspace_domains_domain_verified ON public.workspace_domains USING btree (domain, is_verified);

CREATE UNIQUE INDEX idx_workspace_domains_primary_per_workspace ON public.workspace_domains USING btree (workspace_id) WHERE (is_primary = true);

CREATE INDEX idx_workspace_domains_status ON public.workspace_domains USING btree (is_verified, kind);

CREATE INDEX idx_workspace_domains_workspace_id_primary ON public.workspace_domains USING btree (workspace_id, is_primary);

CREATE INDEX idx_workspace_domains_workspace_id_verified ON public.workspace_domains USING btree (workspace_id, is_verified);

-- Phase C: idx_workspace_hydra_clients_* removed (tenant_hydra_clients table dropped).

-- Phase 6: idx_workspace_mappings_* removed (tenant_mappings table dropped).

CREATE INDEX idx_workspace_totp_active ON public.workspace_totp_secrets USING btree (is_active);

CREATE INDEX idx_workspace_totp_created_at ON public.workspace_totp_secrets USING btree (created_at);

CREATE INDEX idx_workspace_totp_primary ON public.workspace_totp_secrets USING btree (is_primary);

CREATE INDEX idx_workspace_totp_workspace ON public.workspace_totp_secrets USING btree (workspace_id);

CREATE INDEX idx_workspace_totp_user ON public.workspace_totp_secrets USING btree (user_id);

CREATE INDEX idx_workspace_totp_user_active ON public.workspace_totp_secrets USING btree (user_id, is_active);







CREATE INDEX idx_teus_last_seen ON public.workspace_end_user_states USING btree (workspace_id, last_seen_at DESC);

CREATE INDEX idx_teus_workspace_plan ON public.workspace_end_user_states USING btree (workspace_id, plan_tier) WHERE (plan_tier IS NOT NULL);

CREATE INDEX idx_teus_workspace_status ON public.workspace_end_user_states USING btree (workspace_id, status);

-- workspace_user_memberships indexes removed (table dropped)

CREATE INDEX idx_totp_active ON public.totp_secrets USING btree (is_active, is_primary);

CREATE UNIQUE INDEX idx_totp_primary_device ON public.totp_secrets USING btree (user_id, workspace_id) WHERE (is_primary = true);

CREATE INDEX idx_totp_workspace ON public.totp_secrets USING btree (workspace_id);

CREATE INDEX idx_totp_user ON public.totp_secrets USING btree (user_id);

CREATE INDEX idx_ug_workspace_group ON public.user_groups USING btree (workspace_id, group_id);

CREATE INDEX idx_ug_workspace_user ON public.user_groups USING btree (workspace_id, user_id);

CREATE INDEX idx_users_account_locked ON public.users USING btree (account_locked_at) WHERE (account_locked_at IS NOT NULL);

CREATE INDEX idx_users_active ON public.users USING btree (active);

CREATE INDEX idx_users_client_email ON public.users USING btree (client_id, email);

CREATE INDEX idx_users_client_email_lower ON public.users USING btree (client_id, lower((email)::text));

CREATE INDEX idx_users_client_id ON public.users USING btree (client_id);

CREATE INDEX idx_users_created_at ON public.users USING btree (created_at);

CREATE INDEX idx_users_created_at_desc ON public.users USING btree (created_at DESC);

CREATE INDEX idx_users_deleted_at ON public.users USING btree (deleted_at);

CREATE INDEX idx_users_email ON public.users USING btree (email);

CREATE INDEX idx_users_email_client ON public.users USING btree (email, client_id);

CREATE INDEX idx_users_email_workspace ON public.users USING btree (email, workspace_id);

CREATE INDEX idx_users_external_id ON public.users USING btree (external_id);

CREATE INDEX idx_users_is_primary_admin ON public.users USING btree (is_primary_admin) WHERE (is_primary_admin = true);

CREATE INDEX idx_users_last_login ON public.users USING btree (last_login DESC) WHERE (last_login IS NOT NULL);

CREATE INDEX idx_users_mfa ON public.users USING btree (mfa_enabled, mfa_verified);

CREATE INDEX idx_users_mfa_method ON public.users USING gin (mfa_method);

CREATE INDEX idx_users_password_change_required ON public.users USING btree (password_change_required) WHERE (password_change_required = true);

CREATE INDEX idx_users_project_id ON public.users USING btree (project_id);

CREATE INDEX idx_users_provider ON public.users USING btree (workspace_id, provider, provider_id);

CREATE INDEX idx_users_provider_data ON public.users USING gin (provider_data);

CREATE UNIQUE INDEX idx_users_workspace_provider_provider_id ON public.users USING btree (workspace_id, provider, provider_id) WHERE (provider_id IS NOT NULL AND deleted_at IS NULL);

CREATE INDEX idx_users_provider_status ON public.users USING btree (provider, active);

CREATE INDEX idx_users_sync_info ON public.users USING btree (sync_source, is_synced_user);

CREATE INDEX idx_users_sync_source ON public.users USING btree (sync_source);

CREATE INDEX idx_users_temp_password_expires_at ON public.users USING btree (temporary_password_expires_at) WHERE (temporary_password_expires_at IS NOT NULL);

CREATE INDEX idx_users_temporary_password ON public.users USING btree (temporary_password) WHERE (temporary_password = true);

CREATE INDEX idx_users_workspace_domain ON public.users USING btree (workspace_domain);

-- idx_users_workspace_email: the UNIQUE partial index (line ~2064) supersedes this plain index

CREATE INDEX idx_users_workspace_id ON public.users USING btree (workspace_id);

CREATE INDEX idx_users_workspace_id_active ON public.users USING btree (workspace_id, active) WHERE (active = true);

-- Phase A: canonical multi-workspace identity constraint.
-- One user row per (workspace, email). Enforces "same email in two workspaces
-- = two distinct users" — the Slack/GitHub user model.
CREATE UNIQUE INDEX idx_users_workspace_email ON public.users (workspace_id, LOWER(email)) WHERE deleted_at IS NULL;

CREATE INDEX idx_users_workspace_project ON public.users USING btree (workspace_id, project_id);

CREATE INDEX idx_users_timestamps ON public.users USING btree (created_at, updated_at);

CREATE INDEX idx_users_updated_at ON public.users USING btree (updated_at);

CREATE INDEX idx_voice_identity_links_is_active ON public.voice_identity_links USING btree (is_active);

CREATE INDEX idx_voice_identity_links_workspace_id ON public.voice_identity_links USING btree (workspace_id);

CREATE INDEX idx_voice_identity_links_user_id ON public.voice_identity_links USING btree (user_id);

CREATE INDEX idx_voice_identity_links_voice_platform_user ON public.voice_identity_links USING btree (voice_platform, voice_user_id);

CREATE INDEX idx_voice_sessions_expires_at ON public.voice_sessions USING btree (expires_at);

CREATE INDEX idx_voice_sessions_session_token ON public.voice_sessions USING btree (session_token);

CREATE INDEX idx_voice_sessions_status ON public.voice_sessions USING btree (status);

CREATE INDEX idx_voice_sessions_workspace_id ON public.voice_sessions USING btree (workspace_id);

CREATE INDEX idx_voice_sessions_voice_user_id ON public.voice_sessions USING btree (voice_user_id);

CREATE INDEX idx_webauthn_sessions_created_at ON public.webauthn_sessions USING btree (created_at);

CREATE INDEX idx_webauthn_sessions_expires_at ON public.webauthn_sessions USING btree (expires_at);

CREATE INDEX idx_webauthn_sessions_user_id ON public.webauthn_sessions USING btree (user_id);

CREATE UNIQUE INDEX roles_name_workspace_unique ON public.roles USING btree (name, workspace_id);

CREATE TRIGGER oidc_providers_updated_at BEFORE UPDATE ON public.oidc_providers FOR EACH ROW EXECUTE FUNCTION public.update_oidc_providers_updated_at();

CREATE TRIGGER oidc_user_identities_updated_at BEFORE UPDATE ON public.oidc_user_identities FOR EACH ROW EXECUTE FUNCTION public.update_oidc_user_identities_updated_at();

CREATE TRIGGER trigger_device_codes_updated_at BEFORE UPDATE ON public.device_codes FOR EACH ROW EXECUTE FUNCTION public.update_device_codes_updated_at();

CREATE TRIGGER trigger_voice_identity_links_updated_at BEFORE UPDATE ON public.voice_identity_links FOR EACH ROW EXECUTE FUNCTION public.update_voice_identity_links_updated_at();

CREATE TRIGGER trigger_voice_sessions_updated_at BEFORE UPDATE ON public.voice_sessions FOR EACH ROW EXECUTE FUNCTION public.update_voice_sessions_updated_at();

CREATE TRIGGER update_services_updated_at BEFORE UPDATE ON public.services FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Phase C: update_workspace_hydra_clients_updated_at trigger removed (table dropped).

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE ONLY public.delegation_tokens
    ADD CONSTRAINT delegation_tokens_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.delegation_policies(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT fk_agent_action_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT fk_agent_action_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_guard_settings
    ADD CONSTRAINT fk_agent_guard_settings_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT fk_backup_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT fk_backup_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_device FOREIGN KEY (device_token_id) REFERENCES public.device_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_action_decisions
    ADD CONSTRAINT fk_decision_action FOREIGN KEY (action_request_id) REFERENCES public.agent_action_requests(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_token_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_token_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_creator FOREIGN KEY (workspace_id, created_by) REFERENCES public.users(workspace_id, id) ON DELETE SET NULL;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_group FOREIGN KEY (workspace_id, group_id) REFERENCES public.groups(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_role FOREIGN KEY (workspace_id, role_id) REFERENCES public.roles(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_user FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.risk_policies
    ADD CONSTRAINT fk_risk_policy_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.saml_sp_certificates
    ADD CONSTRAINT fk_saml_sp_cert_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.spire_policy_rules
    ADD CONSTRAINT fk_spire_policies_rules FOREIGN KEY (policy_id) REFERENCES public.spire_policies(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.spire_policy_actions
    ADD CONSTRAINT fk_spire_policy_rules_actions FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.spire_policy_conditions
    ADD CONSTRAINT fk_spire_policy_rules_conditions FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.spire_policy_resources
    ADD CONSTRAINT fk_spire_policy_rules_resources FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.spire_policy_subjects
    ADD CONSTRAINT fk_spire_policy_rules_subjects FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sync_runs
    ADD CONSTRAINT sync_runs_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sync_runs
    ADD CONSTRAINT sync_runs_triggered_by_user_id_fkey FOREIGN KEY (triggered_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.workspace_totp_backup_codes
    ADD CONSTRAINT fk_workspace_backup FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_totp_backup_codes
    ADD CONSTRAINT fk_workspace_backup_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_ciba_auth_requests
    ADD CONSTRAINT fk_workspace_ciba_device FOREIGN KEY (device_token_id, workspace_id) REFERENCES public.workspace_device_tokens(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_ciba_auth_requests
    ADD CONSTRAINT fk_workspace_ciba FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_ciba_auth_requests
    ADD CONSTRAINT fk_workspace_ciba_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_device_tokens
    ADD CONSTRAINT fk_workspace_device FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_device_tokens
    ADD CONSTRAINT fk_workspace_device_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_domains
    ADD CONSTRAINT fk_workspace_domains_workspace_id FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_totp_secrets
    ADD CONSTRAINT fk_workspace_totp FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_totp_secrets
    ADD CONSTRAINT fk_workspace_totp_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_end_user_states
    ADD CONSTRAINT fk_teus_suspended_by FOREIGN KEY (suspended_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.workspace_end_user_states
    ADD CONSTRAINT fk_teus_user FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

-- workspace_user_memberships FKs removed (table dropped)

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT fk_totp_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT fk_totp_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_added_by FOREIGN KEY (added_by) REFERENCES public.users(id) ON DELETE SET NULL;

-- Composite FK so a user can only be added to a group in the SAME workspace.
-- Matches groups' UNIQUE (workspace_id, id).
ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_group FOREIGN KEY (group_id, workspace_id) REFERENCES public.groups(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_user FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.oauth_scopes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.mcp_tools(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_is_public_acknowledged_by_fkey FOREIGN KEY (is_public_acknowledged_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_rs_workspace_fkey FOREIGN KEY (resource_server_id, workspace_id) REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.identity_providers
    ADD CONSTRAINT identity_providers_saml_fkey FOREIGN KEY (saml_provider_id, workspace_id) REFERENCES public.saml_providers(id, workspace_id) ON DELETE SET NULL;

-- Workspace-ownership FKs (schema-enforced, not just app convention).
-- saml_providers.workspace_id is NOT NULL (always workspace-owned).
ALTER TABLE ONLY public.saml_providers
    ADD CONSTRAINT saml_providers_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- oidc_providers.workspace_id is nullable (NULL = platform provider shared across
-- workspaces); MATCH SIMPLE skips the FK when NULL, enforces it otherwise.
ALTER TABLE ONLY public.oidc_providers
    ADD CONSTRAINT oidc_providers_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- scope_catalog_entries.workspace_id is NOT NULL (always workspace-owned).
ALTER TABLE ONLY public.scope_catalog_entries
    ADD CONSTRAINT scope_catalog_entries_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_oauth_clients
    ADD CONSTRAINT mcp_oauth_clients_home_workspace_fkey FOREIGN KEY (home_workspace_id) REFERENCES public.workspaces(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES public.mcp_oauth_clients(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_rs_workspace_fkey FOREIGN KEY (resource_server_id, workspace_id) REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_scope_permissions
    ADD CONSTRAINT oauth_scope_permissions_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.oauth_scopes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_parent_scope_id_fkey FOREIGN KEY (parent_scope_id) REFERENCES public.oauth_scopes(id) ON DELETE SET NULL;

-- Composite FK so a scope's owning resource server is in the SAME workspace as
-- the scope. resource_server_id is nullable (workspace-level scopes with no RS);
-- MATCH SIMPLE skips the check when it is NULL. Matches resource_servers'
-- UNIQUE (id, workspace_id).
ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_resource_server_id_fkey FOREIGN KEY (resource_server_id, workspace_id) REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.oidc_user_identities
    ADD CONSTRAINT oidc_user_identities_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- Composite workspace-safe FKs: guarantee referenced role/RS is in the same workspace.
ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_default_role_id_fkey FOREIGN KEY (default_role_id, workspace_id) REFERENCES public.roles(id, workspace_id) ON DELETE SET NULL;

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_resource_server_id_fkey FOREIGN KEY (resource_server_id, workspace_id) REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES public.mcp_oauth_clients(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_rs_workspace_fkey FOREIGN KEY (resource_server_id, workspace_id) REFERENCES public.resource_servers(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_drift_event_dismissals
    ADD CONSTRAINT resource_server_drift_event_dismissals_admin_user_id_fkey FOREIGN KEY (admin_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_drift_event_dismissals
    ADD CONSTRAINT resource_server_drift_event_dismissals_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.resource_server_drift_events(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_drift_events
    ADD CONSTRAINT resource_server_drift_events_occurred_by_fkey FOREIGN KEY (occurred_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.resource_server_drift_events
    ADD CONSTRAINT resource_server_drift_events_rs_id_fkey FOREIGN KEY (rs_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_manifest_attempts
    ADD CONSTRAINT resource_server_manifest_attempts_rs_id_fkey FOREIGN KEY (rs_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.auth_request_contexts
    ADD CONSTRAINT auth_request_contexts_rs_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_servers
    ADD CONSTRAINT resource_servers_setup_completed_by_fkey FOREIGN KEY (setup_completed_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_role_id_fkey FOREIGN KEY (role_id, workspace_id) REFERENCES public.roles(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_user_id_fkey FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

-- role_bindings: composite FKs guarantee role and user are in the same workspace.
-- Simple (single-column) FKs removed — the composite ones are strictly stronger.
ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_workspace_role_fk FOREIGN KEY (workspace_id, role_id) REFERENCES public.roles(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_workspace_user_fk FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

-- role_permissions: simple FK kept because this table has no workspace_id column.
-- Cross-workspace safety is enforced by the application layer (ScopeRegistryService
-- validates workspace ownership before writing rows).
ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_end_user_states
    ADD CONSTRAINT workspace_end_user_states_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- workspace_memberships: composite FK guarantees role is in the same workspace.
ALTER TABLE ONLY public.workspace_memberships
    ADD CONSTRAINT workspace_memberships_role_workspace_fk FOREIGN KEY (role_id, workspace_id) REFERENCES public.roles(id, workspace_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT voice_identity_links_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT voice_sessions_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- ============================================================================
-- Phase 3: XAA / ID-JAG redemption (Agent Identity)
-- ============================================================================

-- trusted_issuers: known external AS principals that may issue ID-JAGs
-- redeemable at this AuthSec instance. provider_name links to
-- oidc_user_identities for subject materialization (spec (a)).
CREATE TABLE public.trusted_issuers (
    id              uuid    DEFAULT gen_random_uuid() NOT NULL,
    iss             text    NOT NULL,
    jwks_uri        text    NOT NULL,
    allowed_algs    text[]  NOT NULL DEFAULT ARRAY['RS256'::text],
    allowed_auds    text[]  NOT NULL DEFAULT ARRAY[]::text[],
    clock_skew_secs int     NOT NULL DEFAULT 30,
    workspace_claim_mapping text,
    subject_mapping text,
    provider_name   text    NOT NULL,
    jit_provisioning bool   NOT NULL DEFAULT false,
    status          text    NOT NULL DEFAULT 'active',
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT trusted_issuers_pkey PRIMARY KEY (id),
    CONSTRAINT trusted_issuers_status_chk CHECK (status IN ('active', 'revoked'))
);
CREATE UNIQUE INDEX uq_trusted_issuers_iss ON public.trusted_issuers (iss);
CREATE INDEX idx_trusted_issuers_provider_name ON public.trusted_issuers (provider_name);

-- a2a_brokering_policies: permit/deny rules for XAA requester→RS pairings.
-- side='redemption' gates incoming ID-JAG redemption; side='issuance' gates
-- outbound ID-JAG issuance (Phase 5).
CREATE TABLE public.a2a_brokering_policies (
    id              uuid    DEFAULT gen_random_uuid() NOT NULL,
    workspace_id    uuid    NOT NULL,
    side            text    NOT NULL CONSTRAINT a2a_brokering_policies_side_chk
                        CHECK (side IN ('redemption','issuance')),
    client_id       text,
    resource_server_id uuid,
    effect          text    NOT NULL DEFAULT 'permit'
                        CONSTRAINT a2a_brokering_policies_effect_chk
                        CHECK (effect IN ('permit','deny')),
    conditions      jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT a2a_brokering_policies_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_a2a_brokering_ws ON public.a2a_brokering_policies (workspace_id);
CREATE INDEX idx_a2a_brokering_side_rs ON public.a2a_brokering_policies (side, resource_server_id);

-- access_requests: coordination table for "identity wants access but has no
-- grant yet". Drives the admin queue, requester status, and notifications.
-- NOT an authority for token issuance — that remains registration + live RBAC.
CREATE TABLE public.access_requests (
    id                  uuid    DEFAULT gen_random_uuid() NOT NULL,
    workspace_id        uuid    NOT NULL,
    resource_server_id  uuid    NOT NULL,
    subject_type        text    NOT NULL
                            CONSTRAINT access_requests_subject_type_chk
                            CHECK (subject_type IN ('user','service_account')),
    subject_id          uuid    NOT NULL,
    requested_by_client text    NOT NULL,
    requested_scopes    text    NOT NULL DEFAULT '',
    requested_rar_id    uuid,
    authorization_details jsonb,
    status              text    NOT NULL DEFAULT 'pending'
                            CONSTRAINT access_requests_status_chk
                            CHECK (status IN ('pending','approved','denied','expired','revoked')),
    reason              text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz,
    decided_by          uuid,
    decided_at          timestamptz,
    -- Governance intent on the LIVE request pipeline. Deliberately here and not on
    -- role_assignment_requests: that table is vestigial (no service or controller
    -- reads it) and lacks expires_at, requested_scopes, and a usable status enum.
    justification       text    NOT NULL DEFAULT '',
    -- What the access is FOR, in the requester's words. Certification compares
    -- stated purpose against observed usage, which needs it captured up front.
    purpose             text    NOT NULL DEFAULT '',
    request_origin      text    NOT NULL DEFAULT 'admin'
                            CONSTRAINT access_requests_origin_chk
                            CHECK (request_origin IN ('discovery_claim','self_service',
                                                      'birthright','admin','escalation')),
    -- What was ASKED for, as distinct from expires_at, which is what was GRANTED.
    -- Keeping both makes "we always cut requests down" visible instead of folklore.
    requested_duration  interval,
    discovered_agent_id uuid,
    CONSTRAINT access_requests_pkey PRIMARY KEY (id)
);
-- §2: at most one open pending row per (subject, rs, client). ON CONFLICT
-- refreshes updated_at so the requester sees a live record.
CREATE UNIQUE INDEX uq_access_req_open ON public.access_requests
    (workspace_id, resource_server_id, subject_type, subject_id, requested_by_client)
    WHERE status = 'pending';
CREATE INDEX idx_access_requests_workspace ON public.access_requests (workspace_id);
CREATE INDEX idx_access_requests_status ON public.access_requests (status);
CREATE INDEX idx_access_requests_resource_server ON public.access_requests (resource_server_id);
CREATE INDEX idx_access_requests_expires_at ON public.access_requests (expires_at)
    WHERE status = 'pending';

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT fk_access_requests_workspace
    FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT fk_access_requests_resource_server
    FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.a2a_brokering_policies
    ADD CONSTRAINT fk_a2a_brokering_workspace
    FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- ============================================================================
-- Seed data: system workspace + base permissions + role bindings
-- ============================================================================
-- IMPORTANT: pg_dump set `search_path = ''` at the top of this file (line 42)
-- so every schema object reference above is `public.<name>`. The seed blocks
-- below were authored against the default search_path and use unqualified
-- names like `INSERT INTO workspaces`. Restore the public schema on the path
-- so those resolve; otherwise the bootstrap fails with
-- `ERROR: relation does not exist (legacy comment)`.
SET search_path TO public;

-- Migration 103: Add permissions for User Flow Service
-- Fixed to use production schema (no resources table, permissions uses workspace_id/resource/action)
-- Fixed: uses check-before-insert instead of ON CONFLICT ON CONSTRAINT (constraint may not exist yet)
-- Fixed: removed full_permission_string column (added by migration 109, not available yet)

DO $$
DECLARE
    sys_workspace CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Phase 6: system workspace seed (replaces the legacy tenants seed).
    -- Workspaces table is defined further down; this DO block runs in the same
    -- transaction once the whole file has been loaded, so the table reference
    -- resolves correctly.
    -- (The actual INSERT into workspaces lives in a later DO block, below the
    -- workspaces CREATE TABLE.)

    -- Ensure users:delete permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE workspace_id = sys_workspace AND resource = 'users' AND action = 'delete'
    ) THEN
        INSERT INTO permissions (id, workspace_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_workspace, 'users', 'delete', 'Delete a user', NOW());
    END IF;

    -- Ensure users:read permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE workspace_id = sys_workspace AND resource = 'users' AND action = 'read'
    ) THEN
        INSERT INTO permissions (id, workspace_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_workspace, 'users', 'read', 'Read user information', NOW());
    END IF;

    -- Ensure users:write permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE workspace_id = sys_workspace AND resource = 'users' AND action = 'write'
    ) THEN
        INSERT INTO permissions (id, workspace_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_workspace, 'users', 'write', 'Create and update users', NOW());
    END IF;

    -- Assign permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id
    FROM roles r, permissions p
    WHERE r.name = 'admin' AND r.workspace_id = sys_workspace
      AND p.workspace_id = sys_workspace
      AND p.resource = 'users'
      AND p.action IN ('delete', 'read', 'write')
    ON CONFLICT DO NOTHING;
END $$;


-- Phase 2 (tenant → workspace migration): seed the system workspace mirroring
-- the system workspace. Both rows share UUID 00000000-...000. Future phases drop
-- the workspaces table; the system workspace stays as the anchor for
-- platform-level permissions/role bindings.
-- Placed AFTER the workspaces CREATE TABLE — earlier Migration 103 seeds
-- run before this table exists.
DO $$
DECLARE
    sys_workspace CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, created_at, updated_at)
    VALUES (sys_workspace, 'System', NULL, sys_workspace, 'team', NOW(), NOW())
    ON CONFLICT (id) DO NOTHING;
END $$;

-- Migration 200: RBAC permissions for authsec-migration service
-- Fixed to use production permissions schema (workspace_id, resource, action) instead of old (resource_id, action)

DO $$
DECLARE
    sys_workspace CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Phase 6: ensure system workspace exists (replaces legacy tenants seed).
    INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, workspace_domain, email, status, created_at, updated_at)
    VALUES (sys_workspace, 'System', NULL, sys_workspace, 'team', 'system.authsec.dev', 'system@authsec.local', 'active', NOW(), NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Create migrations permissions
    INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
    VALUES
        (gen_random_uuid(), sys_workspace, 'migrations', 'admin', 'Full admin access to migration operations', 'migrations:admin', NOW()),
        (gen_random_uuid(), sys_workspace, 'migrations', 'run', 'Execute database migrations', 'migrations:run', NOW()),
        (gen_random_uuid(), sys_workspace, 'migrations', 'view', 'View migration status and history', 'migrations:view', NOW()),
        (gen_random_uuid(), sys_workspace, 'migrations', 'create_workspace_db', 'Create new workspace databases', 'migrations:create_workspace_db', NOW())
    ON CONFLICT ON CONSTRAINT permissions_workspace_resource_action_key DO NOTHING;

    -- Assign migration admin permissions to super_admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'super_admin' AND ro.workspace_id = sys_workspace
      AND p.workspace_id = sys_workspace AND p.resource = 'migrations'
    ON CONFLICT DO NOTHING;

    -- Assign migration permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'admin' AND ro.workspace_id = sys_workspace
      AND p.workspace_id = sys_workspace AND p.resource = 'migrations'
      AND p.action IN ('admin', 'run', 'create_workspace_db')
    ON CONFLICT DO NOTHING;
END $$;
-- Phase 4a: PDP policies + issuance audit ---------------------------------

-- policies — permit/deny rules evaluated by the token-issuance PDP.
-- explicit-deny-wins: a deny rule at any priority beats any permit.
-- subject_id / client_id / resource_server_id NULL means "wildcard".
CREATE TABLE public.policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    subject_type text CHECK (subject_type IN ('user', 'service_account', '*')),
    subject_id uuid,
    client_id text,
    resource_server_id uuid,
    token_family text NOT NULL DEFAULT '*'
        CHECK (token_family IN ('m2m', 'xaa', 'ciba', '*')),
    effect text NOT NULL DEFAULT 'permit'
        CHECK (effect IN ('permit', 'deny')),
    priority int NOT NULL DEFAULT 0,
    conditions jsonb,
    is_active bool NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT policies_pkey PRIMARY KEY (id),
    CONSTRAINT fk_policies_workspace FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE
);

CREATE INDEX idx_policies_workspace ON public.policies(workspace_id);
CREATE INDEX idx_policies_active ON public.policies(workspace_id, is_active, priority DESC);

-- auth_issuance_audit — shadow-mode comparison log.
-- pdp_effect: what the PDP decided ('permit'/'deny'/'no_policy').
-- gate_effect: what the thin gate (P2/P3 RBAC+registration checks) decided.
-- pdp_agrees: true when they agree (or pdp has no opinion).
CREATE TABLE public.auth_issuance_audit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    token_family text NOT NULL,
    client_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid,
    resource_server_id uuid NOT NULL,
    pdp_effect text NOT NULL CHECK (pdp_effect IN ('permit', 'deny', 'no_policy')),
    gate_effect text NOT NULL CHECK (gate_effect IN ('permit', 'deny')),
    pdp_agrees bool NOT NULL,
    scopes_requested text NOT NULL DEFAULT '',
    scopes_granted text NOT NULL DEFAULT '',
    pdp_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT auth_issuance_audit_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_auth_issuance_audit_ws ON public.auth_issuance_audit(workspace_id);
CREATE INDEX idx_auth_issuance_audit_created ON public.auth_issuance_audit(created_at);

-- Migration 201: RBAC permission for template-based workspace DB creation
-- Requires JWT + admin role (not service token)

DO $$
DECLARE
    sys_workspace CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Phase 6: ensure system workspace exists (replaces legacy tenants seed).
    INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, workspace_domain, email, status, created_at, updated_at)
    VALUES (sys_workspace, 'System', NULL, sys_workspace, 'team', 'system.authsec.dev', 'system@authsec.local', 'active', NOW(), NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Create template cloning permission
    INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
    VALUES
        (gen_random_uuid(), sys_workspace, 'migrations', 'create_workspace_from_template', 'Create workspace databases by cloning golden template', 'migrations:create_workspace_from_template', NOW())
    ON CONFLICT ON CONSTRAINT permissions_workspace_resource_action_key DO NOTHING;

    -- Assign to super_admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'super_admin' AND ro.workspace_id = sys_workspace
      AND p.workspace_id = sys_workspace AND p.resource = 'migrations'
      AND p.action = 'create_workspace_from_template'
    ON CONFLICT DO NOTHING;

    -- Assign to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'admin' AND ro.workspace_id = sys_workspace
      AND p.workspace_id = sys_workspace AND p.resource = 'migrations'
      AND p.action = 'create_workspace_from_template'
    ON CONFLICT DO NOTHING;
END $$;

-- Connectors -------------------------------------------------------------
-- A workspace-scoped registry of integration connectors (HubSpot, Mixpanel,
-- Segment, …) modelled on the Descope/Segment shape: provider + non-secret
-- config + event subscriptions/field-mappings. Secrets (apiKey/writeKey/…)
-- live in Vault, not here. Runtime consumer is agents over SPIFFE JWT-SVID.

-- connector_providers — fixed catalog of supported integration types.
-- Seeded below; not created by tenants. config_schema/secret_keys describe
-- which config fields are allowed and which route to Vault.
CREATE TABLE public.connector_providers (
    key                    text NOT NULL,
    display_name           text NOT NULL,
    component_type         text NOT NULL DEFAULT '',
    config_schema          jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_keys            text[] NOT NULL DEFAULT '{}'::text[],
    -- Which credential methods this provider supports. A provider can support
    -- more than one (e.g. api_key AND oauth2); the connect flow picks per use.
    supported_auth_methods text[] NOT NULL DEFAULT '{oauth2}'::text[],
    -- OAuth 2.0 endpoints + scope catalog (for the connect-once flow, P/B).
    oauth_authorize_url    text NOT NULL DEFAULT '',
    oauth_token_url        text NOT NULL DEFAULT '',
    oauth_scopes_supported text[] NOT NULL DEFAULT '{}'::text[],
    oauth_default_scopes   text[] NOT NULL DEFAULT '{}'::text[],
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_providers_pkey PRIMARY KEY (key)
);

-- connectors — per-workspace configured instances of a catalog provider.
-- config: non-secret settings (portalId, sampleRate, …).
-- subscriptions: the [{partnerAction, subscribe, mapping}] array, stored
--   verbatim as a declarative contract the agent reads (no event engine here).
-- vault_path: kv/data/secret/workspaces/{ws}/connectors/{id} holding the secrets.
CREATE TABLE public.connectors (
    id               uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL,
    provider_key     text NOT NULL,
    name             text NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    config           jsonb NOT NULL DEFAULT '{}'::jsonb,
    subscriptions    jsonb NOT NULL DEFAULT '[]'::jsonb,
    vault_path       text,
    agent_accessible boolean NOT NULL DEFAULT false,
    -- allowed_subject_groups (F5): if non-empty, a DELEGATED (XAA) action is only
    -- permitted when the on-behalf-of user is a member of one of these groups
    -- (group ids in this workspace). Empty = no subject-group restriction. Gates
    -- WHO an agent may act for at the broker; does not apply to non-delegated M2M
    -- calls (which have no human subject).
    allowed_subject_groups uuid[] NOT NULL DEFAULT '{}'::uuid[],
    created_by       text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connectors_pkey PRIMARY KEY (id),
    CONSTRAINT connectors_provider_fkey FOREIGN KEY (provider_key)
        REFERENCES public.connector_providers(key),
    CONSTRAINT connectors_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT connectors_workspace_name_key UNIQUE (workspace_id, name),
    -- Composite key so child tables (connections, assignments) reference a
    -- (workspace_id, connector_id) pair and cannot point across workspaces.
    CONSTRAINT connectors_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_connectors_workspace ON public.connectors(workspace_id);
CREATE INDEX idx_connectors_provider ON public.connectors(provider_key);

-- connector_connections — a credential binding + its lifecycle state (P1,
-- hardened). One connector holds a single workspace-scope connection and N
-- user-scope connections, each with independent lifecycle. Secret material
-- (api key / oauth token) lives in Vault at vault_path; PG holds only metadata.
--   binding_type='workspace' → subject_user_id NULL
--   binding_type='user'      → keyed by subject_user_id (a local user UUID)
-- Hardening: workspace_id + composite FK (no cross-workspace binding); CHECKs
-- pin binding_type/subject/status/auth_method consistency; NULL-safe PARTIAL
-- unique indexes (a plain UNIQUE lets duplicate workspace rows through because
-- Postgres treats NULLs as distinct); version column for optimistic-CAS on
-- refresh; external-account + lifecycle columns.
CREATE TABLE public.connector_connections (
    id                     uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id           uuid NOT NULL,
    connector_id           uuid NOT NULL,
    binding_type           text NOT NULL,                  -- 'workspace' | 'user'
    subject_user_id        uuid,                           -- NULL iff workspace-scope
    status                 text NOT NULL DEFAULT 'active',  -- active|expired|error|revoked|disconnected
    auth_method            text NOT NULL,                  -- 'api_key' | 'oauth2'
    vault_path             text NOT NULL,
    scopes_granted         text[] NOT NULL DEFAULT '{}'::text[],
    -- Non-secret external-account metadata (populated at OAuth callback) so the
    -- console can show which provider account/org a connection represents and
    -- warn on reconnect-with-different-account (F2).
    external_account_id    text,
    external_account_name  text,
    external_org_id        text,
    external_org_name      text,
    connected_by           text,
    -- OAuth lifecycle.
    access_expires_at      timestamptz,
    refresh_expires_at     timestamptz,
    refresh_token_present  boolean NOT NULL DEFAULT false,
    last_refresh_at        timestamptz,
    last_refresh_error     text,
    last_used_at           timestamptz,
    revoked_at             timestamptz,
    version                integer NOT NULL DEFAULT 1,      -- optimistic concurrency (refresh CAS)
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_connections_pkey PRIMARY KEY (id),
    CONSTRAINT connector_connections_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.connectors(workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT connector_connections_binding_chk CHECK (
        (binding_type = 'workspace' AND subject_user_id IS NULL)
        OR (binding_type = 'user' AND subject_user_id IS NOT NULL)),
    CONSTRAINT connector_connections_status_chk CHECK (
        status IN ('active', 'expired', 'error', 'revoked', 'disconnected')),
    CONSTRAINT connector_connections_auth_chk CHECK (
        auth_method IN ('api_key', 'oauth2', 'github_app'))
);

-- NULL-safe uniqueness: exactly one workspace connection per connector, and one
-- per (connector, user). Plain UNIQUE(connector_id, binding_type, subject_user_id)
-- would NOT prevent two workspace rows (subject_user_id NULL is distinct).
CREATE UNIQUE INDEX uq_conn_workspace ON public.connector_connections (connector_id)
    WHERE binding_type = 'workspace';
CREATE UNIQUE INDEX uq_conn_user ON public.connector_connections (connector_id, subject_user_id)
    WHERE binding_type = 'user';
CREATE INDEX idx_connector_connections_connector ON public.connector_connections(connector_id);
CREATE INDEX idx_connector_connections_subject ON public.connector_connections(subject_user_id);

-- connector_assignments — fine-grained authorization (P0). Controls which OAuth
-- client (agent) may use which connector + action on the broker data plane.
-- action_key NULL => all actions on the connector. The composite FK to
-- (workspace_id, connector_id) prevents cross-workspace assignment.
CREATE TABLE public.connector_assignments (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    client_id    text NOT NULL,        -- OAuth client / agent permitted
    action_key   text,                 -- NULL => all actions on this connector
    -- input_constraints (F3): optional per-assignment predicate over action
    -- inputs, e.g. {"owner":{"equals":"acme-eng"},"repo":{"glob":"release-*"}}.
    -- Enforced after input-schema validation, before the provider call. NULL/
    -- empty = no input restriction. Bounds WHERE an action runs.
    input_constraints jsonb,
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_assignments_pkey PRIMARY KEY (id),
    CONSTRAINT connector_assignments_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.connectors(workspace_id, id) ON DELETE CASCADE
);

-- Partial unique indexes: Postgres treats NULLs as distinct, so a plain UNIQUE
-- over (connector_id, client_id, action_key) would allow duplicate all-action
-- rows. Split the NULL and non-NULL cases.
CREATE UNIQUE INDEX uq_assign_all    ON public.connector_assignments (connector_id, client_id)             WHERE action_key IS NULL;
CREATE UNIQUE INDEX uq_assign_action ON public.connector_assignments (connector_id, client_id, action_key) WHERE action_key IS NOT NULL;
CREATE INDEX idx_connector_assignments_client ON public.connector_assignments(client_id);

-- connector_actions — the typed, invocable units, defined at the PROVIDER level
-- (every Slack connector exposes the same slack.postMessage). Keyed by
-- provider_key, not connector_id: with a curated catalog the actions are
-- intrinsic to the provider and identical across instances, so we avoid
-- duplicating rows per connector. Each action maps to a provider adapter that
-- fixes the HTTP method + base path (no caller-supplied URL — SSRF guard).
CREATE TABLE public.connector_actions (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    provider_key    text NOT NULL,
    action_key      text NOT NULL,                    -- 'postMessage', 'createIssue'
    display_name    text NOT NULL DEFAULT '',
    adapter_key     text NOT NULL,                    -- adapter that implements it
    http_method     text NOT NULL,                    -- adapter-fixed; NOT caller-supplied
    input_schema    jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_schema   jsonb NOT NULL DEFAULT '{}'::jsonb,
    required_scopes text[] NOT NULL DEFAULT '{}'::text[],
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_actions_pkey PRIMARY KEY (id),
    CONSTRAINT connector_actions_provider_fkey FOREIGN KEY (provider_key)
        REFERENCES public.connector_providers(key) ON DELETE CASCADE,
    CONSTRAINT connector_actions_provider_action_key UNIQUE (provider_key, action_key)
);

CREATE INDEX idx_connector_actions_provider ON public.connector_actions(provider_key);

-- connector_oauth_states — short-lived CSRF/PKCE state for the connect-once
-- OAuth flow (P3). Created at oauth/start, consumed once at oauth/callback,
-- expires quickly. Binds the returning code to the workspace + connector +
-- binding scope so the callback can't be replayed against another connector.
CREATE TABLE public.connector_oauth_states (
    state           text NOT NULL,
    workspace_id    uuid NOT NULL,
    connector_id    uuid NOT NULL,
    provider_key    text NOT NULL,
    binding_type    text NOT NULL DEFAULT 'workspace',  -- 'workspace' | 'user'
    subject_user_id text,                                -- for user-scope connect (P4)
    code_verifier   text NOT NULL,                       -- PKCE
    redirect_after  text,                                -- UI return URL
    created_by      text,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_oauth_states_pkey PRIMARY KEY (state)
);

CREATE INDEX idx_connector_oauth_states_expires ON public.connector_oauth_states(expires_at);

-- connector_action_audit — the durable "who did what, on whose behalf, with
-- which token" record for every broker action (allow AND deny). This is the
-- action-outcome accountability a token vault cannot produce: principal (sub),
-- actor (the agent/on-behalf-of client), token family+jti, connector+action,
-- outcome, and latency. Never stores secrets or the token itself.
CREATE TABLE public.connector_action_audit (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    connector_id    uuid,
    action_key      text NOT NULL,
    -- F8 — four orthogonal outcome fields (was one overloaded outcome+status):
    --  authz_outcome:   did the broker permit the attempt.       allow | deny
    --  broker_status:   broker-side HTTP (200, or 403/404/424 on deny-before-call).
    --  provider_status: real upstream HTTP; NULL when the broker denied first.
    --  action_outcome:  success | provider_error | policy_deny.
    authz_outcome   text NOT NULL,               -- allow | deny
    broker_status   int,
    provider_status int,
    action_outcome  text,                        -- success | provider_error | policy_deny
    deny_reason     text,
    subject_type    text,                        -- 'user' | 'service_account'
    subject_id      uuid,                        -- the principal (sub) — who
    actor_client_id text,                        -- the acting agent (act) — on behalf of
    actor_spiffe_id text,
    owner_email     text,                        -- accountable human (D1: owner always)
    owner_team      text,
    token_family    text,                        -- m2m | xaa | ciba — which token
    token_jti       text,
    latency_ms      bigint,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_action_audit_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_connector_action_audit_ws ON public.connector_action_audit(workspace_id);
CREATE INDEX idx_connector_action_audit_connector ON public.connector_action_audit(connector_id, created_at DESC);

-- connector_provider_apps — per-workspace OAuth application credentials for a
-- provider (AuthSec's registered app AT the provider, e.g. a workspace's own
-- GitHub OAuth app). client_id + redirect_uri are non-secret and live here; the
-- client_secret lives in Vault at vault_path. Resolution order in the connect
-- flow: this row for (workspace, provider) first, else the global env vars
-- (CONNECTOR_OAUTH_<P>_CLIENT_ID/_SECRET/_REDIRECT_URI). Lets each workspace
-- bring its own OAuth app instead of a single deployment-wide one.
CREATE TABLE public.connector_provider_apps (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    provider_key  text NOT NULL,
    -- app_kind distinguishes an OAuth app (code-exchange, has redirect_uri +
    -- client secret) from a GitHub-App-style bot install (JWT-signed
    -- installation tokens, has github_app_id + private key, no redirect).
    app_kind      text NOT NULL DEFAULT 'oauth2',   -- 'oauth2' | 'github_app'
    client_id     text NOT NULL DEFAULT '',         -- OAuth client_id (oauth2)
    redirect_uri  text NOT NULL DEFAULT '',         -- OAuth redirect (oauth2)
    github_app_id text NOT NULL DEFAULT '',         -- numeric App ID (github_app)
    vault_path    text NOT NULL,                    -- Vault: client_secret (oauth2) OR private key PEM (github_app)
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_provider_apps_pkey PRIMARY KEY (id),
    CONSTRAINT connector_provider_apps_ws_provider_key UNIQUE (workspace_id, provider_key)
);

-- Seed the curated OAuth provider catalog. All connect via OAuth 2.0. Slack and
-- GitHub carry the first typed actions (vertical slice); the rest are catalog
-- rows their adapters/actions clone the pattern onto.
INSERT INTO public.connector_providers
    (key, display_name, supported_auth_methods, oauth_authorize_url, oauth_token_url, oauth_scopes_supported, oauth_default_scopes)
VALUES
    ('slack',   'Slack',   '{oauth2}'::text[],
        'https://slack.com/oauth/v2/authorize', 'https://slack.com/api/oauth.v2.access',
        '{chat:write,channels:read,channels:history}'::text[], '{chat:write}'::text[]),
    ('github',  'GitHub',  '{oauth2}'::text[],
        'https://github.com/login/oauth/authorize', 'https://github.com/login/oauth/access_token',
        '{repo,read:org}'::text[], '{repo}'::text[]),
    ('google',  'Google',  '{oauth2}'::text[],
        'https://accounts.google.com/o/oauth2/v2/auth', 'https://oauth2.googleapis.com/token',
        '{https://www.googleapis.com/auth/gmail.send,https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/analytics.readonly}'::text[],
        '{}'::text[]),
    ('hubspot', 'HubSpot', '{oauth2}'::text[],
        'https://app.hubspot.com/oauth/authorize', 'https://api.hubapi.com/oauth/v1/token',
        '{crm.objects.contacts.read,crm.objects.contacts.write,crm.objects.deals.write}'::text[], '{}'::text[]),
    ('notion',  'Notion',  '{oauth2}'::text[],
        'https://api.notion.com/v1/oauth/authorize', 'https://api.notion.com/v1/oauth/token',
        '{}'::text[], '{}'::text[]),
    ('jira',    'Jira',    '{oauth2}'::text[],
        'https://auth.atlassian.com/authorize', 'https://auth.atlassian.com/oauth/token',
        '{read:jira-work,write:jira-work,offline_access}'::text[], '{read:jira-work,write:jira-work}'::text[])
ON CONFLICT (key) DO NOTHING;

-- Seed the first typed actions (vertical slice: Slack + GitHub). Each maps to a
-- provider adapter with a fixed HTTP method; input_schema is the typed contract
-- the agent fills. Other providers' actions clone this pattern.
INSERT INTO public.connector_actions
    (provider_key, action_key, display_name, adapter_key, http_method, input_schema, required_scopes)
VALUES
    ('slack', 'postMessage', 'Post a Slack message', 'slack', 'POST',
        '{"type":"object","required":["channel","text"],"properties":{"channel":{"type":"string"},"text":{"type":"string"}}}'::jsonb,
        '{chat:write}'::text[]),
    ('github', 'createIssue', 'Create a GitHub issue', 'github', 'POST',
        '{"type":"object","required":["owner","repo","title"],"properties":{"owner":{"type":"string"},"repo":{"type":"string"},"title":{"type":"string"},"body":{"type":"string"}}}'::jsonb,
        '{repo}'::text[]),
    ('github', 'listCommits', 'List recent commits', 'github', 'GET',
        '{"type":"object","required":["owner","repo"],"properties":{"owner":{"type":"string"},"repo":{"type":"string"},"per_page":{"type":"integer","minimum":1,"maximum":50,"description":"defaults to 10"}}}'::jsonb,
        '{repo}'::text[])
ON CONFLICT (provider_key, action_key) DO NOTHING;

-- Connector RBAC permissions — GLOBAL (workspace_id IS NULL) so they apply in
-- every workspace. hasDBPermission / the scope resolver match a permission when
-- p.workspace_id = caller_workspace OR p.workspace_id IS NULL, so a global
-- permission is the correct model for a platform-wide capability. Admins grant
-- the matching role to users per workspace via normal RBAC; a user holding a
-- role bound to these permissions can use connectors.
-- ON CONFLICT targets the partial unique index for NULL-workspace rows.
INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'connector', 'create',  'Create a connector',                  'connector:create',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'read',    'Read connectors',                     'connector:read',    NOW()),
    (gen_random_uuid(), NULL, 'connector', 'update',  'Update a connector',                  'connector:update',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'delete',  'Delete a connector',                  'connector:delete',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'config',  'Read connector config (non-secret)',  'connector:config',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'assign',  'Manage connector assignments',        'connector:assign',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'execute', 'Execute a connector action (broker)', 'connector:execute', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

-- Agent Discovery (IGA) ---------------------------------------------------
-- A quarantine-first inventory of every AI agent running in a workspace's
-- estate, including ones nobody registered. A sighting NEVER grants access: it
-- only makes an agent visible, which is what makes it safe to run discovery
-- against production before anything is provisioned or enforced. An agent
-- becomes a governed principal only when a human claims it (linking it to an
-- mcp_oauth_clients identity and an accountable owner) -- otherwise an admin
-- quarantines it.

-- discovery_sources -- a connector that produces sightings, whether an admin
-- configured it in the console or an agent registered itself.
--
-- kind: k8s_webhook and repo_scan are the active channels; aws/azure/gcp/
--   vm_sensor are designed but deferred and need no schema change to enable.
-- config: non-secret connector settings. Secrets belong in Vault, not here.
--
-- SELF-REGISTRATION. One control plane serves discovery agents in many clusters,
-- so it needs a first-class record of each one -- otherwise cluster identity
-- lives only inside sighting metadata and there is no way to list connected
-- clusters, see their agent versions, or tell a live agent from one that stopped
-- reporting last week. A self-registering agent upserts its own row here on
-- startup, heartbeats into last_heartbeat_at, and receives this row's id back so
-- every sighting it reports carries a real discovery_source_id.
--
-- instance_id is the stable key the agent asserts. For the Kubernetes connector
-- it derives from cluster.name, which is ALREADY part of every agent
-- fingerprint -- so renaming a cluster re-mints the connector row at exactly the
-- moment it re-mints the agent rows. Keying on display_name would instead break
-- the first time an admin renamed the connector in the console.
CREATE TABLE public.discovery_sources (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    kind         text NOT NULL,
    display_name text NOT NULL,
    config       jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled      boolean NOT NULL DEFAULT true,
    last_sync_at timestamptz,
    last_status  text NOT NULL DEFAULT '',
    last_error   text NOT NULL DEFAULT '',
    -- self-registration / liveness ('' for admin-configured connectors)
    instance_id       text NOT NULL DEFAULT '',
    cluster_name      text NOT NULL DEFAULT '',
    -- Corroborating fact, never a key: the kube-system namespace UID, immutable
    -- per cluster. Lets the control plane spot two DIFFERENT clusters installed
    -- with the same cluster.name (same instance_id, but the uid changed). Empty
    -- when the agent lacks RBAC to read it, which is the default.
    cluster_uid       text NOT NULL DEFAULT '',
    agent_version     text NOT NULL DEFAULT '',
    last_heartbeat_at timestamptz,
    -- Separates a machine-owned row (runtime fields overwritten by every
    -- heartbeat) from an admin-configured one.
    self_registered   boolean NOT NULL DEFAULT false,
    -- Last reported runtime snapshot: pod/node identity, resolved config,
    -- counters. Observability only -- no decision reads it, so it stays
    -- schemaless on purpose.
    runtime           jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Actuation credential. Only a HASH is stored: a leaked backup must not yield a
    -- working credential. The token identifies WHICH connector is calling, so an agent
    -- never asserts its own cluster.
    actuation_token_hash text NOT NULL DEFAULT '',
    actuation_enabled_at timestamptz,
    created_by   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovery_sources_pkey PRIMARY KEY (id),
    CONSTRAINT discovery_sources_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT discovery_sources_kind_chk CHECK (
        kind IN ('k8s_webhook', 'aws', 'azure', 'gcp', 'vm_sensor', 'repo_scan')),
    CONSTRAINT discovery_sources_workspace_kind_name_key UNIQUE (workspace_id, kind, display_name)
);

CREATE INDEX idx_discovery_sources_workspace ON public.discovery_sources(workspace_id);

-- The self-registration upsert target. PARTIAL so it constrains only
-- self-registered rows: admin-created connectors keep instance_id='' and any
-- number of them may coexist, which a plain UNIQUE would forbid.
CREATE UNIQUE INDEX discovery_sources_instance_key
    ON public.discovery_sources(workspace_id, kind, instance_id)
    WHERE instance_id <> '';

-- Answers "which clusters are reporting right now?" without a full scan.
CREATE INDEX idx_discovery_sources_heartbeat
    ON public.discovery_sources(workspace_id, last_heartbeat_at DESC);

-- discovered_agents -- one row per distinct agent sighting, keyed by a stable
-- fingerprint. UNIQUE(workspace_id, source, fingerprint) is what makes a
-- repeated sighting an upsert (a last_seen_at / sighting_count bump) instead of
-- a duplicate row -- the connector can re-report freely and idempotently.
--
-- status moves forward only (unregistered -> registered | quarantined |
--   ignored); it never returns to unregistered. 'ignored' is the "keep the row
--   but stop surfacing it" state, so there is no soft-delete column here.
-- runtime_status is a SEPARATE, orthogonal axis and must stay that way. `status`
--   is what a human DECIDED; runtime_status is what we OBSERVED (running |
--   stopped | gone | unknown), it is machine-written, and it moves both ways. An
--   agent that was claimed and later deleted must stay `registered` -- the audit
--   trail is the entire point -- while its runtime_status becomes `gone`.
--   Collapsing the two would force a choice between losing the governance
--   decision and lying about whether the workload is running.
-- deployment_origin: a manually run agent (a developer's script with no
--   pipeline behind it) is the higher-risk, harder-to-attribute case, since its
--   permissions are typically whatever the developer's own credentials allow --
--   so the Unregistered Agents report surfaces manual first. It is a heuristic;
--   an admin correction is audited like any other decision.
-- archetype: '' until known. Autonomous agents hold their own authority;
--   user-delegated agents borrow a scoped slice of a user's.
CREATE TABLE public.discovered_agents (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    source              text NOT NULL,
    discovery_source_id uuid,
    fingerprint         text NOT NULL,
    display_name        text NOT NULL DEFAULT '',
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
    deployment_origin   text NOT NULL DEFAULT 'unknown',
    archetype           text NOT NULL DEFAULT '',
    -- the governed identity this sighting was claimed into
    matched_client_id   uuid,
    -- the accountable human; mandatory to register (see registered_chk)
    owner_user_id       uuid,
    status              text NOT NULL DEFAULT 'unregistered',
    claimed_by          uuid,
    claimed_at          timestamptz,
    quarantined_by      uuid,
    quarantined_at      timestamptz,
    quarantine_reason   text NOT NULL DEFAULT '',
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    sighting_count      integer NOT NULL DEFAULT 1,
    -- observed runtime lifecycle (see the runtime_status note in the header)
    runtime_status      text NOT NULL DEFAULT 'unknown',
    -- Why runtime_status holds its value, in the agent's words ("deleted by
    -- alice@corp via Deployment DELETE"). Shown verbatim; a reviewer should never
    -- have to guess how we concluded an agent was gone.
    runtime_reason      text NOT NULL DEFAULT '',
    -- Observation time of the event that last set runtime_status -- NOT receive
    -- time. This is the monotonic guard: a sighting delayed in a retry queue must
    -- not resurrect an agent deleted after it was enqueued, so a transition
    -- applies only when its observed_at is at least as recent as this value.
    runtime_observed_at timestamptz,
    terminated_at       timestamptz,
    -- The principal the API SERVER attributed the DELETE to. The answer to "who
    -- destroyed this agent", and available only from admission: a resync can
    -- prove absence but can never attribute it.
    terminated_by       text NOT NULL DEFAULT '',
    -- Whether the quarantine DECISION has actually been enforced in the cluster. The
    -- same decision-versus-observation split as status vs runtime_status: an admin needs
    -- to know "I quarantined it" from "it is actually blocked".
    quarantine_enforced_at       timestamptz,
    quarantine_enforcement_error text NOT NULL DEFAULT '',
    -- When the quarantine was LIFTED. quarantined_at/by/reason deliberately survive a
    -- release as the record that it happened, so this is what separates a live
    -- quarantine from a historical one.
    quarantine_released_at timestamptz,
    quarantine_released_by uuid,
    -- The workload identity actually observed running. When it disagrees with the
    -- provisioned anchor, the entitlement is bound to an identity the workload lacks.
    observed_service_account text NOT NULL DEFAULT '',
    identity_verified_at     timestamptz,
    created_by          text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovered_agents_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agents_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- A single-column FK (not the composite (workspace_id, id) pattern used by
    -- connector children) because an agent must OUTLIVE its source: deleting a
    -- connector nulls the pointer and keeps the inventory row. A composite FK
    -- cannot ON DELETE SET NULL without nulling the NOT NULL workspace_id. The
    -- service only ever resolves a source inside the caller's workspace.
    CONSTRAINT discovered_agents_source_id_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agents_matched_client_fkey FOREIGN KEY (matched_client_id)
        REFERENCES public.mcp_oauth_clients(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agents_owner_fkey FOREIGN KEY (owner_user_id)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agents_source_chk CHECK (
        source IN ('k8s_webhook', 'aws', 'azure', 'gcp', 'vm_sensor', 'repo_scan')),
    CONSTRAINT discovered_agents_origin_chk CHECK (
        deployment_origin IN ('manual', 'automated', 'unknown')),
    CONSTRAINT discovered_agents_status_chk CHECK (
        status IN ('unregistered', 'registered', 'quarantined', 'ignored')),
    CONSTRAINT discovered_agents_archetype_chk CHECK (
        archetype IN ('', 'autonomous', 'user_delegated', 'hybrid')),
    CONSTRAINT discovered_agents_runtime_status_chk CHECK (
        runtime_status IN ('running', 'stopped', 'gone', 'unknown')),
    -- Registered means claimed: a governed principal always has both an identity
    -- to trace tokens to and an accountable human owner. Enforced in the DB so
    -- no code path can produce an unowned registered agent.
    CONSTRAINT discovered_agents_registered_chk CHECK (
        status <> 'registered'
        OR (matched_client_id IS NOT NULL AND owner_user_id IS NOT NULL)),
    CONSTRAINT discovered_agents_fingerprint_key UNIQUE (workspace_id, source, fingerprint)
);

CREATE INDEX idx_discovered_agents_workspace_status_origin
    ON public.discovered_agents(workspace_id, status, deployment_origin);
CREATE INDEX idx_discovered_agents_last_seen ON public.discovered_agents(last_seen_at);
-- The "show me agents that vanished" / "show me live agents" reports.
CREATE INDEX idx_discovered_agents_runtime
    ON public.discovered_agents(workspace_id, runtime_status);

-- discovered_agent_events -- the lifecycle trail behind runtime_status.
--
-- Append-only. The inventory row carries only the CURRENT runtime state; this is
-- the history, which is what makes "when and how was this agent destroyed"
-- answerable after the fact rather than merely "it is gone now".
--
-- Kept separate from audit_events deliberately: these are MACHINE observations of
-- third-party workloads, not administrator actions on AuthSec objects. They carry
-- no acting AuthSec user, they are far higher volume, and they are safe to prune
-- on a shorter retention -- all of which would be wrong for the admin audit log.
--
-- discovered_agent_id is nullable because an event can legitimately arrive for a
-- fingerprint we hold no sighting for: an agent created and destroyed between two
-- resyncs, or deleted while the reporting queue was backed up. Dropping such an
-- event would discard the only evidence that agent ever existed.
CREATE TABLE public.discovered_agent_events (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    discovered_agent_id uuid,
    discovery_source_id uuid,
    source              text NOT NULL,
    fingerprint         text NOT NULL,
    event               text NOT NULL,
    -- The runtime_status this event asserted, or '' for a purely informational
    -- event such as a controller-owned pod being rescheduled.
    runtime_status      text NOT NULL DEFAULT '',
    reason              text NOT NULL DEFAULT '',
    actor               text NOT NULL DEFAULT '',
    -- 'admission' | 'resync' | 'control_plane'. An admission event carries a
    -- trustworthy actor; a resync event never can.
    channel             text NOT NULL DEFAULT '',
    cluster_name        text NOT NULL DEFAULT '',
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at         timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovered_agent_events_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agent_events_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_events_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agent_events_source_id_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agent_events_event_chk CHECK (
        event IN ('observed', 'deleted', 'pod_terminated', 'absent', 'reappeared')),
    CONSTRAINT discovered_agent_events_runtime_chk CHECK (
        runtime_status IN ('', 'running', 'stopped', 'gone', 'unknown'))
);

CREATE INDEX idx_discovered_agent_events_agent
    ON public.discovered_agent_events(discovered_agent_id, observed_at DESC);
CREATE INDEX idx_discovered_agent_events_ws_fp
    ON public.discovered_agent_events(workspace_id, source, fingerprint, observed_at DESC);

-- Discovery RBAC permissions -- GLOBAL (workspace_id IS NULL) so they apply in
-- every workspace, exactly like the connector:* permissions above. Admins grant
-- the matching role per workspace via normal RBAC. discovery:report is split out
-- from the rest so a connector's service account can report sightings without
-- holding any authority to claim or quarantine.
INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'discovery', 'report',     'Report an agent sighting',            'discovery:report',     NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'read',       'Read the discovered-agent inventory', 'discovery:read',       NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'claim',      'Claim an agent into an identity',     'discovery:claim',      NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'quarantine', 'Quarantine a discovered agent',       'discovery:quarantine', NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'admin',      'Manage discovery sources',            'discovery:admin',      NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

-- =========================================================================
-- Agentic IGA — canonical model and evidence layer
-- =========================================================================
-- Implements the persistence contract in the GitHub Discovery Integration
-- specification (section 11.4). The GitHub Integration is the first consumer,
-- but nothing below is GitHub-specific: provider payloads live only in
-- iga_source_objects / iga_observations, never in a canonical table.
--
-- NAMING. The specification assumes an isolated IGA database, where these
-- tables would simply be called integrations, agents, observations and so on.
-- This deployment shares the AuthSec database, where `credentials` already
-- exists (WebAuthn) and `agents` / `resources` / `observations` are generic
-- enough to collide later. Every table is therefore prefixed `iga_`. Semantics
-- are unchanged; only the physical names differ.
--
-- THE CENTRAL IDEA. Evidence is preserved before it is interpreted:
--
--   source object  ->  observation  ->  candidate  ->  canonical object
--   (what GitHub     (a versioned     (a proposal    (agent, identity,
--    showed us)       fact + its       a human or     resource, edge)
--                     provenance)      rule makes)
--
-- Canonical rows never replace observations; iga_observation_links records
-- which observations support, contradict or previously supported each value.
-- That is what lets every displayed fact be drilled back to its evidence, and
-- what keeps "we did not look" distinct from "there is nothing there."
--
-- INVARIANTS ENFORCED IN THE DATABASE (spec 11.4.1):
--   * every tenant-owned row carries workspace_id NOT NULL
--   * every foreign key between tenant-owned tables is COMPOSITE and carries
--     workspace_id, so an object id from workspace A cannot bind to a row in
--     workspace B even if the id is valid
--   * a verified provider installation has exactly one active owner, enforced
--     by a uniqueness constraint that deliberately EXCLUDES workspace_id
--   * no secret material: only secret_ref plus non-secret key metadata
--   * coverage is stored per scope and object class and is never averaged
-- =========================================================================

-- ------------------------------------------------------------------ --
-- 1. Integration control plane                                        --
-- ------------------------------------------------------------------ --

-- iga_integrations — one verified binding between an AuthSec workspace and a
-- provider installation. requested_permissions and granted_permissions are
-- stored separately and never merged: the difference between what we asked for
-- and what we actually got is the honest basis for every coverage claim.
CREATE TABLE public.iga_integrations (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    provider              text NOT NULL,
    -- provider_host distinguishes github.com from a GHES hostname; it is part
    -- of the installation's global identity.
    provider_host         text NOT NULL,
    -- The AuthSec-side App registration this installation belongs to.
    app_registration_id   text NOT NULL,
    installation_id       text,
    account_native_id     text,
    capability_profile    jsonb NOT NULL DEFAULT '{}'::jsonb,
    requested_permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
    granted_permissions   jsonb NOT NULL DEFAULT '{}'::jsonb,
    status                text NOT NULL DEFAULT 'pending',
    -- Pointer into the approved secrets store. The App private key and any
    -- token material never touch this database.
    secret_ref            text NOT NULL DEFAULT '',
    -- NULL until the installation has been proven to belong to the
    -- authenticated provider administrator. A setup-URL installation_id is
    -- attacker-controllable, so it is untrusted until this is set.
    verified_at           timestamptz,
    -- One-time state for the install/authorize round trip. It is what ties the
    -- provider's callback back to the request WE started, so a callback that
    -- did not originate here cannot activate an integration.
    authorization_state      text,
    authorization_expires_at timestamptz,
    version               bigint NOT NULL DEFAULT 1,
    created_by            text NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_integrations_pkey PRIMARY KEY (id),
    CONSTRAINT iga_integrations_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_integrations_status_chk CHECK (
        status IN ('pending', 'active', 'degraded', 'disconnected', 'revoked')),
    -- Composite-FK target: children reference (workspace_id, id) as a pair.
    CONSTRAINT iga_integrations_workspace_id_key UNIQUE (workspace_id, id)
);

-- The cross-workspace rebinding guard. workspace_id is deliberately ABSENT
-- from this index: that is the entire point. Two workspaces cannot both hold a
-- verified binding to the same provider installation, so an installation
-- cannot be silently moved or duplicated into another tenant. Partial on
-- verified_at so abandoned half-finished authorizations do not block a retry.
CREATE UNIQUE INDEX uq_iga_integrations_verified_installation
    ON public.iga_integrations (provider_host, app_registration_id, installation_id)
    WHERE verified_at IS NOT NULL AND installation_id IS NOT NULL;

CREATE INDEX idx_iga_integrations_workspace_status
    ON public.iga_integrations (workspace_id, status);

-- The state must be globally unique and single-use: the callback arrives
-- unauthenticated, so the state is the only thing proving provenance.
CREATE UNIQUE INDEX uq_iga_integrations_auth_state
    ON public.iga_integrations (authorization_state)
    WHERE authorization_state IS NOT NULL;

-- iga_integration_scopes — the estate the customer actually selected. A scope
-- stays on the books even when excluded or denied, because "you did not select
-- this" and "we could not read this" are different answers and neither is zero.
CREATE TABLE public.iga_integration_scopes (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    integration_id        uuid NOT NULL,
    estate_scope_id       uuid,
    native_scope_kind     text NOT NULL,
    native_scope_id       text NOT NULL,
    selection_state       text NOT NULL DEFAULT 'selected',
    filters               jsonb NOT NULL DEFAULT '{}'::jsonb,
    effective_permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_integration_scopes_pkey PRIMARY KEY (id),
    CONSTRAINT iga_integration_scopes_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_integration_scopes_selection_chk CHECK (
        selection_state IN ('selected', 'excluded', 'denied', 'unknown')),
    CONSTRAINT iga_integration_scopes_native_key
        UNIQUE (workspace_id, integration_id, native_scope_kind, native_scope_id),
    CONSTRAINT iga_integration_scopes_workspace_id_key UNIQUE (workspace_id, id)
);

-- ------------------------------------------------------------------ --
-- 2. Scans, coverage and durable ingress                              --
-- ------------------------------------------------------------------ --

-- iga_scan_runs — one enumeration attempt. A generation becomes authoritative
-- ONLY on successful completion (see the CHECK): an interrupted scan must
-- never be allowed to prove that something was deleted.
CREATE TABLE public.iga_scan_runs (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    integration_id      uuid NOT NULL,
    mode                text NOT NULL,
    generation          bigint NOT NULL,
    status              text NOT NULL DEFAULT 'pending',
    requested_by        text NOT NULL DEFAULT '',
    normalizer_version  text NOT NULL DEFAULT '',
    rule_catalog_version text NOT NULL DEFAULT '',
    started_at          timestamptz,
    completed_at        timestamptz,
    counters            jsonb NOT NULL DEFAULT '{}'::jsonb,
    failure_code        text NOT NULL DEFAULT '',
    -- Set in the same transaction that publishes coverage; see 11.4.4.
    is_authoritative    boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_scan_runs_pkey PRIMARY KEY (id),
    CONSTRAINT iga_scan_runs_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_scan_runs_mode_chk CHECK (mode IN ('full', 'incremental', 'targeted')),
    CONSTRAINT iga_scan_runs_status_chk CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    -- The deletion-safety rule, expressed as a constraint rather than a
    -- convention: only a succeeded run may be authoritative.
    CONSTRAINT iga_scan_runs_authoritative_chk CHECK (
        is_authoritative = false OR status = 'succeeded'),
    CONSTRAINT iga_scan_runs_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_iga_scan_runs_workspace_integration
    ON public.iga_scan_runs (workspace_id, integration_id, created_at DESC);

-- iga_scan_checkpoints — resumable cursors. A worker that dies mid-scan leaves
-- a reclaimable lease and a cursor to resume from, so a restart never rescans
-- from zero and never silently skips a partition.
CREATE TABLE public.iga_scan_checkpoints (
    workspace_id  uuid NOT NULL,
    scan_run_id   uuid NOT NULL,
    object_class  text NOT NULL,
    partition_key text NOT NULL,
    cursor        text NOT NULL DEFAULT '',
    watermark     timestamptz,
    lease_owner   text,
    leased_until  timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_scan_checkpoints_pkey
        PRIMARY KEY (workspace_id, scan_run_id, object_class, partition_key),
    CONSTRAINT iga_scan_checkpoints_run_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id) ON DELETE CASCADE
);

-- iga_coverage_states — what could actually be inspected, per scope and per
-- object class. Deliberately has NO percentage column: averaging these states
-- into one reassuring number is the exact failure this table exists to prevent.
-- 'unknown' must never render as zero.
CREATE TABLE public.iga_coverage_states (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    integration_id        uuid NOT NULL,
    integration_scope_id  uuid NOT NULL,
    object_class          text NOT NULL,
    state                 text NOT NULL DEFAULT 'unknown',
    reason_code           text NOT NULL DEFAULT '',
    last_success_at       timestamptz,
    last_attempt_at       timestamptz,
    watermark             timestamptz,
    inspected_count       bigint NOT NULL DEFAULT 0,
    denied_count          bigint NOT NULL DEFAULT 0,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_coverage_states_pkey PRIMARY KEY (id),
    CONSTRAINT iga_coverage_states_scope_fkey
        FOREIGN KEY (workspace_id, integration_scope_id)
        REFERENCES public.iga_integration_scopes (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_coverage_states_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_coverage_states_state_chk CHECK (state IN (
        'complete_for_selected_scope',
        'partial',
        'unknown',
        'not_configured',
        'unsupported',
        'failed',
        'stale')),
    CONSTRAINT iga_coverage_states_key
        UNIQUE (workspace_id, integration_id, integration_scope_id, object_class)
);

CREATE INDEX idx_iga_coverage_states_workspace_class
    ON public.iga_coverage_states (workspace_id, object_class, state);

-- iga_webhook_deliveries — the provider ingress ledger.
--
-- workspace_id is NULLABLE here, unlike every other IGA table, and the reason
-- matters: a delivery is recorded at the moment it arrives, BEFORE the
-- App/installation binding has been resolved server-side. The payload's own
-- installation_id is never sufficient to establish a workspace, so there is
-- genuinely nothing trustworthy to write until resolution succeeds. It is
-- backfilled once the binding is known.
--
-- Uniqueness is (app_registration_id, delivery_id): redelivery of the same
-- event returns the previously committed acceptance and produces no second
-- canonical effect.
CREATE TABLE public.iga_webhook_deliveries (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    app_registration_id   text NOT NULL,
    delivery_id           text NOT NULL,
    workspace_id          uuid,
    integration_id        uuid,
    event_type            text NOT NULL DEFAULT '',
    action                text NOT NULL DEFAULT '',
    body_hash             text NOT NULL DEFAULT '',
    received_at           timestamptz NOT NULL DEFAULT now(),
    -- NULL means the signature was not verified. No parsed work may derive
    -- from such a row.
    signature_validated_at timestamptz,
    state                 text NOT NULL DEFAULT 'received',
    CONSTRAINT iga_webhook_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT iga_webhook_deliveries_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_webhook_deliveries_state_chk CHECK (
        state IN ('received', 'rejected_signature', 'rejected_binding', 'accepted', 'processed')),
    -- Accepted implies both a verified signature and a resolved workspace.
    CONSTRAINT iga_webhook_deliveries_accepted_chk CHECK (
        state NOT IN ('accepted', 'processed')
        OR (signature_validated_at IS NOT NULL AND workspace_id IS NOT NULL)),
    CONSTRAINT iga_webhook_deliveries_key UNIQUE (app_registration_id, delivery_id)
);

-- iga_durable_jobs — work accepted but not yet done. The webhook route commits
-- a delivery row and a job row in ONE transaction and only then returns 2xx;
-- acknowledging first would lose the event if the process died in between.
CREATE TABLE public.iga_durable_jobs (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    integration_id uuid NOT NULL,
    job_kind       text NOT NULL,
    dedupe_key     text NOT NULL,
    payload_ref    text NOT NULL DEFAULT '',
    state          text NOT NULL DEFAULT 'ready',
    available_at   timestamptz NOT NULL DEFAULT now(),
    lease_owner    text,
    leased_until   timestamptz,
    attempt_count  integer NOT NULL DEFAULT 0,
    last_error     text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_durable_jobs_pkey PRIMARY KEY (id),
    CONSTRAINT iga_durable_jobs_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_durable_jobs_state_chk CHECK (
        state IN ('ready', 'leased', 'done', 'failed', 'dead')),
    CONSTRAINT iga_durable_jobs_dedupe_key UNIQUE (workspace_id, integration_id, dedupe_key)
);

-- Worker claim path: find ready work whose time has come, oldest first.
CREATE INDEX idx_iga_durable_jobs_claimable
    ON public.iga_durable_jobs (workspace_id, state, available_at);

-- ------------------------------------------------------------------ --
-- 3. Append-preserving source evidence                                --
-- ------------------------------------------------------------------ --

-- iga_source_objects — what the provider showed us, keyed by a recognition key
-- built from immutable provider identifiers. The locator (owner/name/path) is
-- descriptive only: a repository rename or a file move changes the locator and
-- must NOT create a new object or silently merge two.
--
-- lifecycle is 'tombstoned' only after an authoritative enumeration of the
-- parent scope proved absence. A single 404 means nothing: it could be a
-- deletion, a permission loss, a transfer, or transient inconsistency.
CREATE TABLE public.iga_source_objects (
    id                 uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL,
    integration_id     uuid NOT NULL,
    object_type        text NOT NULL,
    recognition_key    text NOT NULL,
    native_id          text NOT NULL DEFAULT '',
    locator            jsonb NOT NULL DEFAULT '{}'::jsonb,
    normalized_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Hash of the raw body we parsed. The body itself is deliberately not kept.
    raw_hash           text NOT NULL DEFAULT '',
    source_version     text NOT NULL DEFAULT '',
    -- Deletion of provider payload is scoped by (workspace, integration,
    -- source_subject_key) while governed history survives.
    source_subject_key text NOT NULL DEFAULT '',
    scan_generation    bigint,
    lifecycle          text NOT NULL DEFAULT 'active',
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    tombstoned_at      timestamptz,
    CONSTRAINT iga_source_objects_pkey PRIMARY KEY (id),
    CONSTRAINT iga_source_objects_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_source_objects_lifecycle_chk CHECK (
        lifecycle IN ('active', 'tombstoned', 'redacted')),
    CONSTRAINT iga_source_objects_tombstone_chk CHECK (
        lifecycle <> 'tombstoned' OR tombstoned_at IS NOT NULL),
    CONSTRAINT iga_source_objects_recognition_key
        UNIQUE (workspace_id, integration_id, object_type, recognition_key),
    CONSTRAINT iga_source_objects_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_iga_source_objects_workspace_type
    ON public.iga_source_objects (workspace_id, object_type, lifecycle);
CREATE INDEX idx_iga_source_objects_subject
    ON public.iga_source_objects (workspace_id, integration_id, source_subject_key);

-- iga_observations — versioned facts with provenance. APPEND-PRESERVING: a
-- later scan adds a new row, it does not rewrite an earlier one. That is what
-- makes contradiction visible instead of silently overwritten, and what lets a
-- canonical value name the exact evidence behind it.
--
-- Idempotent by dedupe_key, so a redelivered webhook or a re-run scan segment
-- cannot double-count.
CREATE TABLE public.iga_observations (
    id                 uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL,
    source_object_id   uuid NOT NULL,
    -- Exactly one provenance anchor: a scan or a webhook delivery.
    scan_run_id        uuid,
    delivery_id        uuid,
    -- Evidence mode, in descending semantic strength. This is the ceiling on
    -- what a rule may conclude: a dependency or a secret name can never on its
    -- own produce a confirmed agent.
    mode               text NOT NULL,
    fact_payload       jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_ref       text NOT NULL DEFAULT '',
    observed_at        timestamptz NOT NULL,
    ingested_at        timestamptz NOT NULL DEFAULT now(),
    normalizer_version text NOT NULL DEFAULT '',
    rule_id            text NOT NULL DEFAULT '',
    rule_version       text NOT NULL DEFAULT '',
    dedupe_key         text NOT NULL,
    CONSTRAINT iga_observations_pkey PRIMARY KEY (id),
    CONSTRAINT iga_observations_source_object_fkey
        FOREIGN KEY (workspace_id, source_object_id)
        REFERENCES public.iga_source_objects (workspace_id, id) ON DELETE CASCADE,
    -- CASCADE, not SET NULL. An observation is the OUTPUT of the scan or
    -- delivery that produced it, and iga_observations_provenance_chk below
    -- requires one of them to be present. Nulling the anchor would leave a fact
    -- that cannot be explained -- and would break the check on the very delete
    -- that caused it. Pruning a scan therefore prunes its observations; the
    -- source object and the curated governance history both survive separately.
    CONSTRAINT iga_observations_scan_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observations_delivery_fkey FOREIGN KEY (delivery_id)
        REFERENCES public.iga_webhook_deliveries (id) ON DELETE CASCADE,
    CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
        'platform_declared',
        'deployment_declared',
        'invocation_declared',
        'framework_dependency',
        'tool_configuration',
        'secret_reference',
        'identity_grant',
        'audit_event')),
    -- An observation with no provenance anchor is not evidence.
    CONSTRAINT iga_observations_provenance_chk CHECK (
        scan_run_id IS NOT NULL OR delivery_id IS NOT NULL),
    CONSTRAINT iga_observations_dedupe_key UNIQUE (workspace_id, dedupe_key),
    CONSTRAINT iga_observations_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_iga_observations_source_time
    ON public.iga_observations (workspace_id, source_object_id, observed_at DESC);

-- iga_classification_candidates — a proposal that some source object is an
-- agent (or another canonical kind). Nothing is promoted silently: a candidate
-- carries the rule that produced it and waits for a decision. The partial
-- unique index allows exactly one PENDING proposal per signature while keeping
-- the full history of decided ones.
CREATE TABLE public.iga_classification_candidates (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    source_object_id    uuid NOT NULL,
    proposed_object_kind text NOT NULL,
    proposal_signature  text NOT NULL,
    rule_id             text NOT NULL DEFAULT '',
    rule_version        text NOT NULL DEFAULT '',
    evidence_mode       text NOT NULL DEFAULT '',
    state               text NOT NULL DEFAULT 'pending',
    decided_by          text,
    decided_at          timestamptz,
    reason              text NOT NULL DEFAULT '',
    version             bigint NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_classification_candidates_pkey PRIMARY KEY (id),
    CONSTRAINT iga_classification_candidates_source_fkey
        FOREIGN KEY (workspace_id, source_object_id)
        REFERENCES public.iga_source_objects (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_classification_candidates_state_chk CHECK (
        state IN ('pending', 'confirmed', 'rejected', 'insufficient_evidence', 'superseded')),
    CONSTRAINT iga_classification_candidates_decided_chk CHECK (
        state = 'pending' OR decided_at IS NOT NULL),
    CONSTRAINT iga_classification_candidates_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX uq_iga_classification_candidates_active
    ON public.iga_classification_candidates (workspace_id, proposal_signature)
    WHERE state = 'pending';

CREATE INDEX idx_iga_classification_candidates_state
    ON public.iga_classification_candidates (workspace_id, state);

-- iga_correlations — the reversible mapping from a source object to a canonical
-- object. Weak joins (name, path, label similarity) stay proposals forever
-- unless a human accepts them. A split flips state; it never deletes the
-- observations that justified the original join.
CREATE TABLE public.iga_correlations (
    id               uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL,
    source_object_id uuid NOT NULL,
    canonical_kind   text NOT NULL,
    canonical_id     uuid NOT NULL,
    join_key         text NOT NULL DEFAULT '',
    strength         text NOT NULL DEFAULT 'weak',
    state            text NOT NULL DEFAULT 'proposed',
    decided_by       text,
    decided_at       timestamptz,
    version          bigint NOT NULL DEFAULT 1,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_correlations_pkey PRIMARY KEY (id),
    CONSTRAINT iga_correlations_source_fkey
        FOREIGN KEY (workspace_id, source_object_id)
        REFERENCES public.iga_source_objects (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_correlations_strength_chk CHECK (strength IN ('strong', 'weak')),
    CONSTRAINT iga_correlations_state_chk CHECK (
        state IN ('proposed', 'accepted', 'rejected', 'split')),
    -- Only a provider-exposed relationship may auto-link; a weak join that
    -- claims accepted status without a decision is a bug.
    CONSTRAINT iga_correlations_weak_chk CHECK (
        state <> 'accepted' OR strength = 'strong' OR decided_by IS NOT NULL)
);

CREATE INDEX idx_iga_correlations_canonical
    ON public.iga_correlations (workspace_id, canonical_kind, canonical_id);

-- ------------------------------------------------------------------ --
-- 4. Canonical graph — provider-neutral                               --
-- ------------------------------------------------------------------ --
-- No column below may hold a provider-specific field. GitHub specifics belong
-- in iga_source_objects.normalized_payload or iga_observations.fact_payload.

-- iga_estate_scopes — containment only (organization, project, cluster).
-- Containment confers NO access inheritance; an access path must be evidenced.
CREATE TABLE public.iga_estate_scopes (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    scope_kind      text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    parent_scope_id uuid,
    stage           text NOT NULL DEFAULT 'unknown',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_estate_scopes_pkey PRIMARY KEY (id),
    CONSTRAINT iga_estate_scopes_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_estate_scopes_parent_fkey
        FOREIGN KEY (workspace_id, parent_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (parent_scope_id),
    CONSTRAINT iga_estate_scopes_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_estate_scopes_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_agents — the LOGICAL agent only. A candidate is not an agent: proposals
-- live in iga_classification_candidates until confirmed. rollup_state carries
-- the honesty of the record (confirmed / contested / unknown / stale) and is
-- separate from any displayed value.
CREATE TABLE public.iga_agents (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    estate_scope_id uuid,
    display_name text NOT NULL DEFAULT '',
    classification text NOT NULL DEFAULT 'unknown',
    status       text NOT NULL DEFAULT 'active',
    rollup_state text NOT NULL DEFAULT 'unknown',
    lifecycle    text NOT NULL DEFAULT 'active',
    version      bigint NOT NULL DEFAULT 1,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_agents_pkey PRIMARY KEY (id),
    CONSTRAINT iga_agents_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_agents_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_agents_rollup_chk CHECK (
        rollup_state IN ('confirmed', 'contested', 'unknown', 'stale')),
    CONSTRAINT iga_agents_lifecycle_chk CHECK (
        lifecycle IN ('active', 'retired', 'tombstoned')),
    CONSTRAINT iga_agents_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_iga_agents_workspace_rollup
    ON public.iga_agents (workspace_id, rollup_state, lifecycle);

-- iga_agent_instances — a REALIZATION proven by a source that can prove
-- deployment (a Kubernetes workload, a hosted agent, an endpoint install).
-- A repository declaration alone never produces a row here: declared is not
-- running.
CREATE TABLE public.iga_agent_instances (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    agent_id          uuid NOT NULL,
    estate_scope_id   uuid,
    native_workload_id text NOT NULL DEFAULT '',
    runtime_kind      text NOT NULL DEFAULT '',
    stage             text NOT NULL DEFAULT 'unknown',
    lifecycle         text NOT NULL DEFAULT 'active',
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_agent_instances_pkey PRIMARY KEY (id),
    CONSTRAINT iga_agent_instances_agent_fkey
        FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_agent_instances_scope_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_agent_instances_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_agent_instances_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_identity_accounts — a programmatic principal. Never a credential, and
-- never automatically an agent: an App installation or a PAT owner is an
-- identity until evidence links it to an agent.
CREATE TABLE public.iga_identity_accounts (
    id               uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL,
    estate_scope_id  uuid,
    display_name     text NOT NULL DEFAULT '',
    account_kind     text NOT NULL,
    identity_backing text NOT NULL DEFAULT 'unknown',
    lifecycle        text NOT NULL DEFAULT 'active',
    rollup_state     text NOT NULL DEFAULT 'unknown',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_identity_accounts_pkey PRIMARY KEY (id),
    CONSTRAINT iga_identity_accounts_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_identity_accounts_scope_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_identity_accounts_rollup_chk CHECK (
        rollup_state IN ('confirmed', 'contested', 'unknown', 'stale')),
    CONSTRAINT iga_identity_accounts_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_credentials — NON-SECRET metadata about how an identity authenticates.
-- No value, no token, no private key, ever. Rotation appends a lifecycle event
-- under the SAME identity account; it does not create an identity or an agent.
CREATE TABLE public.iga_credentials (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    identity_account_id uuid NOT NULL,
    credential_type     text NOT NULL,
    issuer              text NOT NULL DEFAULT '',
    key_identifier      text NOT NULL DEFAULT '',
    -- Pointer into the secrets store, never the material itself.
    secret_ref          text NOT NULL DEFAULT '',
    issued_at           timestamptz,
    expires_at          timestamptz,
    last_used_at        timestamptz,
    rotation_posture    text NOT NULL DEFAULT 'unknown',
    lifecycle           text NOT NULL DEFAULT 'active',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT iga_credentials_identity_fkey
        FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_credentials_lifecycle_chk CHECK (
        lifecycle IN ('active', 'expired', 'revoked', 'rotated')),
    CONSTRAINT iga_credentials_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_iga_credentials_identity
    ON public.iga_credentials (workspace_id, identity_account_id);

-- iga_resources — the protected thing: a repository, API, tool, model or
-- application. Provider-neutral by contract.
CREATE TABLE public.iga_resources (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    estate_scope_id uuid,
    resource_kind   text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    stage           text NOT NULL DEFAULT 'unknown',
    lifecycle       text NOT NULL DEFAULT 'active',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_resources_pkey PRIMARY KEY (id),
    CONSTRAINT iga_resources_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_resources_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_resources_stage_chk CHECK (
        stage IN ('production', 'non_production', 'unknown')),
    CONSTRAINT iga_resources_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_entitlements — one native access unit. native_rights preserves the
-- provider's own wording; normalized_rights is our derived reading. Both are
-- kept so a reviewer can always see what the provider actually said.
CREATE TABLE public.iga_entitlements (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    resource_id       uuid,
    native_grant_kind text NOT NULL,
    native_rights     jsonb NOT NULL DEFAULT '{}'::jsonb,
    normalized_rights jsonb NOT NULL DEFAULT '{}'::jsonb,
    native_scope      text NOT NULL DEFAULT '',
    -- Whether this grant can actually be revoked through a supported path.
    remediable        boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_entitlements_pkey PRIMARY KEY (id),
    CONSTRAINT iga_entitlements_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_entitlements_resource_fkey
        FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_entitlements_workspace_id_key UNIQUE (workspace_id, id)
);

-- iga_access_edges — subject -> entitlement -> resource.
--
-- calculation_state is the load-bearing column. A source grant is NOT
-- automatically effective access: unsupported conditional controls, policy
-- layers or missing membership evidence leave the effective conclusion
-- unknown, and the UI must say so rather than implying access was proven.
CREATE TABLE public.iga_access_edges (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    subject_kind   text NOT NULL,
    subject_id     uuid NOT NULL,
    entitlement_id uuid,
    resource_id    uuid,
    direction      text NOT NULL,
    path_kind      text NOT NULL DEFAULT '',
    calculation_state text NOT NULL DEFAULT 'unknown',
    effective_conclusion text NOT NULL DEFAULT 'unknown',
    native_scope   text NOT NULL DEFAULT '',
    observed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_access_edges_pkey PRIMARY KEY (id),
    CONSTRAINT iga_access_edges_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_access_edges_entitlement_fkey
        FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_access_edges_resource_fkey
        FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_access_edges_subject_chk CHECK (
        subject_kind IN ('agent', 'agent_instance', 'identity_account', 'user', 'team')),
    CONSTRAINT iga_access_edges_direction_chk CHECK (direction IN ('inbound', 'outbound')),
    CONSTRAINT iga_access_edges_calculation_chk CHECK (
        calculation_state IN ('complete', 'partial', 'unknown')),
    CONSTRAINT iga_access_edges_conclusion_chk CHECK (
        effective_conclusion IN ('effective', 'not_effective', 'unknown')),
    -- An edge may only claim a decided conclusion when the calculation is
    -- complete. Partial or unknown evidence yields an unknown conclusion.
    CONSTRAINT iga_access_edges_honesty_chk CHECK (
        effective_conclusion = 'unknown' OR calculation_state = 'complete'),
    CONSTRAINT iga_access_edges_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE INDEX idx_iga_access_edges_subject
    ON public.iga_access_edges (workspace_id, subject_kind, subject_id, direction);
CREATE INDEX idx_iga_access_edges_resource
    ON public.iga_access_edges (workspace_id, resource_id, direction);

-- iga_canonical_attribute_values — survivorship. When two sources disagree
-- about the same attribute, both values are kept with their authority rank and
-- the observation that supplied each; the winner is a decision, not a
-- last-write-wins accident.
CREATE TABLE public.iga_canonical_attribute_values (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    entity_kind    text NOT NULL,
    entity_id      uuid NOT NULL,
    attribute      text NOT NULL,
    value          jsonb,
    observation_id uuid,
    authority_rank integer NOT NULL DEFAULT 0,
    state          text NOT NULL DEFAULT 'surviving',
    valid_from     timestamptz,
    valid_to       timestamptz,
    fallback_reason text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_canonical_attribute_values_pkey PRIMARY KEY (id),
    CONSTRAINT iga_canonical_attribute_values_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_canonical_attribute_values_observation_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE SET NULL (observation_id),
    CONSTRAINT iga_canonical_attribute_values_state_chk CHECK (
        state IN ('surviving', 'superseded', 'contested', 'rejected'))
);

-- Exactly one surviving value per (entity, attribute).
CREATE UNIQUE INDEX uq_iga_canonical_attribute_surviving
    ON public.iga_canonical_attribute_values (workspace_id, entity_kind, entity_id, attribute)
    WHERE state = 'surviving';

-- iga_attribute_authority_policies — which source wins for which attribute, and
-- whether an authoritative source is allowed to assert null.
CREATE TABLE public.iga_attribute_authority_policies (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    entity_kind    text NOT NULL,
    attribute      text NOT NULL,
    provider       text NOT NULL DEFAULT '',
    authority_rank integer NOT NULL DEFAULT 0,
    allow_authoritative_null boolean NOT NULL DEFAULT false,
    version        bigint NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_attribute_authority_policies_pkey PRIMARY KEY (id),
    CONSTRAINT iga_attribute_authority_policies_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_attribute_authority_policies_key
        UNIQUE (workspace_id, entity_kind, attribute, provider)
);

-- iga_observation_links — the drill-down path. Every canonical value and edge
-- must resolve to the observations that support it, and crucially to those
-- that CONTRADICT it, which is how a contested rollup state is justified.
CREATE TABLE public.iga_observation_links (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    observation_id uuid NOT NULL,
    target_kind    text NOT NULL,
    target_id      uuid NOT NULL,
    relation       text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_observation_links_pkey PRIMARY KEY (id),
    CONSTRAINT iga_observation_links_observation_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observation_links_relation_chk CHECK (
        relation IN ('supports', 'contradicts', 'supersedes', 'previously_supported')),
    CONSTRAINT iga_observation_links_key
        UNIQUE (workspace_id, observation_id, target_kind, target_id, relation)
);

CREATE INDEX idx_iga_observation_links_target
    ON public.iga_observation_links (workspace_id, target_kind, target_id);

-- iga_ownership_candidates — proposed TECHNICAL owners with the evidence that
-- proposed them. A code-review owner is not a business sponsor: no row here
-- may silently populate sponsorship, which is a separate governance action
-- that must resolve to a person.
CREATE TABLE public.iga_ownership_candidates (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    subject_kind   text NOT NULL,
    subject_id     uuid NOT NULL,
    candidate_kind text NOT NULL,
    candidate_ref  text NOT NULL,
    evidence_source text NOT NULL DEFAULT '',
    rank           integer NOT NULL DEFAULT 0,
    state          text NOT NULL DEFAULT 'proposed',
    decided_by     text,
    decided_at     timestamptz,
    version        bigint NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_ownership_candidates_pkey PRIMARY KEY (id),
    CONSTRAINT iga_ownership_candidates_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_ownership_candidates_kind_chk CHECK (
        candidate_kind IN ('user', 'team', 'unknown')),
    CONSTRAINT iga_ownership_candidates_state_chk CHECK (
        state IN ('proposed', 'confirmed', 'rejected')),
    CONSTRAINT iga_ownership_candidates_decided_chk CHECK (
        state = 'proposed' OR decided_at IS NOT NULL)
);

CREATE INDEX idx_iga_ownership_candidates_subject
    ON public.iga_ownership_candidates (workspace_id, subject_kind, subject_id, state);

-- iga_operational_issues — permission loss, staleness, truncation, API failure.
-- Kept strictly SEPARATE from agent-risk findings: "we could not read this" is
-- an operational problem for the administrator, not a security finding about
-- an agent, and mixing the two makes both untrustworthy.
CREATE TABLE public.iga_operational_issues (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    integration_id uuid,
    issue_kind     text NOT NULL,
    severity       text NOT NULL DEFAULT 'info',
    object_class   text NOT NULL DEFAULT '',
    scope_ref      text NOT NULL DEFAULT '',
    detail         jsonb NOT NULL DEFAULT '{}'::jsonb,
    state          text NOT NULL DEFAULT 'open',
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    CONSTRAINT iga_operational_issues_pkey PRIMARY KEY (id),
    CONSTRAINT iga_operational_issues_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_operational_issues_kind_chk CHECK (issue_kind IN (
        'permission_denied', 'stale_scan', 'tree_truncated', 'api_failure',
        'rate_limited', 'unsupported_capability', 'binding_failure')),
    CONSTRAINT iga_operational_issues_state_chk CHECK (
        state IN ('open', 'acknowledged', 'resolved'))
);

CREATE INDEX idx_iga_operational_issues_state
    ON public.iga_operational_issues (workspace_id, state, issue_kind);

-- iga_integration_scopes.estate_scope_id is wired up here rather than inline:
-- iga_estate_scopes is declared further down, so the reference cannot exist at
-- CREATE TABLE time. Column-list SET NULL for the same reason as above.
ALTER TABLE ONLY public.iga_integration_scopes
    ADD CONSTRAINT iga_integration_scopes_estate_scope_fkey
    FOREIGN KEY (workspace_id, estate_scope_id)
    REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id);

-- Agentic IGA RBAC permissions -- GLOBAL (workspace_id IS NULL), same model as
-- connector:* and discovery:*. Three, matching the authorization tiers in the
-- API contract: viewer reads, admin connects/verifies/scans, reviewer decides.
-- 'review' is separate from 'admin' so a reviewer can confirm or reject a
-- candidate without also being able to rebind an installation.
INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'iga', 'read',   'Read IGA inventory, coverage and evidence', 'iga:read',   NOW()),
    (gen_random_uuid(), NULL, 'iga', 'admin',  'Manage IGA integrations and run scans',     'iga:admin',  NOW()),
    (gen_random_uuid(), NULL, 'iga', 'review', 'Decide classification and ownership candidates', 'iga:review', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

-- iga_idempotency_keys -- replay protection for POST scan and decision routes.
-- Reuse of a key with the SAME request returns the original result; reuse with
-- a different request is a conflict. request_hash is what tells them apart.
CREATE TABLE public.iga_idempotency_keys (
    workspace_id    uuid NOT NULL,
    idempotency_key text NOT NULL,
    route           text NOT NULL,
    request_hash    text NOT NULL,
    response_status integer NOT NULL,
    response_body   jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_idempotency_keys_pkey PRIMARY KEY (workspace_id, idempotency_key),
    CONSTRAINT iga_idempotency_keys_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE
);

-- ============================================================================
-- GOVERNANCE: entitlement provenance (PROVISIONING-GOVERNANCE-ARCHITECTURE.md §5)
--
-- The platform can already answer "what does this subject have?" precisely: the
-- ScopeResolver walks role_bindings -> roles -> permissions -> oauth_scopes and
-- honours expires_at at read time. What it cannot answer is "WHY does this subject
-- have it?" -- who asked, who approved, on what justification, for what purpose,
-- and whether it was meant to be temporary.
--
-- That is the prerequisite for certification. A reviewer asked "should this agent
-- still have this?" has nothing to review without it, and every answer is a guess.
-- It is also what keeps a revocation auditable once the grant row itself is gone.
--
-- Placed at the end of the file because it references users, workspaces,
-- role_bindings, access_requests, connector_assignments,
-- resource_server_client_registrations, and discovered_agents -- all created above.
-- ============================================================================

-- Deferred FKs for the ownership columns added inline to earlier tables, whose
-- targets (users, discovered_agents) are created further down the file.
ALTER TABLE ONLY public.resource_servers
    ADD CONSTRAINT resource_servers_owner_fkey FOREIGN KEY (owner_user_id)
    REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.mcp_oauth_clients
    ADD CONSTRAINT mcp_oauth_clients_owner_fkey FOREIGN KEY (owner_user_id)
    REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_discovered_agent_fkey FOREIGN KEY (discovered_agent_id)
    REFERENCES public.discovered_agents(id) ON DELETE SET NULL;

CREATE INDEX idx_resource_servers_owner
    ON public.resource_servers(owner_user_id) WHERE owner_user_id IS NOT NULL;
CREATE INDEX idx_mcp_oauth_clients_owner
    ON public.mcp_oauth_clients(owner_user_id) WHERE owner_user_id IS NOT NULL;

-- entitlement_provenance -- one row per grant DECISION.
--
-- Rows are OPENED when a grant is made and CLOSED when it is revoked. Nothing is
-- ever deleted from this table, because it is evidence.
--
-- WHY BOTH A POINTER AND A SNAPSHOT
-- The live pointers (role_binding_id etc.) are ON DELETE SET NULL, because
-- provenance must OUTLIVE the grant it describes -- an expired binding is deleted,
-- and that is precisely when the record of it becomes important. entitlement_snapshot
-- carries a denormalised copy of the essentials and stays readable after the pointer
-- is nulled. A pointer alone would lose the evidence; a snapshot alone could not be
-- joined while the grant is live.
CREATE TABLE public.entitlement_provenance (
    id                       uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id             uuid NOT NULL,

    -- WHAT was granted
    entitlement_type         text NOT NULL,
    role_binding_id          uuid,
    client_registration_id   uuid,
    connector_assignment_id  uuid,
    entitlement_snapshot     jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Human-readable one-liner for a review queue, so a reviewer never has to read
    -- jsonb to know what they are deciding on.
    entitlement_label        text NOT NULL DEFAULT '',

    -- WHO holds it. Deliberately not an FK: the subject may be a user, a service
    -- account, an oauth client, or a group, and one polymorphic FK cannot express
    -- that. The service resolves and validates the subject before writing.
    subject_type             text NOT NULL,
    subject_id               uuid NOT NULL,
    subject_label            text NOT NULL DEFAULT '',

    -- WHY it was granted
    origin                   text NOT NULL,
    justification            text NOT NULL DEFAULT '',
    purpose                  text NOT NULL DEFAULT '',
    access_request_id        uuid,
    discovered_agent_id      uuid,

    -- BY WHOM. granted_by_label is denormalised on purpose: a deactivated user's row
    -- can be removed, and "granted by <null>" is useless in an audit six months on.
    granted_by               uuid,
    granted_by_label         text NOT NULL DEFAULT '',
    granted_at               timestamptz NOT NULL DEFAULT now(),

    -- FOR HOW LONG. is_standing marks a deliberate permanent grant; those require a
    -- justification (see the check below) and sort first in every campaign.
    expires_at               timestamptz,
    is_standing              boolean NOT NULL DEFAULT false,

    -- CLOSING. revoked_via records which of the five callers invoked the single
    -- de-provision path.
    revoked_at               timestamptz,
    revoked_by               uuid,
    revoked_reason           text NOT NULL DEFAULT '',
    revoked_via              text NOT NULL DEFAULT '',

    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT entitlement_provenance_pkey PRIMARY KEY (id),
    CONSTRAINT entitlement_provenance_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT entitlement_provenance_role_binding_fkey FOREIGN KEY (role_binding_id)
        REFERENCES public.role_bindings(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_client_reg_fkey FOREIGN KEY (client_registration_id)
        REFERENCES public.resource_server_client_registrations(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_connector_assignment_fkey FOREIGN KEY (connector_assignment_id)
        REFERENCES public.connector_assignments(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_access_request_fkey FOREIGN KEY (access_request_id)
        REFERENCES public.access_requests(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_discovered_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_granted_by_fkey FOREIGN KEY (granted_by)
        REFERENCES public.users(id) ON DELETE SET NULL,

    CONSTRAINT entitlement_provenance_type_chk CHECK (
        entitlement_type IN ('role_binding', 'client_registration', 'secret_access')),
    CONSTRAINT entitlement_provenance_subject_chk CHECK (
        subject_type IN ('user', 'service_account', 'oauth_client', 'group')),
    CONSTRAINT entitlement_provenance_origin_chk CHECK (
        origin IN ('discovery_claim', 'self_service', 'birthright', 'admin',
                   'escalation', 'connection_approval', 'migration')),
    CONSTRAINT entitlement_provenance_revoked_via_chk CHECK (
        revoked_via IN ('', 'expiry', 'certification', 'leaver', 'quarantine',
                        'admin', 'sod_remediation')),
    -- A standing grant must say why it is standing. This is the mechanism behind
    -- "ephemeral is the default, permanent is the audited exception" -- without it,
    -- is_standing is just a boolean nobody has to defend.
    CONSTRAINT entitlement_provenance_standing_needs_justification_chk CHECK (
        NOT is_standing OR justification <> ''),
    -- A closed row must say when and how.
    CONSTRAINT entitlement_provenance_revocation_complete_chk CHECK (
        (revoked_at IS NULL AND revoked_via = '')
        OR (revoked_at IS NOT NULL AND revoked_via <> '')),
    -- Exactly one live pointer, matching entitlement_type. Stops a row that claims
    -- to describe a role binding while pointing at a client registration.
    CONSTRAINT entitlement_provenance_pointer_chk CHECK (
        (entitlement_type = 'role_binding'
            AND client_registration_id IS NULL AND connector_assignment_id IS NULL)
     OR (entitlement_type = 'client_registration'
            AND role_binding_id IS NULL AND connector_assignment_id IS NULL)
     OR (entitlement_type = 'secret_access'
            AND role_binding_id IS NULL AND client_registration_id IS NULL))
);

-- At most ONE OPEN provenance row per live entitlement. Partial, so the closed
-- history of a recreated entitlement is unconstrained. Without this a retried
-- provision would silently double-record, and every "why" query would return two
-- conflicting answers.
CREATE UNIQUE INDEX entitlement_provenance_open_role_binding_key
    ON public.entitlement_provenance(role_binding_id)
    WHERE role_binding_id IS NOT NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX entitlement_provenance_open_client_reg_key
    ON public.entitlement_provenance(client_registration_id)
    WHERE client_registration_id IS NOT NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX entitlement_provenance_open_connector_key
    ON public.entitlement_provenance(connector_assignment_id)
    WHERE connector_assignment_id IS NOT NULL AND revoked_at IS NULL;

-- "What does this subject have, and why?" -- the certification and console query.
CREATE INDEX idx_entitlement_provenance_subject
    ON public.entitlement_provenance(workspace_id, subject_type, subject_id)
    WHERE revoked_at IS NULL;
-- The expiry worker's sweep.
CREATE INDEX idx_entitlement_provenance_expiring
    ON public.entitlement_provenance(expires_at)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
-- "Show me every standing grant" -- the first page of any campaign.
CREATE INDEX idx_entitlement_provenance_standing
    ON public.entitlement_provenance(workspace_id)
    WHERE revoked_at IS NULL AND is_standing;
CREATE INDEX idx_entitlement_provenance_agent
    ON public.entitlement_provenance(discovered_agent_id)
    WHERE discovered_agent_id IS NOT NULL;

-- Governance RBAC permissions -- GLOBAL (workspace_id IS NULL), like discovery's
-- above. governance:read is split from governance:admin so a reviewer can work a
-- campaign without gaining the ability to grant anything.
INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'governance', 'read',    'Read entitlement provenance and governance reports', 'governance:read',    NOW()),
    (gen_random_uuid(), NULL, 'governance', 'certify', 'Decide certification items',                         'governance:certify', NOW()),
    (gen_random_uuid(), NULL, 'governance', 'revoke',  'Revoke an entitlement',                              'governance:revoke',  NOW()),
    (gen_random_uuid(), NULL, 'governance', 'admin',   'Manage governance policy and campaigns',             'governance:admin',   NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

-- ============================================================================
-- GOVERNANCE: separation of duties (PROVISIONING-GOVERNANCE-ARCHITECTURE.md §6.4)
--
-- TWO RULE SHAPES, because the agentic cases are not all classic SoD:
--   'conflict'    -- holding capabilities from BOTH sides is the violation.
--   'prohibition' -- one side only; holding ANY of these is the violation for the
--                    subjects the rule applies to. This is what expresses "no agent
--                    principal may hold role-management authority", which is not a
--                    conflict between two duties but a capability an agent must never
--                    have. Forcing it into the two-set shape would mean inventing a
--                    fake second side.
--
-- Capabilities are named in the platform's OWN vocabulary (role ids, `resource:action`
-- permission strings), so a rule means exactly what enforcement means. A parallel
-- vocabulary is how an SoD engine drifts from the thing it polices, and a drifted
-- engine gives false assurance -- worse than none.
-- ============================================================================
-- sod_rules ----------------------------------------------------------------
--
-- Capabilities are named in the platform's OWN vocabulary — role ids and
-- `resource:action` permission strings — so a rule means exactly what enforcement
-- means. Expressing rules in a parallel vocabulary is how an SoD engine drifts from
-- the thing it is supposed to police, and a drifted engine gives false assurance,
-- which is worse than none.
--
-- workspace_id NULL marks a GLOBAL rule, the same convention permissions use. Global
-- + is_system rules are the seeded controls; the API refuses to edit or delete them.
CREATE TABLE public.sod_rules (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid,
    name          text NOT NULL,
    description   text NOT NULL DEFAULT '',
    kind          text NOT NULL DEFAULT 'conflict',
    severity      text NOT NULL DEFAULT 'high',
    enabled       boolean NOT NULL DEFAULT true,
    -- A system rule is immutable through the API. The self-modification control has to
    -- be un-editable, or an attacker who reaches the governance API simply turns it off
    -- before escalating.
    is_system     boolean NOT NULL DEFAULT false,
    -- Which subjects the rule applies to. 'agents' means a service account that is an
    -- agent's entitlement anchor (service_accounts.oauth_client_id IS NOT NULL) —
    -- which is precisely the population the self-modification control targets.
    subject_scope text NOT NULL DEFAULT 'any',

    -- Side A. Always meaningful.
    left_label       text NOT NULL DEFAULT '',
    left_roles       text[] NOT NULL DEFAULT '{}',
    left_permissions text[] NOT NULL DEFAULT '{}',

    -- Side B. Empty for a prohibition.
    right_label       text NOT NULL DEFAULT '',
    right_roles       text[] NOT NULL DEFAULT '{}',
    right_permissions text[] NOT NULL DEFAULT '{}',

    -- 'block' refuses the grant in the preventive check; 'warn' records the violation
    -- and allows it. Warn exists so a rule can be rolled out in observation mode
    -- before it starts refusing real requests.
    enforcement text NOT NULL DEFAULT 'block',

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sod_rules_pkey PRIMARY KEY (id),
    CONSTRAINT sod_rules_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT sod_rules_kind_chk CHECK (kind IN ('conflict', 'prohibition')),
    CONSTRAINT sod_rules_severity_chk CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT sod_rules_subject_scope_chk CHECK (subject_scope IN ('any', 'agents', 'humans')),
    CONSTRAINT sod_rules_enforcement_chk CHECK (enforcement IN ('block', 'warn')),
    -- Side A must name something, or the rule matches everything.
    CONSTRAINT sod_rules_left_nonempty_chk CHECK (
        cardinality(left_roles) > 0 OR cardinality(left_permissions) > 0),
    -- A conflict needs a second side; a prohibition must not have one, or it is
    -- silently a conflict wearing the wrong label.
    CONSTRAINT sod_rules_shape_chk CHECK (
        (kind = 'conflict'
            AND (cardinality(right_roles) > 0 OR cardinality(right_permissions) > 0))
     OR (kind = 'prohibition'
            AND cardinality(right_roles) = 0 AND cardinality(right_permissions) = 0))
);

-- One rule name per workspace. Partial-by-coalesce so global rules (workspace_id
-- NULL) share one namespace rather than every NULL being distinct.
CREATE UNIQUE INDEX sod_rules_name_key
    ON public.sod_rules(COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE INDEX idx_sod_rules_enabled
    ON public.sod_rules(workspace_id) WHERE enabled;

-- sod_violations -----------------------------------------------------------
--
-- Records the CONFLICTING PATHS, not just a flag. A reviewer told "this subject
-- violates rule X" cannot act; one told "it holds governance:admin via role
-- platform-admin, bound by binding <id>" can.
CREATE TABLE public.sod_violations (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    rule_id      uuid NOT NULL,
    rule_name    text NOT NULL DEFAULT '',

    subject_type  text NOT NULL,
    subject_id    uuid NOT NULL,
    subject_label text NOT NULL DEFAULT '',

    -- Which capabilities matched each side, and through which bindings.
    left_evidence  jsonb NOT NULL DEFAULT '[]'::jsonb,
    right_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,

    status text NOT NULL DEFAULT 'open',
    -- 'accepted' is a documented risk acceptance, not a fix. It needs a note and an
    -- owner, because an unexplained acceptance is indistinguishable from neglect.
    resolution_note text NOT NULL DEFAULT '',
    resolved_by     uuid,
    resolved_at     timestamptz,

    detected_at timestamptz NOT NULL DEFAULT now(),
    -- Refreshed by each scan that still sees it, so an open violation's age is real.
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    -- 'preventive' means a grant was refused; 'detective' means a scan found an
    -- existing one. Preventive rows are evidence of an attempt, which is worth
    -- keeping distinct.
    detected_via text NOT NULL DEFAULT 'detective',

    CONSTRAINT sod_violations_pkey PRIMARY KEY (id),
    CONSTRAINT sod_violations_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT sod_violations_rule_fkey FOREIGN KEY (rule_id)
        REFERENCES public.sod_rules(id) ON DELETE CASCADE,
    CONSTRAINT sod_violations_resolved_by_fkey FOREIGN KEY (resolved_by)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT sod_violations_status_chk CHECK (status IN ('open', 'accepted', 'remediated')),
    CONSTRAINT sod_violations_detected_via_chk CHECK (detected_via IN ('preventive', 'detective')),
    CONSTRAINT sod_violations_resolution_chk CHECK (
        status = 'open' OR (resolved_at IS NOT NULL AND resolution_note <> ''))
);

-- One OPEN violation per (rule, subject). Re-detecting refreshes last_seen_at rather
-- than piling up duplicates, so the count means "how many problems" and not "how many
-- times the scan ran".
CREATE UNIQUE INDEX sod_violations_open_key
    ON public.sod_violations(workspace_id, rule_id, subject_type, subject_id)
    WHERE status = 'open';
CREATE INDEX idx_sod_violations_open
    ON public.sod_violations(workspace_id, status, detected_at DESC);

-- The seeded self-modification control -------------------------------------
--
-- An agent that can grant itself permissions is not governed, whatever the inventory
-- says. This is the preventive half of that control; the other half is that the PDP
-- resolves no scope for a binding an agent does not hold.
--
-- GLOBAL and is_system, so it applies in every workspace and cannot be edited or
-- disabled through the API. 'prohibition' rather than 'conflict' because these are
-- capabilities an agent must never hold at all, not two duties that must stay apart.
INSERT INTO public.sod_rules
    (workspace_id, name, description, kind, severity, is_system, subject_scope,
     left_label, left_permissions, enforcement, created_by)
VALUES (
    NULL,
    'agent-self-modification',
    'An agent principal may not hold governance, role-management, or binding-write '
        || 'authority. An agent that can widen its own access is ungoverned however '
        || 'complete its inventory record looks.',
    'prohibition',
    'critical',
    true,
    'agents',
    'governance and role-management authority',
    ARRAY[
        'governance:admin',
        'governance:revoke',
        'governance:certify',
        'roles:create', 'roles:update', 'roles:delete',
        'role_bindings:create', 'role_bindings:update', 'role_bindings:delete',
        'permissions:create', 'permissions:update', 'permissions:delete',
        'discovery:claim', 'discovery:admin'
    ]::text[],
    'block',
    'system'
)
ON CONFLICT (COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), name)
DO NOTHING;

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.sod_rules')      AS rules_table,
       to_regclass('public.sod_violations')  AS violations_table,
       (SELECT count(*) FROM public.sod_rules WHERE is_system) AS system_rules;

-- ============================================================================
-- GOVERNANCE: access certification (PROVISIONING-GOVERNANCE-ARCHITECTURE.md §6.3)
--
-- Periodically the accountable human for each entitlement confirms it is still needed
-- or revokes it. It exists because access accumulates -- people request, nobody
-- removes -- and because an auditor wants evidence a NAMED person reviewed.
--
-- The queue here is deliberately small. Traditional certification exists because all
-- access is standing; PG-4 inverted that, so most grants expire rather than needing
-- review. What genuinely needs certifying is the STANDING grants, which is why
-- standing_only is the default scope.
--
-- ITEMS ARE SNAPSHOTS. Certifying against live data means the thing you approved can
-- change under you mid-review, and the frozen export would not match what the reviewer
-- actually saw.
-- ============================================================================
-- certification_campaigns --------------------------------------------------
CREATE TABLE public.certification_campaigns (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',

    -- What to review. Typed in Go (services.CampaignScope) but stored as jsonb, so a
    -- new filter dimension does not need a migration. Empty means the default:
    -- standing grants only.
    scope jsonb NOT NULL DEFAULT '{}'::jsonb,

    status text NOT NULL DEFAULT 'draft',
    -- Reviewers get until this date; past it, items are overdue and escalate to the
    -- workspace owner. A campaign with no deadline is one nobody finishes.
    due_at timestamptz,

    -- The frozen export, written at close. This is the artifact an auditor reads, so
    -- it is stored rather than recomputed: recomputing it later would reflect the
    -- world as it is now, not as the reviewer found it.
    export      jsonb,
    generated_at timestamptz,
    closed_at    timestamptz,
    closed_by    uuid,

    -- Denormalised counters, maintained as decisions land, so a campaign list does not
    -- need an aggregate over every item.
    items_total    integer NOT NULL DEFAULT 0,
    items_decided  integer NOT NULL DEFAULT 0,
    items_kept     integer NOT NULL DEFAULT 0,
    items_revoked  integer NOT NULL DEFAULT 0,

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT certification_campaigns_pkey PRIMARY KEY (id),
    CONSTRAINT certification_campaigns_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT certification_campaigns_closed_by_fkey FOREIGN KEY (closed_by)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT certification_campaigns_status_chk CHECK (
        status IN ('draft', 'active', 'closed')),
    -- A closed campaign must have its export. Without this, "closed" could mean
    -- "abandoned" and the audit artifact would be silently absent.
    CONSTRAINT certification_campaigns_closed_chk CHECK (
        status <> 'closed' OR (closed_at IS NOT NULL AND export IS NOT NULL)),
    -- An active campaign must have been generated: an active campaign with no items is
    -- a review nobody can perform.
    CONSTRAINT certification_campaigns_active_chk CHECK (
        status <> 'active' OR generated_at IS NOT NULL)
);

CREATE UNIQUE INDEX certification_campaigns_name_key
    ON public.certification_campaigns(workspace_id, name);
CREATE INDEX idx_certification_campaigns_status
    ON public.certification_campaigns(workspace_id, status, due_at);

-- certification_items ------------------------------------------------------
--
-- One entitlement under review. entitlement_provenance_id is the anchor: provenance is
-- already the append-only record of WHY a grant exists, so an item points at it rather
-- than re-deriving the justification.
CREATE TABLE public.certification_items (
    id          uuid NOT NULL DEFAULT gen_random_uuid(),
    campaign_id uuid NOT NULL,
    workspace_id uuid NOT NULL,

    -- ON DELETE SET NULL, not CASCADE: an item must survive its provenance row being
    -- removed, or closing a campaign could lose the very record it certified.
    entitlement_provenance_id uuid,

    -- The SNAPSHOT. Everything the reviewer saw, frozen at generation.
    subject_type  text NOT NULL,
    subject_id    uuid NOT NULL,
    subject_label text NOT NULL DEFAULT '',
    entitlement_label text NOT NULL DEFAULT '',
    entitlement_type  text NOT NULL DEFAULT '',
    snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Assembled evidence: why it was granted, whether it has ever been used, whether
    -- the workload is still running, and any open SoD violation. This is the
    -- difference between a real review and a rubber stamp.
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Who has to decide, resolved at generation: resource-server owner -> the human who
    -- granted it -> workspace owner. Frozen, so a later ownership change cannot
    -- silently move an in-flight review.
    reviewer_user_id uuid,
    reviewer_label   text NOT NULL DEFAULT '',
    reviewer_source  text NOT NULL DEFAULT '',

    decision      text NOT NULL DEFAULT 'pending',
    decision_note text NOT NULL DEFAULT '',
    decided_by    uuid,
    decided_at    timestamptz,
    -- Set when a 'revoke' decision was actually carried out, so a decision that failed
    -- to execute is visibly distinct from one that succeeded.
    revocation_executed_at timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT certification_items_pkey PRIMARY KEY (id),
    CONSTRAINT certification_items_campaign_fkey FOREIGN KEY (campaign_id)
        REFERENCES public.certification_campaigns(id) ON DELETE CASCADE,
    CONSTRAINT certification_items_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT certification_items_provenance_fkey FOREIGN KEY (entitlement_provenance_id)
        REFERENCES public.entitlement_provenance(id) ON DELETE SET NULL,
    CONSTRAINT certification_items_reviewer_fkey FOREIGN KEY (reviewer_user_id)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT certification_items_decided_by_fkey FOREIGN KEY (decided_by)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT certification_items_decision_chk CHECK (
        decision IN ('pending', 'keep', 'revoke', 'delegate')),
    -- A decision must record who made it and when. An undated decision is not evidence.
    CONSTRAINT certification_items_decided_chk CHECK (
        decision = 'pending' OR (decided_at IS NOT NULL)),
    -- Keeping an entitlement needs a reason as much as revoking one does: "keep"
    -- without justification is exactly the rubber stamp certification exists to stop.
    CONSTRAINT certification_items_keep_note_chk CHECK (
        decision <> 'keep' OR decision_note <> '')
);

-- One item per entitlement per campaign. Without this, re-running generation would
-- duplicate the reviewer's work and double-count the campaign totals.
CREATE UNIQUE INDEX certification_items_unique_key
    ON public.certification_items(campaign_id, entitlement_provenance_id)
    WHERE entitlement_provenance_id IS NOT NULL;

-- The reviewer's queue.
CREATE INDEX idx_certification_items_reviewer
    ON public.certification_items(workspace_id, reviewer_user_id, decision);
CREATE INDEX idx_certification_items_campaign
    ON public.certification_items(campaign_id, decision);

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.certification_campaigns') AS campaigns_table,
       to_regclass('public.certification_items')     AS items_table;

-- ============================================================================
-- GOVERNANCE: in-cluster actuation (PROVISIONING-GOVERNANCE-ARCHITECTURE.md §6.6)
--
-- NOT credential delivery. AuthSec's workload identity model is SECRETLESS: a workload
-- authenticates with a `spiffe-svid` client assertion using an SVID it already holds,
-- so governance grants access to an identity the workload has rather than shipping one
-- to it. What genuinely needs in-cluster action is quarantine ENFORCEMENT (a
-- NetworkPolicy -- `status='quarantined'` was advisory, enforced by nothing) and
-- verifying that a workload really runs as the ServiceAccount its entitlements are
-- anchored to.
--
-- Pull-based: the control plane cannot reach into a customer's cluster and should not
-- want to. An inbound connection is a hole in their network; an outbound poll is not.
-- Leases rather than locks, so a crashed agent's work returns to the queue -- which is
-- why every instruction kind must be idempotent.
-- ============================================================================
-- provisioning_instructions -------------------------------------------------
--
-- A pull-based work queue, one row per cluster-side action. Pull rather than push
-- because the control plane cannot reach into a customer's cluster, and should not want
-- to: an inbound connection is a hole in their network, an outbound poll is not.
--
-- LEASES, NOT LOCKS. An agent claims work with a time-bounded lease. If it crashes
-- mid-apply the lease expires and the instruction returns to pending, so work is never
-- silently lost -- at the cost of a possible re-apply, which is why every instruction
-- kind must be idempotent.
CREATE TABLE public.provisioning_instructions (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    -- Which cluster is responsible. NOT NULL: an instruction nobody owns is one nobody
    -- applies, and silently queuing work for a cluster that has no agent is worse than
    -- refusing to queue it.
    discovery_source_id uuid NOT NULL,

    kind    text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- What this instruction is about, for the console and for dedupe.
    discovered_agent_id uuid,
    fingerprint         text NOT NULL DEFAULT '',

    -- Collapses a re-issued instruction onto the existing row rather than queuing the
    -- same action twice. Quarantining an already-quarantined agent should be a no-op,
    -- not a second NetworkPolicy write.
    idempotency_key text NOT NULL,

    status   text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,

    lease_expires_at timestamptz,
    leased_by        text NOT NULL DEFAULT '',
    applied_at       timestamptz,
    -- What the agent reported. For verify_uptake this is the ANSWER, not just an
    -- acknowledgement, which is why it is structured rather than a status flag.
    result jsonb,
    error  text NOT NULL DEFAULT '',

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT provisioning_instructions_pkey PRIMARY KEY (id),
    CONSTRAINT provisioning_instructions_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT provisioning_instructions_source_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE CASCADE,
    CONSTRAINT provisioning_instructions_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,
    CONSTRAINT provisioning_instructions_kind_chk CHECK (
        kind IN ('quarantine', 'unquarantine', 'verify_uptake')),
    -- 'superseded' is an instruction overtaken by a newer, contradicting decision
    -- before it was applied — a quarantine released before the cluster agent polled.
    -- Kept rather than deleted so an operator can see the decision was overtaken
    -- rather than find a gap where a row used to be. Not "open", so it never blocks a
    -- later enqueue for the same key.
    CONSTRAINT provisioning_instructions_status_chk CHECK (
        status IN ('pending', 'leased', 'applied', 'failed', 'superseded')),
    -- A terminal instruction must say when it finished. An applied row with no
    -- timestamp cannot be reasoned about later.
    CONSTRAINT provisioning_instructions_terminal_chk CHECK (
        status NOT IN ('applied', 'failed') OR applied_at IS NOT NULL),
    -- A failure must say why, or the console can only report that something went wrong.
    CONSTRAINT provisioning_instructions_failure_chk CHECK (
        status <> 'failed' OR error <> '')
);

-- One OPEN instruction per idempotency key. Partial, so the history of completed
-- instructions is unconstrained and an agent can be quarantined, released, and
-- quarantined again.
CREATE UNIQUE INDEX provisioning_instructions_open_key
    ON public.provisioning_instructions(discovery_source_id, idempotency_key)
    WHERE status IN ('pending', 'leased');

-- The agent's poll: pending work for my cluster, oldest first.
CREATE INDEX idx_provisioning_instructions_queue
    ON public.provisioning_instructions(discovery_source_id, status, created_at);
-- The lease reaper.
CREATE INDEX idx_provisioning_instructions_leases
    ON public.provisioning_instructions(lease_expires_at)
    WHERE status = 'leased';
CREATE INDEX idx_provisioning_instructions_agent
    ON public.provisioning_instructions(discovered_agent_id)
    WHERE discovered_agent_id IS NOT NULL;


-- ============================================================================
-- GOVERNANCE: human lifecycle (joiner / mover / leaver)
--
-- RECONCILED, not event-driven. ARCHITECTURE.md §4.5 proposed consuming scim_events;
-- that table is an HTTP AUDIT LOG (method, path, status_code) with no semantic payload,
-- so `PATCH /Users/123` could be a rename, a deactivation, or a group edit and the
-- before/after state is recorded nowhere. JML cannot be derived from it.
--
-- Reconciling is strictly better anyway: it catches changes made through ANY path (SCIM,
-- console, direct SQL), it is idempotent and self-healing, and it needs no cursor --
-- desired state is computable from birthright policies and actual state is already in
-- entitlement_provenance (origin='birthright').
--
-- NOTE: the authoritative deactivation flag on `users` is `active` (models.User.Active,
-- and what the SCIM controller writes). `is_active` is a vestigial duplicate with no
-- model field and no writer -- reading it would make a leaver invisible.
-- ============================================================================
-- birthright_policies -------------------------------------------------------
--
-- "Everyone in this group gets this role on this Application." The joiner half of JML,
-- and the thing a mover diff is computed against.
--
-- Matching is GROUP-based (or workspace-wide). Deliberately not department- or
-- title-based: `users` has no such column, and inventing one would mean matching on a
-- field nothing populates.
CREATE TABLE public.birthright_policies (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',

    -- WHO it applies to.
    match_kind     text NOT NULL DEFAULT 'group',
    match_group_id uuid,

    -- WHAT they get.
    resource_server_id uuid NOT NULL,
    role_id            uuid NOT NULL,

    -- FOR HOW LONG. NULL duration means a STANDING grant, which the provenance layer
    -- requires a justification for -- so the same "ephemeral by default, permanent is
    -- the audited exception" rule applies to birthrights as to everything else.
    duration      interval,
    justification text NOT NULL DEFAULT '',

    -- What to do when a user STOPS matching (the mover case). Default 'flag', because
    -- auto-revoking on a group change would let a mistyped group membership take
    -- someone's access away with no human in the loop. Revoking is opt-in per policy.
    on_unmatch text NOT NULL DEFAULT 'flag',

    enabled    boolean NOT NULL DEFAULT true,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT birthright_policies_pkey PRIMARY KEY (id),
    CONSTRAINT birthright_policies_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_group_fkey FOREIGN KEY (match_group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_rs_fkey FOREIGN KEY (resource_server_id)
        REFERENCES public.resource_servers(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_role_fkey FOREIGN KEY (role_id)
        REFERENCES public.roles(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_match_kind_chk CHECK (match_kind IN ('group', 'all')),
    CONSTRAINT birthright_policies_on_unmatch_chk CHECK (on_unmatch IN ('flag', 'revoke')),
    -- A group policy must name a group; an 'all' policy must not, or it would look
    -- scoped while applying to everyone.
    CONSTRAINT birthright_policies_match_chk CHECK (
        (match_kind = 'group' AND match_group_id IS NOT NULL)
     OR (match_kind = 'all'   AND match_group_id IS NULL)),
    -- A standing birthright must say why it is permanent, mirroring the provenance
    -- rule. Without this, "no duration" would quietly become the easy default for
    -- policies that apply to entire groups -- the widest blast radius there is.
    CONSTRAINT birthright_policies_standing_chk CHECK (
        duration IS NOT NULL OR justification <> ''),
    CONSTRAINT birthright_policies_name_key UNIQUE (workspace_id, name)
);

-- One policy per (match, grant) target. Stops two identically-scoped policies both
-- granting the same role, which would make the reconcile's "does this grant still have
-- a matching policy?" question ambiguous.
CREATE UNIQUE INDEX birthright_policies_target_key
    ON public.birthright_policies(
        workspace_id, match_kind,
        COALESCE(match_group_id, '00000000-0000-0000-0000-000000000000'::uuid),
        resource_server_id, role_id);

CREATE INDEX idx_birthright_policies_enabled
    ON public.birthright_policies(workspace_id) WHERE enabled;
CREATE INDEX idx_birthright_policies_group
    ON public.birthright_policies(match_group_id) WHERE match_group_id IS NOT NULL;

-- ============================================================================
-- Bridge: the k8s runtime inventory <-> the correlated IGA estate.
-- Two agent models coexist and neither subsumes the other: discovered_agents is
-- what is actually running in a cluster, iga_agents is the logical agent across
-- every channel. This is the join, and it only ever PROPOSES -- the models share
-- no identifier, so a weak link needs a recorded human decision (the CHECK below
-- mirrors iga_correlations_weak_chk).
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.discovered_agent_iga_links (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    discovered_agent_id uuid NOT NULL,
    iga_agent_id        uuid NOT NULL,

    -- The evidence. Recorded so a reviewer can see WHY this was proposed rather
    -- than being asked to trust it: an unexplained proposal is one a reviewer can
    -- only rubber-stamp.
    join_key text NOT NULL DEFAULT '',
    strength text NOT NULL DEFAULT 'weak',

    state      text NOT NULL DEFAULT 'proposed',
    decided_by uuid,
    decided_at timestamptz,

    -- Optimistic concurrency, matching the iga_* decision routes: a decision
    -- carrying a stale version is rejected rather than silently winning.
    version bigint NOT NULL DEFAULT 1,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT discovered_agent_iga_links_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agent_iga_links_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- CASCADE on both sides: if either entity goes, the claim that they are the
    -- same thing is meaningless. This is what makes an invalid state
    -- unrepresentable rather than merely unlikely.
    CONSTRAINT discovered_agent_iga_links_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_iga_links_iga_fkey FOREIGN KEY (workspace_id, iga_agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,

    CONSTRAINT discovered_agent_iga_links_strength_chk CHECK (strength IN ('strong', 'weak')),
    CONSTRAINT discovered_agent_iga_links_state_chk CHECK (
        state IN ('proposed', 'accepted', 'rejected')),
    -- Mirrors iga_correlations_weak_chk. A weak join that claims accepted status
    -- without a decision is a bug, not a shortcut.
    CONSTRAINT discovered_agent_iga_links_weak_chk CHECK (
        state <> 'accepted' OR strength = 'strong' OR decided_by IS NOT NULL),
    -- A decision must say when it happened, or it cannot be reasoned about later.
    CONSTRAINT discovered_agent_iga_links_decided_chk CHECK (
        state = 'proposed' OR decided_at IS NOT NULL),

    -- One link per discovered agent: a k8s workload is one logical agent, or none.
    -- Re-proposing therefore updates in place rather than accumulating rows, and
    -- the repository refuses to overwrite a link that has already been DECIDED --
    -- so a rejected link stays rejected instead of being re-proposed on every
    -- sighting.
    CONSTRAINT discovered_agent_iga_links_agent_key UNIQUE (workspace_id, discovered_agent_id)
);

-- The reverse join: "which running workloads are believed to be this agent?"
CREATE INDEX IF NOT EXISTS idx_discovered_agent_iga_links_iga
    ON public.discovered_agent_iga_links(workspace_id, iga_agent_id);

-- A reviewer's queue: proposals still awaiting a decision.
CREATE INDEX IF NOT EXISTS idx_discovered_agent_iga_links_proposed
    ON public.discovered_agent_iga_links(workspace_id) WHERE state = 'proposed';


-- ===========================================================================
-- discovery_scan_runs — durable record + work queue for a GitHub scan.
-- Mirrors 007_discovery_scan_runs.sql so a FRESH bootstrap and an UPGRADED
-- database end at the same schema. Keep the two in step: the rationale for
-- every column lives in 007, not here.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.discovery_scan_runs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    -- ON DELETE CASCADE: a scan report for a source that no longer exists has
    -- no reader. The FINDINGS outlive the source (discovered_agents keeps them);
    -- the report of how they were gathered does not.
    source_id    uuid NOT NULL
        REFERENCES public.discovery_sources(id) ON DELETE CASCADE,

    -- queued -> running -> succeeded | failed | cancelled
    status text NOT NULL DEFAULT 'queued',

    -- The PLAN, snapshotted at enqueue time. A scan must report the plan it
    -- actually ran under: if an admin widens the selection while a scan is in
    -- flight, the finished report still describes what was really inspected.
    selection_mode text NOT NULL DEFAULT '',
    branch_mode    text NOT NULL DEFAULT 'default',
    max_branches   integer NOT NULL DEFAULT 0,

    -- Counters. repos_failed and repos_excluded stay separate for the reason
    -- that runs through this whole feature: "we could not look" and "we chose
    -- not to look" are different answers and neither one means "clean".
    repos_selected   integer NOT NULL DEFAULT 0,
    repos_scanned    integer NOT NULL DEFAULT 0,
    repos_failed     integer NOT NULL DEFAULT 0,
    repos_excluded   integer NOT NULL DEFAULT 0,
    repos_truncated  integer NOT NULL DEFAULT 0,
    branches_scanned integer NOT NULL DEFAULT 0,
    -- Branches beyond max_branches. Non-zero must force complete=false: we know
    -- there were more refs and we did not read them.
    branches_skipped integer NOT NULL DEFAULT 0,
    files_fetched    integer NOT NULL DEFAULT 0,
    -- Files the scan could not read. Distinct from repos_failed: a readable
    -- repository can still hold a file we failed to fetch, and reporting only
    -- the repository count shows "0 failed" beside a page of file errors.
    files_failed     integer NOT NULL DEFAULT 0,
    sightings_new    integer NOT NULL DEFAULT 0,
    sightings_bumped integer NOT NULL DEFAULT 0,

    -- complete_for_selected_scope. Only true when every selected unit was fully
    -- read. Never averaged, never inferred from "no errors logged".
    complete boolean NOT NULL DEFAULT false,

    -- Monotonic "we know we missed something": set the first time any unit is
    -- unreadable, any tree is truncated, or the branch cap bites, and never
    -- cleared.
    --
    -- It exists because `complete` cannot be written while a run is in flight —
    -- the CHECK below reserves it for a finished run, so that a queued or failed
    -- row can never read as an authoritative all-clear. Without a separate flag,
    -- a scan interrupted and resumed would have no way to carry "attempt one hit
    -- a 403" across the restart, and would finish claiming complete coverage it
    -- never had. Completeness is therefore DERIVED at the end: succeeded AND NOT
    -- degraded.
    degraded boolean NOT NULL DEFAULT false,

    excluded_repositories jsonb NOT NULL DEFAULT '[]'::jsonb,
    warnings              jsonb NOT NULL DEFAULT '[]'::jsonb,
    error                 text  NOT NULL DEFAULT '',

    -- Resume cursor: {"done": ["acme/payments@main", ...]}. A unit already in
    -- here is skipped on a retry, so an interrupted scan continues rather than
    -- re-paying for the repositories it already read.
    cursor jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Lease. leased_until in the past means the worker holding it died; another
    -- worker may take the run over. attempts bounds that so a run that crashes
    -- the worker every time is marked failed instead of looping forever.
    attempts     integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    leased_by    text NOT NULL DEFAULT '',
    leased_until timestamptz,
    heartbeat_at timestamptz,

    requested_by text NOT NULL DEFAULT '',
    queued_at    timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT discovery_scan_runs_status_chk CHECK (
        status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
    ),
    CONSTRAINT discovery_scan_runs_branch_mode_chk CHECK (
        branch_mode IN ('default', 'all')
    ),
    -- A finished run must say when it finished, and an unfinished one must not
    -- claim to have. Without this a crashed worker can leave a row that reads
    -- as succeeded-but-still-running.
    CONSTRAINT discovery_scan_runs_finished_chk CHECK (
        (status IN ('succeeded', 'failed', 'cancelled')) = (finished_at IS NOT NULL)
    ),
    -- Completeness is only meaningful for a run that finished successfully.
    -- A queued or failed run asserting complete=true would be read by the
    -- console as an authoritative all-clear it never earned.
    CONSTRAINT discovery_scan_runs_complete_chk CHECK (
        NOT complete OR status = 'succeeded'
    )
);

-- One active scan per source. An admin double-clicking Scan, or a webhook
-- firing while a manual scan runs, must not put two workers on the same
-- repositories: they would race on the same fingerprints and bill twice for
-- identical work. The partial predicate lets history accumulate freely.
CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_scan_runs_active
    ON public.discovery_scan_runs (source_id)
    WHERE status IN ('queued', 'running');

-- The worker's claim query: oldest queued (or expired-lease) run first.
CREATE INDEX IF NOT EXISTS idx_discovery_scan_runs_claim
    ON public.discovery_scan_runs (status, leased_until, queued_at);

-- The console's history query: newest first for one source.
CREATE INDEX IF NOT EXISTS idx_discovery_scan_runs_source
    ON public.discovery_scan_runs (workspace_id, source_id, queued_at DESC);


-- ===========================================================================
-- discovery_rule_catalogs — per-workspace detection-pattern overlay.
-- Mirrors 009_discovery_rule_catalogs.sql so a FRESH bootstrap and an
-- UPGRADED database end at the same schema. Rationale lives in 009.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.discovery_rule_catalogs (
    -- One overlay per workspace. The workspace IS the key: a second row would
    -- mean two answers to "what does this workspace search for".
    workspace_id uuid PRIMARY KEY,

    -- The overlay: {"vocabularies":{...},"rules":{...},"custom_rules":[...]}.
    -- Shape and limits are enforced in Go before write; see
    -- services/iga_rule_catalog_config.go.
    overlay jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Version of the built-in catalogue this overlay was authored against.
    -- Kept so that a later built-in change that conflicts with an overlay can be
    -- reported to the customer instead of quietly resolved.
    based_on text NOT NULL DEFAULT '',

    -- Content hash of the overlay, recomputed on write. Combined with the
    -- built-in version it forms the effective catalogue version stamped onto
    -- every finding.
    overlay_hash text NOT NULL DEFAULT '',

    updated_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);


-- ===========================================================================
-- cloud_connector — one onboarded cloud account, project or subscription.
-- Mirrors 010_cloud_discovery_connector.sql so a FRESH bootstrap and an
-- UPGRADED database end at the same schema. Rationale, and the recorded
-- deviations from the shared cross-cloud schema note, live in 010.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_connector (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    -- aws | gcp | azure.
    provider text NOT NULL,

    -- account | project | folder | org | subscription.
    scope_kind text NOT NULL,

    -- The provider's own identifier for the scope, verbatim. A join key, never
    -- a display name.
    scope_id text NOT NULL,

    -- Azure tenant, GCP org. NULL, not '', when there is no parent.
    parent_scope_id text,

    -- A HANDLE, never key material: for AWS, the secrets-store path holding the
    -- ExternalId.
    auth_ref text NOT NULL DEFAULT '',

    -- active | revoked | error.
    status text NOT NULL DEFAULT 'active',

    -- Bumped once per scan; drives reconciliation against last_seen_generation.
    scan_generation integer NOT NULL DEFAULT 0,

    -- Per surface (per region x surface for AWS): reached | denied |
    -- not_configured | throttled. Keeps "could not read" distinguishable from
    -- "found nothing".
    coverage jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Provider extras. For AWS: role_arn, regions, caller_arn.
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- When the connection was last PROVEN by assuming the role and reading the
    -- identity back. NULL means never proven, not broken.
    verified_at timestamptz,
    last_error  text NOT NULL DEFAULT '',

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_connector_provider_chk CHECK (
        provider IN ('aws', 'gcp', 'azure')
    ),
    CONSTRAINT cloud_connector_scope_kind_chk CHECK (
        scope_kind IN ('account', 'project', 'folder', 'org', 'subscription')
    ),
    CONSTRAINT cloud_connector_status_chk CHECK (
        status IN ('active', 'revoked', 'error')
    ),
    CONSTRAINT cloud_connector_scope_id_chk CHECK (scope_id <> ''),
    CONSTRAINT cloud_connector_error_chk CHECK (
        status <> 'error' OR last_error <> ''
    ),
    CONSTRAINT cloud_connector_auth_ref_chk CHECK (
        status <> 'active' OR auth_ref <> ''
    ),
    CONSTRAINT cloud_connector_scan_generation_chk CHECK (scan_generation >= 0)
);

-- One row per onboarded scope; the conflict target for the onboarding upsert.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_connector_scope
    ON public.cloud_connector (workspace_id, provider, scope_id);

CREATE INDEX IF NOT EXISTS idx_cloud_connector_workspace
    ON public.cloud_connector (workspace_id, provider, status);


-- ===========================================================================
-- cloud_identity / cloud_secret — the identity foundation of cloud discovery.
-- Mirrors 011_cloud_identity_and_secret.sql so a FRESH bootstrap and an
-- UPGRADED database end at the same schema. Rationale lives in 011, including
-- why created_at holds the PROVIDER's creation time rather than the row's.
-- ===========================================================================

-- ===========================================================================
-- cloud_identity — what code runs as.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_identity (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    -- The connector that most recently saw this identity. ON DELETE CASCADE:
    -- disconnecting an account removes what that account's connector found.
    -- There is no orphan state worth keeping — an identity with no way to reach
    -- it can never be refreshed, re-verified or acted on.
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The real provider object name, never an AuthSec abstraction.
    --   AWS   iam_role | iam_user   (agentcore_workload_identity to follow)
    --   GCP   service_account
    --   AZURE service_principal | managed_identity
    kind text NOT NULL,

    -- The provider's own id, verbatim. For AWS the role or user ARN. This is
    -- the cross-connector join key, which is why it is unique per workspace
    -- rather than per connector: the shared note's rule is "one identity, one
    -- row — two connectors seeing the same principal update the same row,
    -- matched on native_id". An ARN already encodes its account, so this cannot
    -- collide across two legitimately different principals.
    native_id text NOT NULL,

    name text NOT NULL DEFAULT '',

    -- PROVIDER creation time. See the header. Nullable because a provider may
    -- not report one.
    created_at timestamptz,

    -- NULL means UNKNOWN, never "never used". The distinction is load-bearing:
    -- an unused over-privileged role is a finding, and an unknown one is a gap
    -- in our coverage. Reporting the second as the first would manufacture
    -- findings out of our own blind spots.
    last_used_at timestamptz,

    -- AWS has no disable switch for a role or user, so this is always true
    -- there. It exists for the providers that do.
    enabled boolean NOT NULL DEFAULT true,

    -- Small provider extras. For AWS: the unique id (AROA.../AIDA...), path,
    -- description, tags, max session duration.
    --
    -- The unique id lives here rather than replacing native_id as the key: the
    -- ARN is what every other connector and every policy document refers to, so
    -- it has to stay the join key. But a role deleted and recreated with the
    -- same name has the SAME ARN and a DIFFERENT unique id, so keeping the id
    -- is the only way to notice that the principal is not the one we saw last
    -- week.
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Reconciliation. Stamped with cloud_connector.scan_generation on every
    -- scan that sees this row. A row whose generation has fallen behind was not
    -- seen last time — which is only meaningful if that surface was actually
    -- reached, hence cloud_connector.coverage.
    last_seen_generation integer NOT NULL DEFAULT 0,

    -- OUR bookkeeping, deliberately named apart from created_at.
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_identity_kind_chk CHECK (kind <> ''),
    CONSTRAINT cloud_identity_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_identity_generation_chk CHECK (last_seen_generation >= 0)
);

-- One identity, one row. The conflict target for the scan's upsert, and what
-- makes a repeat scan an update rather than a duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_identity_native
    ON public.cloud_identity (workspace_id, native_id);

-- The scan's own reconciliation query: everything this connector saw, by
-- generation.
CREATE INDEX IF NOT EXISTS idx_cloud_identity_connector_generation
    ON public.cloud_identity (connector_id, last_seen_generation);

-- The console's list query.
CREATE INDEX IF NOT EXISTS idx_cloud_identity_workspace_kind
    ON public.cloud_identity (workspace_id, kind);

-- ===========================================================================
-- cloud_secret — the long-lived secret that proves an identity.
-- ===========================================================================
--
-- METADATA ONLY. There is no column here that accepts a secret value, and that
-- is a deliberate structural guarantee rather than a convention: a schema with
-- nowhere to put a value cannot leak one through a careless INSERT, a debug
-- log of a row, or a database backup. native_id holds a key IDENTIFIER — an
-- AWS access key id (AKIA...), which is public in the sense that it appears in
-- CloudTrail and in the credential report.

CREATE TABLE IF NOT EXISTS public.cloud_secret (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The identity this secret proves. NOT NULL: an access key without its user
    -- is not a finding, it is a fragment.
    --
    -- NOTE for the schema owner: AgentCore OAuth2 and API-key credential
    -- providers are account-scoped rather than owned by one identity, so
    -- writing them here (planned for ticket [3]) will need this relaxed to
    -- nullable. Raised in the AWS plan's section 6 and not yet decided; left
    -- NOT NULL until it is, because loosening a constraint later is an
    -- expand-only change while tightening one is not.
    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,

    -- AWS access_key. GCP sa_json_key. AZURE client_secret | certificate.
    kind text NOT NULL,

    -- The key IDENTIFIER only. Never material.
    native_id text NOT NULL,

    -- PROVIDER creation time. "Age is the finding" — this is the column the
    -- stale-credential report reads.
    created_at timestamptz,

    -- NULL where the provider has no expiry, which is the case for every AWS
    -- access key. Not "no expiry recorded" — AWS access keys genuinely do not
    -- expire, which is itself why their age matters.
    expires_at timestamptz,

    -- NULL means unknown, never "never used". AWS reports a key that has never
    -- been used by omitting the date, so the scanner must not turn that into a
    -- zero timestamp.
    last_used_at timestamptz,

    -- active | inactive, the provider's own words.
    status text NOT NULL DEFAULT 'active',

    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_secret_kind_chk CHECK (kind <> ''),
    CONSTRAINT cloud_secret_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_secret_status_chk CHECK (status IN ('active', 'inactive')),
    CONSTRAINT cloud_secret_generation_chk CHECK (last_seen_generation >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_secret_native
    ON public.cloud_secret (workspace_id, native_id);

CREATE INDEX IF NOT EXISTS idx_cloud_secret_identity
    ON public.cloud_secret (identity_id);

CREATE INDEX IF NOT EXISTS idx_cloud_secret_connector_generation
    ON public.cloud_secret (connector_id, last_seen_generation);

-- Stale-credential reporting: oldest active keys first, which is the whole
-- point of holding created_at.
CREATE INDEX IF NOT EXISTS idx_cloud_secret_age
    ON public.cloud_secret (workspace_id, status, created_at);

-- ===========================================================================
-- cloud_assume_edge — who may become an identity. Mirrors
-- 012_cloud_assume_edge.sql so a fresh bootstrap and an existing database that
-- ran the migration reach the same end state.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_assume_edge (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,
    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,

    subject_kind text NOT NULL,
    subject text NOT NULL,
    issuer text,
    mechanism text NOT NULL,
    k8s_ref text,

    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_assume_edge_subject_kind_chk CHECK (subject_kind <> ''),
    CONSTRAINT cloud_assume_edge_mechanism_chk CHECK (mechanism <> ''),
    CONSTRAINT cloud_assume_edge_subject_chk CHECK (subject <> ''),
    CONSTRAINT cloud_assume_edge_k8s_ref_chk CHECK (
        subject_kind <> 'k8s_service_account' OR k8s_ref IS NOT NULL
    ),
    CONSTRAINT cloud_assume_edge_generation_chk CHECK (last_seen_generation >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_assume_edge_subject
    ON public.cloud_assume_edge (identity_id, subject_kind, subject);

CREATE INDEX IF NOT EXISTS idx_cloud_assume_edge_connector_generation
    ON public.cloud_assume_edge (connector_id, last_seen_generation);

CREATE INDEX IF NOT EXISTS idx_cloud_assume_edge_k8s_ref
    ON public.cloud_assume_edge (k8s_ref, issuer) WHERE k8s_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cloud_assume_edge_identity
    ON public.cloud_assume_edge (identity_id);

-- ===========================================================================
-- cloud_resource / cloud_permission — what an identity may reach, and what it
-- is granted to do there. Mirrors 013_cloud_permission_and_resource.sql so a
-- fresh bootstrap and an existing database that ran the migration reach the
-- same end state.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_resource (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    kind text NOT NULL,
    native_id text NOT NULL,
    name text NOT NULL DEFAULT '',
    sensitivity text NOT NULL DEFAULT 'low',

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_resource_kind_chk CHECK (kind <> ''),
    CONSTRAINT cloud_resource_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_resource_sensitivity_chk CHECK (
        sensitivity IN ('low', 'med', 'high')
    ),
    CONSTRAINT cloud_resource_generation_chk CHECK (last_seen_generation >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_resource_native
    ON public.cloud_resource (workspace_id, native_id);

CREATE INDEX IF NOT EXISTS idx_cloud_resource_connector_generation
    ON public.cloud_resource (connector_id, last_seen_generation);

CREATE TABLE IF NOT EXISTS public.cloud_permission (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,
    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,
    resource_id uuid
        REFERENCES public.cloud_resource(id) ON DELETE CASCADE,

    plane text NOT NULL DEFAULT 'cloud',
    effect text NOT NULL,
    role_name text,
    actions text[] NOT NULL,
    scope_kind text NOT NULL,
    derivation text NOT NULL DEFAULT 'granted',
    sensitivity text NOT NULL DEFAULT 'low',
    last_exercised_at timestamptz,
    native_id text NOT NULL,

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_permission_plane_chk CHECK (plane IN ('cloud', 'api')),
    CONSTRAINT cloud_permission_effect_chk CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT cloud_permission_scope_kind_chk CHECK (
        scope_kind IN ('resource', 'prefix', 'account_wide')
    ),
    CONSTRAINT cloud_permission_scope_resource_chk CHECK (
        (scope_kind = 'resource') = (resource_id IS NOT NULL)
    ),
    CONSTRAINT cloud_permission_derivation_chk CHECK (
        derivation IN ('granted', 'effective')
    ),
    CONSTRAINT cloud_permission_sensitivity_chk CHECK (
        sensitivity IN ('low', 'med', 'high')
    ),
    CONSTRAINT cloud_permission_actions_chk CHECK (array_length(actions, 1) > 0),
    CONSTRAINT cloud_permission_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_permission_generation_chk CHECK (last_seen_generation >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_permission_grant
    ON public.cloud_permission (identity_id, native_id, resource_id)
    NULLS NOT DISTINCT;

CREATE INDEX IF NOT EXISTS idx_cloud_permission_connector_generation
    ON public.cloud_permission (connector_id, last_seen_generation);

CREATE INDEX IF NOT EXISTS idx_cloud_permission_identity
    ON public.cloud_permission (identity_id);

CREATE INDEX IF NOT EXISTS idx_cloud_permission_resource
    ON public.cloud_permission (resource_id) WHERE resource_id IS NOT NULL;
