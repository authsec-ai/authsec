-- ============================================================================
-- AuthSec v4 — Master DB Bootstrap
-- ============================================================================
-- A single, self-contained schema definition for a fresh AuthSec database.
-- Brings up the entire v4 schema in one transaction: tables (80), constraints,
-- indexes, triggers, the 7 trigger functions that fire on UPDATE, and seeds
-- the system tenant + base permissions. After this file runs, the DB is ready
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
    CONSTRAINT agent_action_decisions_pkey PRIMARY KEY (id)
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
    CONSTRAINT agent_guard_settings_tenant_id_key UNIQUE (workspace_id)
);

CREATE TABLE public.audit_events (
    id bigint NOT NULL,
    request_id text,
    workspace_id text,
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
    workspace_id uuid,
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
    tenant_domain text,
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
    workspace_id uuid,
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_tenant_id_id_key UNIQUE (workspace_id, id),
    CONSTRAINT uni_groups_tenant_name UNIQUE (workspace_id, name)
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
    deleted_at timestamp with time zone,
    pending_redirect_uris text[] DEFAULT '{}'::text[],
    redirect_review_pending boolean DEFAULT false,
    post_logout_redirect_uris text[] DEFAULT '{}'::text[],
    supports_refresh_token boolean DEFAULT false,
    sync_status text DEFAULT 'active'::text NOT NULL,
    sync_last_error text,
    sync_last_error_at timestamp with time zone,
    CONSTRAINT mcp_oauth_clients_sync_status_chk CHECK (sync_status IN ('active', 'sync_error', 'pending_delete')),
    CONSTRAINT mcp_oauth_clients_client_id_key UNIQUE (client_id),
    CONSTRAINT mcp_oauth_clients_hydra_client_id_key UNIQUE (hydra_client_id),
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
    ARRAY['http://localhost:3000/oidc/auth/callback', 'https://app.authsec.dev/oidc/auth/callback'],
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
    client_id uuid NOT NULL,
    resource_server_id uuid NOT NULL,
    granted_scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_consent_grants_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_consent_grants_tenant_id_user_id_client_id_resource_s_key UNIQUE (workspace_id, user_id, client_id, resource_server_id)
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
    workspace_id uuid,
    display_name_override text,
    redirect_uri text,
    CONSTRAINT oidc_providers_pkey PRIMARY KEY (id)
);

CREATE TABLE public.oidc_states (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    state_token character varying(255) NOT NULL,
    workspace_id uuid,
    tenant_domain character varying(255) NOT NULL,
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
    profile_data jsonb,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT oidc_user_identities_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_user_identities_workspace_provider_unique UNIQUE (workspace_id, provider_name, provider_user_id),
    CONSTRAINT oidc_user_identities_tenant_user_provider_unique UNIQUE (workspace_id, user_id, provider_name)
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
    tenant_domain character varying(255) NOT NULL,
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
    workspace_id uuid,
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
    deleted_at timestamp with time zone,
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
    CONSTRAINT resource_servers_application_type_chk CHECK (application_type IN ('mcp_server', 'ai_agent', 'clawbot', 'api_service')),
    CONSTRAINT resource_servers_pkey PRIMARY KEY (id)
    -- resource_uri uniqueness is enforced by the partial index below so that
    -- soft-deleted rows (deleted_at IS NOT NULL) do not block re-registration
    -- of the same URL. The old unconditional UNIQUE constraint caused
    -- "duplicate key" errors whenever an operator deleted an application and
    -- tried to recreate it with the same base URL.
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
    workspace_id uuid,
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
    workspace_id uuid,
    client_id uuid,
    login_challenge text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL,
    CONSTRAINT saml_callback_states_pkey PRIMARY KEY (id)
);

CREATE TABLE public.saml_requests (
    id character varying(255) NOT NULL,
    login_challenge character varying(255) NOT NULL,
    workspace_id uuid NOT NULL,
    client_id uuid NOT NULL,
    provider_name character varying(255) NOT NULL,
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
    CONSTRAINT saml_sp_certificates_tenant_id_key UNIQUE (workspace_id)
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
    entra_tenant_id character varying(500),
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
    CONSTRAINT sync_configurations_tenant_id_config_name_key UNIQUE (workspace_id, config_name)
);

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
    CONSTRAINT fk_tenant_device_token UNIQUE (device_token, workspace_id),
    CONSTRAINT workspace_device_tokens_device_token_key UNIQUE (device_token),
    CONSTRAINT workspace_device_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT uq_tenant_device_id_tenant UNIQUE (id, workspace_id)
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


CREATE TABLE public.workspace_user_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    membership_type text DEFAULT 'member'::text NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    external_id text,
    invited_by uuid,
    joined_at timestamp with time zone,
    suspended_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_tm_source CHECK ((source = ANY (ARRAY['signup'::text, 'invite'::text, 'scim'::text, 'oidc_jit'::text, 'saml_jit'::text, 'api'::text, 'migration'::text]))),
    CONSTRAINT chk_tm_status CHECK ((status = ANY (ARRAY['active'::text, 'invited'::text, 'suspended'::text, 'left'::text]))),
    CONSTRAINT chk_tm_type CHECK ((membership_type = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'contractor'::text, 'service_operator'::text, 'readonly_auditor'::text]))),
    CONSTRAINT workspace_user_memberships_pkey PRIMARY KEY (id),
    CONSTRAINT workspace_user_memberships_workspace_id_user_id_key UNIQUE (workspace_id, user_id)
);

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
    CONSTRAINT workspace_totp_secrets_user_id_tenant_id_is_primary_key UNIQUE (user_id, workspace_id, is_primary)
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
    password_hash text,
    tenant_domain character varying(255) DEFAULT 'app.authsec.dev'::character varying,
    provider character varying(100) DEFAULT 'local'::character varying,
    provider_id character varying(255),
    provider_data jsonb DEFAULT '{}'::jsonb,
    avatar_url text,
    active boolean DEFAULT true,
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
    CONSTRAINT users_tenant_id_id_key UNIQUE (workspace_id, id)
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
    CONSTRAINT uq_voice_identity_tenant_platform_user UNIQUE (workspace_id, voice_platform, voice_user_id),
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
    role_id uuid NOT NULL REFERENCES public.roles(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspace_memberships_status_chk CHECK (status IN ('active', 'invited', 'suspended', 'left')),
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
    config_ref text NOT NULL,
    status text NOT NULL DEFAULT 'configured',
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT identity_providers_type_chk
        CHECK (provider_type IN ('oidc', 'saml', 'ad', 'entra', 'scim'))
);

CREATE INDEX idx_identity_providers_workspace ON public.identity_providers(workspace_id);
CREATE INDEX idx_identity_providers_type      ON public.identity_providers(provider_type);

-- application_identity_provider_policies — opt-in restriction of which IDPs
-- a given application (resource_servers row) accepts.
CREATE TABLE public.application_identity_provider_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES public.resource_servers(id) ON DELETE CASCADE,
    identity_provider_id uuid NOT NULL REFERENCES public.identity_providers(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT application_identity_provider_policies_uq UNIQUE (application_id, identity_provider_id)
);

CREATE INDEX idx_app_idp_policies_workspace ON public.application_identity_provider_policies(workspace_id);

-- scim_connections — workspace-scoped SCIM 2.0 connection tokens. Optional
-- back-reference to identity_providers if the SCIM source is itself an IDP.
CREATE TABLE public.scim_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    identity_provider_id uuid REFERENCES public.identity_providers(id) ON DELETE SET NULL,
    token_hash text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT scim_connections_status_chk CHECK (status IN ('active', 'revoked', 'disabled')),
    default_client_id uuid,
    default_project_id uuid
);

CREATE INDEX idx_scim_connections_workspace          ON public.scim_connections(workspace_id);
CREATE INDEX idx_scim_connections_identity_provider  ON public.scim_connections(identity_provider_id);

-- application_spiffe_identities — workspace-scoped SPIFFE ID ↔ Application
-- binding. Used by the agent-guard plane.
CREATE TABLE public.application_spiffe_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES public.resource_servers(id) ON DELETE CASCADE,
    spiffe_id text NOT NULL UNIQUE,
    trust_domain text NOT NULL,
    selectors jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT application_spiffe_identities_status_chk CHECK (status IN ('active', 'revoked', 'disabled'))
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
    created_at timestamptz DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_saml_provider_unique UNIQUE (workspace_id, provider_name)
);

CREATE INDEX idx_saml_providers_tenant_id ON public.saml_providers(workspace_id);

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
CREATE UNIQUE INDEX oidc_providers_provider_name_workspace_uq ON public.oidc_providers (workspace_id, provider_name);
CREATE UNIQUE INDEX oidc_providers_global_provider_name_uq ON public.oidc_providers (provider_name) WHERE workspace_id IS NULL;
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

CREATE UNIQUE INDEX groups_name_tenant_unique ON public.groups USING btree (name, workspace_id);

CREATE INDEX idx_agent_action_agent ON public.agent_action_requests USING btree (agent_id);

CREATE INDEX idx_agent_action_expires ON public.agent_action_requests USING btree (expires_at);

CREATE INDEX idx_agent_action_req_id ON public.agent_action_requests USING btree (action_req_id);

CREATE INDEX idx_agent_action_session ON public.agent_action_requests USING btree (session_id);

CREATE INDEX idx_agent_action_status ON public.agent_action_requests USING btree (status);

CREATE INDEX idx_agent_action_tenant ON public.agent_action_requests USING btree (workspace_id);

CREATE INDEX idx_agent_action_user ON public.agent_action_requests USING btree (user_id);

CREATE INDEX idx_agent_action_user_status ON public.agent_action_requests USING btree (user_id, status);

CREATE INDEX idx_agent_audit_action ON public.agent_action_audit_log USING btree (action);

CREATE INDEX idx_agent_audit_agent ON public.agent_action_audit_log USING btree (agent_id);

CREATE INDEX idx_agent_audit_created ON public.agent_action_audit_log USING btree (created_at);

CREATE INDEX idx_agent_audit_risk ON public.agent_action_audit_log USING btree (risk_level);

CREATE INDEX idx_agent_audit_status ON public.agent_action_audit_log USING btree (final_status);

CREATE INDEX idx_agent_audit_tenant ON public.agent_action_audit_log USING btree (workspace_id);

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

CREATE INDEX idx_audit_events_tenant_id ON public.audit_events USING btree (workspace_id);

CREATE INDEX idx_audit_events_timestamp ON public.audit_events USING btree ("timestamp");

CREATE INDEX idx_audit_events_user_id ON public.audit_events USING btree (user_id);

CREATE INDEX idx_backup_tenant ON public.totp_backup_codes USING btree (workspace_id);

CREATE INDEX idx_backup_used ON public.totp_backup_codes USING btree (is_used);

CREATE INDEX idx_backup_user ON public.totp_backup_codes USING btree (user_id);

CREATE INDEX idx_ciba_auth_expires ON public.ciba_auth_requests USING btree (expires_at);

CREATE INDEX idx_ciba_auth_status ON public.ciba_auth_requests USING btree (status);

CREATE INDEX idx_ciba_auth_tenant ON public.ciba_auth_requests USING btree (workspace_id);

CREATE INDEX idx_ciba_auth_user ON public.ciba_auth_requests USING btree (user_id);

-- Phase B: idx_clients_* indexes removed with the public.clients table.

CREATE INDEX idx_consent_grants_tenant ON public.oauth_consent_grants USING btree (workspace_id) WHERE (revoked_at IS NULL);

CREATE INDEX idx_consent_grants_user_client ON public.oauth_consent_grants USING btree (user_id, client_id, resource_server_id) WHERE (revoked_at IS NULL);

CREATE INDEX idx_credentials_created_at ON public.credentials USING btree (created_at);

CREATE INDEX idx_credentials_updated_at ON public.credentials USING btree (updated_at);

CREATE INDEX idx_deleg_policy_client_id ON public.delegation_policies USING btree (client_id);

CREATE INDEX idx_deleg_policy_lookup ON public.delegation_policies USING btree (workspace_id, role_name, agent_type, enabled);

CREATE INDEX idx_deleg_policy_tenant_id ON public.delegation_policies USING btree (workspace_id);

CREATE INDEX idx_deleg_token_expires ON public.delegation_tokens USING btree (expires_at) WHERE (status = 'active'::text);

CREATE INDEX idx_deleg_token_lookup ON public.delegation_tokens USING btree (workspace_id, client_id, status);

CREATE INDEX idx_deleg_token_policy ON public.delegation_tokens USING btree (policy_id);

CREATE INDEX idx_device_codes_device_code ON public.device_codes USING btree (device_code);

CREATE INDEX idx_device_codes_expires_at ON public.device_codes USING btree (expires_at);

CREATE INDEX idx_device_codes_status ON public.device_codes USING btree (status);

CREATE INDEX idx_device_codes_tenant_id ON public.device_codes USING btree (workspace_id);

CREATE INDEX idx_device_codes_user_code ON public.device_codes USING btree (user_code);

CREATE INDEX idx_device_codes_user_id ON public.device_codes USING btree (user_id);

CREATE INDEX idx_device_tokens_active ON public.device_tokens USING btree (is_active);

CREATE INDEX idx_device_tokens_tenant ON public.device_tokens USING btree (workspace_id);

CREATE INDEX idx_device_tokens_token ON public.device_tokens USING btree (device_token);

CREATE INDEX idx_device_tokens_user ON public.device_tokens USING btree (user_id);

CREATE INDEX idx_groups_created_at ON public.groups USING btree (created_at);

CREATE INDEX idx_groups_name ON public.groups USING btree (name);

CREATE INDEX idx_groups_tenant_id ON public.groups USING btree (workspace_id);

CREATE INDEX idx_groups_tenant_name ON public.groups USING btree (workspace_id, name);

CREATE INDEX idx_groups_updated_at ON public.groups USING btree (updated_at);

CREATE INDEX idx_mcp_oauth_clients_client_id ON public.mcp_oauth_clients USING btree (client_id);

CREATE INDEX idx_mcp_oauth_clients_hydra_client_id ON public.mcp_oauth_clients USING btree (hydra_client_id);

CREATE INDEX idx_mcp_tools_rs ON public.mcp_tools USING btree (resource_server_id);

CREATE INDEX idx_mcp_tools_rs_generation ON public.mcp_tools USING btree (resource_server_id, last_scan_generation);

CREATE INDEX idx_mcp_tools_tenant ON public.mcp_tools USING btree (workspace_id);

CREATE INDEX idx_mfa_methods_client_id ON public.mfa_methods USING btree (client_id);

CREATE INDEX idx_mfa_methods_enabled ON public.mfa_methods USING btree (enabled);

CREATE INDEX idx_mfa_methods_type ON public.mfa_methods USING btree (method_type);

CREATE INDEX idx_mfa_methods_user_id ON public.mfa_methods USING btree (user_id);

-- migration_logs indexes — add them defensively in case GORM AutoMigrate didn't
-- create them (older runner versions only created the table, not the helper indexes).
CREATE INDEX IF NOT EXISTS idx_migration_logs_workspace_id ON public.migration_logs USING btree (workspace_id);
CREATE INDEX IF NOT EXISTS idx_migration_logs_version      ON public.migration_logs USING btree (version);

CREATE INDEX idx_oauth_scope_perms_permission ON public.oauth_scope_permissions USING btree (permission_id);

CREATE INDEX idx_oauth_scopes_parent ON public.oauth_scopes USING btree (parent_scope_id);

CREATE INDEX idx_oauth_scopes_rs ON public.oauth_scopes USING btree (resource_server_id);

CREATE INDEX idx_oauth_scopes_tenant ON public.oauth_scopes USING btree (workspace_id);

CREATE UNIQUE INDEX idx_oauth_scopes_tenant_global_scope ON public.oauth_scopes USING btree (workspace_id, scope_string) WHERE (resource_server_id IS NULL);

CREATE INDEX idx_oidc_identities_provider_user ON public.oidc_user_identities USING btree (provider_name, provider_user_id);

CREATE INDEX idx_oidc_identities_tenant ON public.oidc_user_identities USING btree (workspace_id);

CREATE INDEX idx_oidc_identities_user ON public.oidc_user_identities USING btree (workspace_id, user_id);

CREATE INDEX idx_oidc_providers_active ON public.oidc_providers USING btree (is_active);

CREATE INDEX idx_oidc_states_expires ON public.oidc_states USING btree (expires_at);

CREATE INDEX idx_oidc_states_token ON public.oidc_states USING btree (state_token);

CREATE INDEX idx_otp_entries_email ON public.otp_entries USING btree (email);

CREATE INDEX idx_otp_entries_expires_at ON public.otp_entries USING btree (expires_at);

CREATE INDEX idx_otp_entries_verified ON public.otp_entries USING btree (verified);

CREATE INDEX idx_pending_registrations_email ON public.pending_registrations USING btree (email);

CREATE INDEX idx_pending_registrations_expires_at ON public.pending_registrations USING btree (expires_at);

CREATE INDEX idx_pending_registrations_tenant_id ON public.pending_registrations USING btree (workspace_id);

CREATE UNIQUE INDEX idx_permissions_global_id ON public.permissions USING btree (id) WHERE (workspace_id IS NULL);

CREATE UNIQUE INDEX idx_permissions_global_resource_action ON public.permissions USING btree (resource, action) WHERE (workspace_id IS NULL);

CREATE UNIQUE INDEX idx_permissions_tenant_resource_action_unique ON public.permissions USING btree (workspace_id, resource, action);

CREATE INDEX idx_pkce_verifiers_expires_at ON public.pkce_verifiers USING btree (expires_at);

CREATE INDEX idx_rb_tenant_group ON public.role_bindings USING btree (workspace_id, group_id) WHERE (group_id IS NOT NULL);

CREATE INDEX idx_resource_servers_resource_uri ON public.resource_servers USING btree (resource_uri);

-- Partial unique index: only active (non-soft-deleted) rows must have a unique
-- resource_uri. Replaces the unconditional UNIQUE constraint that was on the
-- CREATE TABLE, which blocked re-registration after soft-delete.
CREATE UNIQUE INDEX idx_resource_servers_resource_uri_active
    ON public.resource_servers (resource_uri)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_resource_servers_state ON public.resource_servers USING btree (state);

CREATE INDEX idx_resource_servers_tenant_id ON public.resource_servers USING btree (workspace_id);

CREATE INDEX idx_risk_policies_action ON public.risk_policies USING btree (action_pattern);

CREATE INDEX idx_risk_policies_active ON public.risk_policies USING btree (is_active);

CREATE UNIQUE INDEX idx_risk_policies_name_tenant ON public.risk_policies USING btree (workspace_id, name);

CREATE INDEX idx_risk_policies_tenant ON public.risk_policies USING btree (workspace_id);

CREATE INDEX idx_role_assignment_requests_role_id ON public.role_assignment_requests USING btree (role_id);

CREATE INDEX idx_role_assignment_requests_status ON public.role_assignment_requests USING btree (status);

CREATE INDEX idx_role_assignment_requests_tenant_id ON public.role_assignment_requests USING btree (workspace_id);

CREATE INDEX idx_role_assignment_requests_user_id ON public.role_assignment_requests USING btree (user_id);

CREATE INDEX idx_role_bindings_user_tenant ON public.role_bindings USING btree (user_id, workspace_id);

CREATE INDEX idx_role_permissions_permission_id ON public.role_permissions USING btree (permission_id);

CREATE INDEX idx_role_permissions_role_id ON public.role_permissions USING btree (role_id);

CREATE INDEX idx_roles_created_at ON public.roles USING btree (created_at);

CREATE UNIQUE INDEX idx_roles_global_id ON public.roles USING btree (id) WHERE (workspace_id IS NULL);

CREATE UNIQUE INDEX idx_roles_global_name ON public.roles USING btree (name) WHERE (workspace_id IS NULL);

CREATE INDEX idx_roles_name ON public.roles USING btree (name);

CREATE INDEX idx_roles_tenant_id ON public.roles USING btree (workspace_id);

CREATE INDEX idx_roles_tenant_name ON public.roles USING btree (workspace_id, name);

CREATE INDEX idx_roles_updated_at ON public.roles USING btree (updated_at);

CREATE INDEX idx_rs_access_policies_tenant_id ON public.resource_server_access_policies USING btree (workspace_id);

CREATE INDEX idx_rs_drift_events_rs_occurred ON public.resource_server_drift_events USING btree (rs_id, occurred_at DESC);

CREATE INDEX idx_rs_manifest_attempts_rs_at ON public.resource_server_manifest_attempts USING btree (rs_id, attempted_at DESC);

CREATE INDEX idx_rs_status ON public.resource_servers USING btree (status) WHERE ((active = true) AND (deleted_at IS NULL));

CREATE INDEX idx_rscr_client_id ON public.resource_server_client_registrations USING btree (oauth_client_id);

CREATE INDEX idx_rscr_rs_id ON public.resource_server_client_registrations USING btree (resource_server_id);

CREATE INDEX idx_saml_callback_states_expires_at ON public.saml_callback_states USING btree (expires_at);

CREATE INDEX idx_saml_callback_states_login_challenge ON public.saml_callback_states USING btree (login_challenge);

CREATE INDEX idx_saml_callback_states_tenant_id ON public.saml_callback_states USING btree (workspace_id);

CREATE INDEX idx_saml_requests_client_id ON public.saml_requests USING btree (client_id);

CREATE INDEX idx_saml_requests_expires_at ON public.saml_requests USING btree (expires_at);

CREATE INDEX idx_saml_requests_login_challenge ON public.saml_requests USING btree (login_challenge);

CREATE INDEX idx_saml_requests_tenant_id ON public.saml_requests USING btree (workspace_id);

CREATE INDEX idx_saml_sp_certificates_expires_at ON public.saml_sp_certificates USING btree (expires_at);

CREATE INDEX idx_saml_sp_certificates_tenant_id ON public.saml_sp_certificates USING btree (workspace_id);

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

CREATE INDEX idx_sync_configs_tenant_id ON public.sync_configurations USING btree (workspace_id);

CREATE INDEX idx_sync_configs_tenant_type ON public.sync_configurations USING btree (workspace_id, sync_type);

CREATE INDEX idx_tenant_backup_code ON public.workspace_totp_backup_codes USING btree (code);

CREATE INDEX idx_tenant_backup_created_at ON public.workspace_totp_backup_codes USING btree (created_at);

CREATE INDEX idx_tenant_backup_tenant ON public.workspace_totp_backup_codes USING btree (workspace_id);

CREATE INDEX idx_tenant_backup_used ON public.workspace_totp_backup_codes USING btree (is_used);

CREATE INDEX idx_tenant_backup_user ON public.workspace_totp_backup_codes USING btree (user_id);

CREATE INDEX idx_tenant_backup_user_unused ON public.workspace_totp_backup_codes USING btree (user_id, is_used);

CREATE INDEX idx_tenant_ciba_auth_req_id ON public.workspace_ciba_auth_requests USING btree (auth_req_id);

CREATE INDEX idx_tenant_ciba_created_at ON public.workspace_ciba_auth_requests USING btree (created_at);

CREATE INDEX idx_tenant_ciba_expires_at ON public.workspace_ciba_auth_requests USING btree (expires_at);

CREATE INDEX idx_tenant_ciba_status ON public.workspace_ciba_auth_requests USING btree (status);

CREATE INDEX idx_tenant_ciba_tenant ON public.workspace_ciba_auth_requests USING btree (workspace_id);

CREATE INDEX idx_tenant_ciba_user ON public.workspace_ciba_auth_requests USING btree (user_id);

CREATE INDEX idx_tenant_ciba_user_status ON public.workspace_ciba_auth_requests USING btree (user_id, status);

CREATE INDEX idx_tenant_device_token_active ON public.workspace_device_tokens USING btree (is_active);

CREATE INDEX idx_tenant_device_token_device_token ON public.workspace_device_tokens USING btree (device_token);

CREATE INDEX idx_tenant_device_token_tenant ON public.workspace_device_tokens USING btree (workspace_id);

CREATE INDEX idx_tenant_device_token_user ON public.workspace_device_tokens USING btree (user_id);

CREATE UNIQUE INDEX idx_workspace_domains_domain_unique ON public.workspace_domains USING btree (domain);

CREATE INDEX idx_workspace_domains_domain_verified ON public.workspace_domains USING btree (domain, is_verified);

CREATE UNIQUE INDEX idx_workspace_domains_primary_per_tenant ON public.workspace_domains USING btree (workspace_id) WHERE (is_primary = true);

CREATE INDEX idx_workspace_domains_status ON public.workspace_domains USING btree (is_verified, kind);

CREATE INDEX idx_workspace_domains_tenant_id_primary ON public.workspace_domains USING btree (workspace_id, is_primary);

CREATE INDEX idx_workspace_domains_tenant_id_verified ON public.workspace_domains USING btree (workspace_id, is_verified);

-- Phase C: idx_tenant_hydra_clients_* removed (tenant_hydra_clients table dropped).

-- Phase 6: idx_tenant_mappings_* removed (tenant_mappings table dropped).

CREATE INDEX idx_tenant_totp_active ON public.workspace_totp_secrets USING btree (is_active);

CREATE INDEX idx_tenant_totp_created_at ON public.workspace_totp_secrets USING btree (created_at);

CREATE INDEX idx_tenant_totp_primary ON public.workspace_totp_secrets USING btree (is_primary);

CREATE INDEX idx_tenant_totp_tenant ON public.workspace_totp_secrets USING btree (workspace_id);

CREATE INDEX idx_tenant_totp_user ON public.workspace_totp_secrets USING btree (user_id);

CREATE INDEX idx_tenant_totp_user_active ON public.workspace_totp_secrets USING btree (user_id, is_active);







CREATE INDEX idx_teus_last_seen ON public.workspace_end_user_states USING btree (workspace_id, last_seen_at DESC);

CREATE INDEX idx_teus_workspace_plan ON public.workspace_end_user_states USING btree (workspace_id, plan_tier) WHERE (plan_tier IS NOT NULL);

CREATE INDEX idx_teus_workspace_status ON public.workspace_end_user_states USING btree (workspace_id, status);

CREATE INDEX idx_tm_invited_by ON public.workspace_user_memberships USING btree (invited_by) WHERE (invited_by IS NOT NULL);

CREATE INDEX idx_tm_workspace_status ON public.workspace_user_memberships USING btree (workspace_id, status);

CREATE INDEX idx_tm_workspace_type ON public.workspace_user_memberships USING btree (workspace_id, membership_type);

CREATE INDEX idx_tm_user ON public.workspace_user_memberships USING btree (user_id);

CREATE INDEX idx_totp_active ON public.totp_secrets USING btree (is_active, is_primary);

CREATE UNIQUE INDEX idx_totp_primary_device ON public.totp_secrets USING btree (user_id, workspace_id) WHERE (is_primary = true);

CREATE INDEX idx_totp_tenant ON public.totp_secrets USING btree (workspace_id);

CREATE INDEX idx_totp_user ON public.totp_secrets USING btree (user_id);

CREATE INDEX idx_ug_tenant_group ON public.user_groups USING btree (workspace_id, group_id);

CREATE INDEX idx_ug_tenant_user ON public.user_groups USING btree (workspace_id, user_id);

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

CREATE INDEX idx_users_email_tenant ON public.users USING btree (email, workspace_id);

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

CREATE INDEX idx_users_tenant_domain ON public.users USING btree (tenant_domain);

CREATE INDEX idx_users_tenant_email ON public.users USING btree (workspace_id, email);

CREATE INDEX idx_users_tenant_id ON public.users USING btree (workspace_id);

CREATE INDEX idx_users_workspace_id_active ON public.users USING btree (workspace_id, active) WHERE (active = true);

-- Phase A: canonical multi-workspace identity constraint.
-- One user row per (workspace, email). Enforces "same email in two workspaces
-- = two distinct users" — the Slack/GitHub user model.
CREATE UNIQUE INDEX idx_users_workspace_email ON public.users (workspace_id, LOWER(email)) WHERE deleted_at IS NULL;

CREATE INDEX idx_users_tenant_project ON public.users USING btree (workspace_id, project_id);

CREATE INDEX idx_users_timestamps ON public.users USING btree (created_at, updated_at);

CREATE INDEX idx_users_updated_at ON public.users USING btree (updated_at);

CREATE INDEX idx_voice_identity_links_is_active ON public.voice_identity_links USING btree (is_active);

CREATE INDEX idx_voice_identity_links_tenant_id ON public.voice_identity_links USING btree (workspace_id);

CREATE INDEX idx_voice_identity_links_user_id ON public.voice_identity_links USING btree (user_id);

CREATE INDEX idx_voice_identity_links_voice_platform_user ON public.voice_identity_links USING btree (voice_platform, voice_user_id);

CREATE INDEX idx_voice_sessions_expires_at ON public.voice_sessions USING btree (expires_at);

CREATE INDEX idx_voice_sessions_session_token ON public.voice_sessions USING btree (session_token);

CREATE INDEX idx_voice_sessions_status ON public.voice_sessions USING btree (status);

CREATE INDEX idx_voice_sessions_tenant_id ON public.voice_sessions USING btree (workspace_id);

CREATE INDEX idx_voice_sessions_voice_user_id ON public.voice_sessions USING btree (voice_user_id);

CREATE INDEX idx_webauthn_sessions_created_at ON public.webauthn_sessions USING btree (created_at);

CREATE INDEX idx_webauthn_sessions_expires_at ON public.webauthn_sessions USING btree (expires_at);

CREATE INDEX idx_webauthn_sessions_user_id ON public.webauthn_sessions USING btree (user_id);

CREATE UNIQUE INDEX roles_name_tenant_unique ON public.roles USING btree (name, workspace_id);

CREATE TRIGGER oidc_providers_updated_at BEFORE UPDATE ON public.oidc_providers FOR EACH ROW EXECUTE FUNCTION public.update_oidc_providers_updated_at();

CREATE TRIGGER oidc_user_identities_updated_at BEFORE UPDATE ON public.oidc_user_identities FOR EACH ROW EXECUTE FUNCTION public.update_oidc_user_identities_updated_at();

CREATE TRIGGER trigger_device_codes_updated_at BEFORE UPDATE ON public.device_codes FOR EACH ROW EXECUTE FUNCTION public.update_device_codes_updated_at();

CREATE TRIGGER trigger_voice_identity_links_updated_at BEFORE UPDATE ON public.voice_identity_links FOR EACH ROW EXECUTE FUNCTION public.update_voice_identity_links_updated_at();

CREATE TRIGGER trigger_voice_sessions_updated_at BEFORE UPDATE ON public.voice_sessions FOR EACH ROW EXECUTE FUNCTION public.update_voice_sessions_updated_at();

CREATE TRIGGER update_services_updated_at BEFORE UPDATE ON public.services FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Phase C: update_tenant_hydra_clients_updated_at trigger removed (table dropped).

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE ONLY public.delegation_tokens
    ADD CONSTRAINT delegation_tokens_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.delegation_policies(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT fk_agent_action_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT fk_agent_action_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_guard_settings
    ADD CONSTRAINT fk_agent_guard_settings_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT fk_backup_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT fk_backup_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_device FOREIGN KEY (device_token_id) REFERENCES public.device_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_action_decisions
    ADD CONSTRAINT fk_decision_action FOREIGN KEY (action_request_id) REFERENCES public.agent_action_requests(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_token_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

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
    ADD CONSTRAINT fk_risk_policy_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.saml_sp_certificates
    ADD CONSTRAINT fk_saml_sp_cert_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

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

ALTER TABLE ONLY public.workspace_totp_backup_codes
    ADD CONSTRAINT fk_tenant_backup_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_totp_backup_codes
    ADD CONSTRAINT fk_tenant_backup_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_ciba_auth_requests
    ADD CONSTRAINT fk_tenant_ciba_device FOREIGN KEY (device_token_id, workspace_id) REFERENCES public.workspace_device_tokens(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_ciba_auth_requests
    ADD CONSTRAINT fk_tenant_ciba_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_ciba_auth_requests
    ADD CONSTRAINT fk_tenant_ciba_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_device_tokens
    ADD CONSTRAINT fk_tenant_device_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_device_tokens
    ADD CONSTRAINT fk_tenant_device_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_domains
    ADD CONSTRAINT fk_workspace_domains_workspace_id FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_totp_secrets
    ADD CONSTRAINT fk_tenant_totp_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_totp_secrets
    ADD CONSTRAINT fk_tenant_totp_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_end_user_states
    ADD CONSTRAINT fk_teus_suspended_by FOREIGN KEY (suspended_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.workspace_end_user_states
    ADD CONSTRAINT fk_teus_user FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_user_memberships
    ADD CONSTRAINT fk_tm_invited_by FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.workspace_user_memberships
    ADD CONSTRAINT fk_tm_user FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT fk_totp_tenant FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT fk_totp_user FOREIGN KEY (user_id, workspace_id) REFERENCES public.users(id, workspace_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_added_by FOREIGN KEY (added_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_group FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_user FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.oauth_scopes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.mcp_tools(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_is_public_acknowledged_by_fkey FOREIGN KEY (is_public_acknowledged_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.mcp_oauth_clients(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.oauth_scope_permissions
    ADD CONSTRAINT oauth_scope_permissions_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.oauth_scopes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_parent_scope_id_fkey FOREIGN KEY (parent_scope_id) REFERENCES public.oauth_scopes(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.oidc_user_identities
    ADD CONSTRAINT oidc_user_identities_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_default_role_id_fkey FOREIGN KEY (default_role_id) REFERENCES public.roles(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES public.mcp_oauth_clients(id);

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id);

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

ALTER TABLE ONLY public.resource_servers
    ADD CONSTRAINT resource_servers_setup_completed_by_fkey FOREIGN KEY (setup_completed_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_role_fk_simple FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_tenant_role_fk FOREIGN KEY (workspace_id, role_id) REFERENCES public.roles(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_tenant_user_fk FOREIGN KEY (workspace_id, user_id) REFERENCES public.users(workspace_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_user_fk_simple FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_end_user_states
    ADD CONSTRAINT workspace_end_user_states_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_user_memberships
    ADD CONSTRAINT workspace_user_memberships_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT voice_identity_links_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT voice_sessions_tenant_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;

-- ============================================================================
-- Seed data: system tenant + base permissions + role bindings
-- ============================================================================
-- IMPORTANT: pg_dump set `search_path = ''` at the top of this file (line 42)
-- so every schema object reference above is `public.<name>`. The seed blocks
-- below were authored against the default search_path and use unqualified
-- names like `INSERT INTO tenants`. Restore the public schema on the path
-- so those resolve; otherwise the bootstrap fails with
-- `ERROR: relation "tenants" does not exist`.
SET search_path TO public;

-- Migration 103: Add permissions for User Flow Service
-- Fixed to use production schema (no resources table, permissions uses workspace_id/resource/action)
-- Fixed: uses check-before-insert instead of ON CONFLICT ON CONSTRAINT (constraint may not exist yet)
-- Fixed: removed full_permission_string column (added by migration 109, not available yet)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
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
        WHERE workspace_id = sys_tenant AND resource = 'users' AND action = 'delete'
    ) THEN
        INSERT INTO permissions (id, workspace_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_tenant, 'users', 'delete', 'Delete a user', NOW());
    END IF;

    -- Ensure users:read permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE workspace_id = sys_tenant AND resource = 'users' AND action = 'read'
    ) THEN
        INSERT INTO permissions (id, workspace_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_tenant, 'users', 'read', 'Read user information', NOW());
    END IF;

    -- Ensure users:write permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE workspace_id = sys_tenant AND resource = 'users' AND action = 'write'
    ) THEN
        INSERT INTO permissions (id, workspace_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_tenant, 'users', 'write', 'Create and update users', NOW());
    END IF;

    -- Assign permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id
    FROM roles r, permissions p
    WHERE r.name = 'admin' AND r.workspace_id = sys_tenant
      AND p.workspace_id = sys_tenant
      AND p.resource = 'users'
      AND p.action IN ('delete', 'read', 'write')
    ON CONFLICT DO NOTHING;
END $$;


-- Phase 2 (tenant → workspace migration): seed the system workspace mirroring
-- the system tenant. Both rows share UUID 00000000-...000. Future phases drop
-- the tenants table; the system workspace stays as the anchor for
-- platform-level permissions/role bindings.
-- Placed AFTER the workspaces CREATE TABLE — earlier Migration 103 seeds
-- run before this table exists.
DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, created_at, updated_at)
    VALUES (sys_tenant, 'System', NULL, sys_tenant, 'team', NOW(), NOW())
    ON CONFLICT (id) DO NOTHING;
END $$;

-- Migration 200: RBAC permissions for authsec-migration service
-- Fixed to use production permissions schema (workspace_id, resource, action) instead of old (resource_id, action)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Phase 6: ensure system workspace exists (replaces legacy tenants seed).
    INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, workspace_domain, email, status, created_at, updated_at)
    VALUES (sys_tenant, 'System', NULL, sys_tenant, 'team', 'system.authsec.dev', 'system@authsec.local', 'active', NOW(), NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Create migrations permissions
    INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
    VALUES
        (gen_random_uuid(), sys_tenant, 'migrations', 'admin', 'Full admin access to migration operations', 'migrations:admin', NOW()),
        (gen_random_uuid(), sys_tenant, 'migrations', 'run', 'Execute database migrations', 'migrations:run', NOW()),
        (gen_random_uuid(), sys_tenant, 'migrations', 'view', 'View migration status and history', 'migrations:view', NOW()),
        (gen_random_uuid(), sys_tenant, 'migrations', 'create_tenant_db', 'Create new tenant databases', 'migrations:create_tenant_db', NOW())
    ON CONFLICT ON CONSTRAINT permissions_workspace_resource_action_key DO NOTHING;

    -- Assign migration admin permissions to super_admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'super_admin' AND ro.workspace_id = sys_tenant
      AND p.workspace_id = sys_tenant AND p.resource = 'migrations'
    ON CONFLICT DO NOTHING;

    -- Assign migration permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'admin' AND ro.workspace_id = sys_tenant
      AND p.workspace_id = sys_tenant AND p.resource = 'migrations'
      AND p.action IN ('admin', 'run', 'create_tenant_db')
    ON CONFLICT DO NOTHING;
END $$;
-- Migration 201: RBAC permission for template-based tenant DB creation
-- Requires JWT + admin role (not service token)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Phase 6: ensure system workspace exists (replaces legacy tenants seed).
    INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, workspace_domain, email, status, created_at, updated_at)
    VALUES (sys_tenant, 'System', NULL, sys_tenant, 'team', 'system.authsec.dev', 'system@authsec.local', 'active', NOW(), NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Create template cloning permission
    INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
    VALUES
        (gen_random_uuid(), sys_tenant, 'migrations', 'create_tenant_from_template', 'Create tenant databases by cloning golden template', 'migrations:create_tenant_from_template', NOW())
    ON CONFLICT ON CONSTRAINT permissions_workspace_resource_action_key DO NOTHING;

    -- Assign to super_admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'super_admin' AND ro.workspace_id = sys_tenant
      AND p.workspace_id = sys_tenant AND p.resource = 'migrations'
      AND p.action = 'create_tenant_from_template'
    ON CONFLICT DO NOTHING;

    -- Assign to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'admin' AND ro.workspace_id = sys_tenant
      AND p.workspace_id = sys_tenant AND p.resource = 'migrations'
      AND p.action = 'create_tenant_from_template'
    ON CONFLICT DO NOTHING;
END $$;
