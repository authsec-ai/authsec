-- ============================================================================
-- AuthSec v4 — Master DB Bootstrap (single fresh-start migration)
-- ============================================================================
-- Replaces the legacy 001–127 migration chain with one self-contained file.
-- Created from a pg_dump --schema-only of the live v4 database (May 23, 2026)
-- with the schema_migrations table stripped (we track via migration_logs).
--
-- Seed data (system tenant + base permissions + role bindings, previously in
-- migrations/permissions/master/200–202) is appended at the bottom.
--
-- This file is idempotent for first-run on a fresh database. To bring up a
-- new authsec deployment:
--   1. Provision a fresh Postgres database (no schema, no migration_logs).
--   2. Start the authsec backend — internal/migration/runner.go will pick
--      this file up, execute it, and write a single row to migration_logs.
--   3. Subsequent v4 migrations land as 002_*.sql, 003_*.sql, etc.
--
-- Legacy tables that came along for the ride (api_scopes, ciba_requests,
-- group_roles, role_scopes, saml_callback_states, saml_requests,
-- saml_sp_certificates, user_auth_preferences, clients, tenant_hydra_clients,
-- external_service_migrations, schema_migrations stripped, oauth_sessions,
-- services, monthly_usage, billing_subscriptions, processed_webhook_events,
-- workspace_migration_review) are kept for now to avoid surprise breakage
-- of code paths I haven't audited 100%. They can be dropped via a follow-up
-- 002_drop_legacy_tables.sql once the new cluster is stable.
-- ============================================================================

--
-- PostgreSQL database dump
--

-- Dumped from database version 16.1
-- Dumped by pg_dump version 16.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: backup_foreign_keys(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.backup_foreign_keys() RETURNS TABLE(constraint_name text, table_name text, column_name text, foreign_table_name text, foreign_column_name text, delete_rule text, update_rule text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        tc.constraint_name::text,
        tc.table_name::text,
        kcu.column_name::text,
        ccu.table_name::text,
        ccu.column_name::text,
        rc.delete_rule::text,
        rc.update_rule::text
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
    JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
    JOIN information_schema.referential_constraints rc ON tc.constraint_name = rc.constraint_name
    WHERE tc.constraint_type = 'FOREIGN KEY'
    AND (ccu.table_name = 'tenants' OR tc.table_name = 'tenants');
END;
$$;


--
-- Name: cleanup_expired_device_codes(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cleanup_expired_device_codes() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
    current_epoch BIGINT;
BEGIN
    current_epoch := EXTRACT(EPOCH FROM NOW())::BIGINT;

    DELETE FROM device_codes
    WHERE expires_at < (current_epoch - 86400)  -- 24 hours ago
    AND status IN ('expired', 'consumed', 'denied');

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;


--
-- Name: FUNCTION cleanup_expired_device_codes(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.cleanup_expired_device_codes() IS 'Deletes device codes older than 24 hours that are expired/consumed/denied';


--
-- Name: cleanup_expired_voice_sessions(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cleanup_expired_voice_sessions() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
    current_epoch BIGINT;
BEGIN
    current_epoch := EXTRACT(EPOCH FROM NOW())::BIGINT;

    DELETE FROM voice_sessions
    WHERE expires_at < (current_epoch - 3600)  -- 1 hour ago
    AND status IN ('expired', 'failed', 'verified');

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;


--
-- Name: FUNCTION cleanup_expired_voice_sessions(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.cleanup_expired_voice_sessions() IS 'Deletes voice sessions older than 1 hour that are expired/failed/verified';


--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


--
-- Name: update_device_codes_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_device_codes_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$;


--
-- Name: update_oidc_providers_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_oidc_providers_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


--
-- Name: update_oidc_user_identities_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_oidc_user_identities_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;


--
-- Name: update_voice_identity_links_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_voice_identity_links_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$;


--
-- Name: update_voice_sessions_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

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

--
-- Name: agent_action_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_action_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    created_at bigint NOT NULL
);


--
-- Name: TABLE agent_action_audit_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.agent_action_audit_log IS 'Immutable audit trail of all agent actions and their outcomes';


--
-- Name: agent_action_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_action_decisions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action_request_id uuid NOT NULL,
    approver_user_id uuid NOT NULL,
    approver_email character varying(255) NOT NULL,
    decision character varying(20) NOT NULL,
    reason text,
    biometric_verified boolean DEFAULT false,
    created_at bigint NOT NULL
);


--
-- Name: TABLE agent_action_decisions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.agent_action_decisions IS 'Individual approve/deny votes for multi-party approval';


--
-- Name: agent_action_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_action_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action_req_id character varying(255) NOT NULL,
    tenant_id uuid NOT NULL,
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
    last_polled_at bigint
);


--
-- Name: TABLE agent_action_requests; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.agent_action_requests IS 'Tracks human-in-the-loop approval requests from AI agents';


--
-- Name: COLUMN agent_action_requests.agent_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agent_action_requests.agent_id IS 'Caller-defined agent identifier (any framework)';


--
-- Name: COLUMN agent_action_requests.agent_framework; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agent_action_requests.agent_framework IS 'Agent framework: langchain, crewai, mcp, vercel-ai, custom';


--
-- Name: COLUMN agent_action_requests.risk_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agent_action_requests.risk_score IS 'Computed risk score 0-100 from risk engine';


--
-- Name: COLUMN agent_action_requests.risk_factors; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agent_action_requests.risk_factors IS 'JSON array of {factor, score, reason} explaining the score';


--
-- Name: COLUMN agent_action_requests.approval_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agent_action_requests.approval_type IS 'auto (low risk), single (one human), multi (2+ humans)';


--
-- Name: COLUMN agent_action_requests.device_token_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agent_action_requests.device_token_id IS 'Links to tenant_device_tokens for push notification';


--
-- Name: agent_guard_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_guard_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    updated_at bigint NOT NULL
);


--
-- Name: TABLE agent_guard_settings; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.agent_guard_settings IS 'Tenant-level defaults for risk thresholds and business hours';


--
-- Name: TABLE api_scope_permissions; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: TABLE api_scopes; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: COLUMN api_scopes.name; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id bigint NOT NULL,
    request_id text,
    tenant_id text,
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
    updated_at timestamp with time zone
);


--
-- Name: audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;


--
-- Name: auth_request_contexts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_request_contexts (
    state character varying(255) NOT NULL,
    hydra_client_id character varying(255) NOT NULL,
    resource_server_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
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
    auth_time timestamp without time zone
);


--
-- Name: ciba_auth_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ciba_auth_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    auth_req_id character varying(255) NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
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
    last_polled_at bigint
);


--
-- Name: TABLE ciba_auth_requests; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.ciba_auth_requests IS 'CIBA authentication requests (push notification based auth)';


--
-- Name: COLUMN ciba_auth_requests.auth_req_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ciba_auth_requests.auth_req_id IS 'Unique request ID returned to client for polling';


--
-- Name: COLUMN ciba_auth_requests.binding_message; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ciba_auth_requests.binding_message IS 'Message shown to user in push notification';


--
-- Name: TABLE ciba_requests; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: COLUMN ciba_requests.auth_req_id; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: COLUMN ciba_requests.binding_message; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    tenant_id text,
    project_id text,
    owner_id text,
    org_id text,
    name text NOT NULL,
    email text,
    status text DEFAULT 'Active'::text,
    tags text,
    active boolean DEFAULT true,
    last_login timestamp without time zone,
    mfa_enabled boolean DEFAULT false,
    mfa_method text,
    mfa_default_method text,
    mfa_enrolled_at timestamp without time zone,
    mfa_verified boolean DEFAULT false,
    hydra_client_id text,
    oidc_enabled boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamp without time zone,
    deleted boolean DEFAULT false
);


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

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
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: delegation_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delegation_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    role_name text NOT NULL,
    agent_type text NOT NULL,
    allowed_permissions jsonb DEFAULT '[]'::jsonb,
    max_ttl_seconds integer DEFAULT 3600 NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    client_id uuid
);


--
-- Name: delegation_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.delegation_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    CONSTRAINT chk_deleg_token_status CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'revoked'::text])))
);


--
-- Name: device_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
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
    CONSTRAINT chk_device_codes_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'authorized'::character varying, 'denied'::character varying, 'expired'::character varying, 'consumed'::character varying])::text[])))
);


--
-- Name: TABLE device_codes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.device_codes IS 'OAuth 2.0 Device Authorization Grant (RFC 8628) - stores device flow authorization requests';


--
-- Name: COLUMN device_codes.tenant_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.tenant_id IS 'Resolved from user browser session during /authorize; NULL until then';


--
-- Name: COLUMN device_codes.device_code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.device_code IS 'Long secret code for device polling (128 chars)';


--
-- Name: COLUMN device_codes.user_code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.user_code IS 'Short human-readable code shown to user (8-16 chars, e.g., WDJB-MJHT)';


--
-- Name: COLUMN device_codes.verification_uri; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.verification_uri IS 'URL where user activates device (e.g., https://authsec.dev/activate)';


--
-- Name: COLUMN device_codes.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.status IS 'Authorization state: pending (waiting), authorized (approved), denied (rejected), expired (timeout), consumed (token issued)';


--
-- Name: COLUMN device_codes.scopes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.scopes IS 'JSON array of requested OAuth scopes (e.g., ["openid", "email", "profile"])';


--
-- Name: COLUMN device_codes.expires_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.expires_at IS 'Unix epoch timestamp (seconds) when this device code expires';


--
-- Name: COLUMN device_codes.created_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.created_at IS 'Unix epoch timestamp (seconds) when created';


--
-- Name: COLUMN device_codes.updated_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.updated_at IS 'Unix epoch timestamp (seconds) when last updated';


--
-- Name: COLUMN device_codes.tenant_domain; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.tenant_domain IS 'Cached tenant domain (e.g. mycompany.authsec.ai), set at authorize time';


--
-- Name: COLUMN device_codes.access_token; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_codes.access_token IS 'JWT generated at /authorize time; returned by /token once status = authorized';


--
-- Name: device_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    device_token character varying(500) NOT NULL,
    platform character varying(20) NOT NULL,
    device_name character varying(100),
    device_model character varying(100),
    app_version character varying(20),
    os_version character varying(20),
    is_active boolean DEFAULT true NOT NULL,
    last_used bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);


--
-- Name: TABLE device_tokens; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.device_tokens IS 'FCM/APNS device tokens for push notifications';


--
-- Name: COLUMN device_tokens.device_token; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.device_tokens.device_token IS 'FCM token (Android) or APNS token (iOS)';


--
-- Name: external_service_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--



--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    tenant_id uuid
);


--
-- Name: mcp_oauth_clients; Type: TABLE; Schema: public; Owner: -
--

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
    supports_refresh_token boolean DEFAULT false
);


--
-- Name: mcp_tool_scope_map; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tool_scope_map (
    tool_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    auto_matched boolean DEFAULT true NOT NULL,
    source text DEFAULT 'admin_override'::text NOT NULL,
    CONSTRAINT mcp_tool_scope_map_source_check CHECK ((source = ANY (ARRAY['sdk_suggested'::text, 'admin_override'::text])))
);


--
-- Name: mcp_tools; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tools (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    CONSTRAINT mcp_tools_inventory_source_check CHECK ((inventory_source = ANY (ARRAY['mcp_scan'::text, 'sdk_manifest'::text, 'manual'::text])))
);


--
-- Name: mfa_methods; Type: TABLE; Schema: public; Owner: -
--

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
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: migration_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.migration_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version bigint NOT NULL,
    name character varying(255) NOT NULL,
    executed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    success boolean DEFAULT false NOT NULL,
    error_msg text,
    db_type character varying(50) NOT NULL,
    tenant_id character varying(255),
    execution_ms bigint DEFAULT 0 NOT NULL
);


--
-- Name: oauth_consent_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_consent_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    resource_server_id uuid NOT NULL,
    granted_scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oauth_scope_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_scope_permissions (
    scope_id uuid NOT NULL,
    permission_id uuid NOT NULL
);


--
-- Name: oauth_scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    resource_server_id uuid,
    scope_string text NOT NULL,
    display_name text NOT NULL,
    description text,
    icon text,
    risk_level text DEFAULT 'low'::text NOT NULL,
    parent_scope_id uuid,
    is_auto_discovered boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_scopes_risk_level_check CHECK ((risk_level = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])))
);


--
-- Name: oidc_providers; Type: TABLE; Schema: public; Owner: -
--

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
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: TABLE oidc_providers; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.oidc_providers IS 'Platform-level OIDC provider configurations (Google, GitHub, Microsoft)';


--
-- Name: COLUMN oidc_providers.provider_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.oidc_providers.provider_name IS 'Unique identifier: google, github, microsoft';


--
-- Name: COLUMN oidc_providers.client_secret_vault_path; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.oidc_providers.client_secret_vault_path IS 'HashiCorp Vault path where client_secret is stored';


--
-- Name: oidc_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_states (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    state_token character varying(255) NOT NULL,
    tenant_id uuid,
    tenant_domain character varying(255) NOT NULL,
    provider_name character varying(50) NOT NULL,
    action character varying(20) NOT NULL,
    code_verifier character varying(128),
    redirect_after character varying(500),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    request_host character varying(255)
);


--
-- Name: TABLE oidc_states; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.oidc_states IS 'Short-lived OIDC state storage for secure OAuth flow';


--
-- Name: COLUMN oidc_states.state_token; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.oidc_states.state_token IS 'Random token passed to OAuth provider and verified on callback';


--
-- Name: COLUMN oidc_states.code_verifier; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.oidc_states.code_verifier IS 'PKCE code verifier for enhanced security';


--
-- Name: COLUMN oidc_states.request_host; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.oidc_states.request_host IS 'Full domain where OIDC was initiated (e.g., auth.company.com) for callback redirect';


--
-- Name: oidc_user_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_user_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider_name character varying(50) NOT NULL,
    provider_user_id character varying(255) NOT NULL,
    email character varying(255),
    profile_data jsonb,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: TABLE oidc_user_identities; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.oidc_user_identities IS 'Links OIDC provider identities to tenant users';


--
-- Name: COLUMN oidc_user_identities.provider_user_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.oidc_user_identities.provider_user_id IS 'Unique user ID from provider (Google sub, GitHub id)';


--
-- Name: otp_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.otp_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    otp character varying(10) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    verified boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: pending_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    password_hash text NOT NULL,
    first_name character varying(100) DEFAULT ''::character varying,
    last_name character varying(100) DEFAULT ''::character varying,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    client_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    tenant_domain character varying(255) NOT NULL
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    resource text NOT NULL,
    action text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    full_permission_string text
);


--
-- Name: pkce_verifiers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pkce_verifiers (
    key character varying(512) NOT NULL,
    verifier text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    name character varying(255) NOT NULL,
    description text,
    user_id uuid,
    tenant_id uuid,
    client_id uuid,
    active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: TABLE projects; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.projects IS 'Projects table with UUID primary key for shared-models compatibility';


--
-- Name: COLUMN projects.id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.projects.id IS 'UUID primary key for shared-models compatibility';


--
-- Name: resource_server_access_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_server_access_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    resource_server_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    default_role_id uuid,
    assignment_trigger text DEFAULT 'first_successful_login'::text NOT NULL,
    assignment_source text DEFAULT 'default_policy'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: resource_server_client_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_server_client_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    resource_server_id uuid NOT NULL,
    oauth_client_id uuid NOT NULL,
    status character varying(20) DEFAULT 'approved'::character varying NOT NULL,
    registration_type character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: resource_server_drift_event_dismissals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_server_drift_event_dismissals (
    event_id uuid NOT NULL,
    admin_user_id uuid NOT NULL,
    dismissed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: resource_server_drift_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_server_drift_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rs_id uuid NOT NULL,
    event_type text NOT NULL,
    event_payload jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    occurred_by uuid,
    CONSTRAINT resource_server_drift_events_event_type_check CHECK ((event_type = ANY (ARRAY['scope_deleted'::text, 'tool_unmapped'::text, 'default_role_disabled'::text, 'secret_rotated'::text])))
);


--
-- Name: resource_server_manifest_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_server_manifest_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rs_id uuid NOT NULL,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL,
    status text NOT NULL,
    reason text,
    tool_count integer,
    manifest_version text,
    sdk_build_id text,
    CONSTRAINT resource_server_manifest_attempts_status_check CHECK ((status = ANY (ARRAY['success'::text, 'auth_failed'::text, 'invalid_payload'::text, 'empty_tool_list'::text, 'server_error'::text])))
);


--
-- Name: resource_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_servers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    CONSTRAINT resource_servers_status_check CHECK ((status = ANY (ARRAY['pending_scan'::text, 'ready'::text, 'degraded'::text])))
);


--
-- Name: risk_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.risk_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    updated_at bigint NOT NULL
);


--
-- Name: TABLE risk_policies; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.risk_policies IS 'Tenant-configurable rules for scoring AI agent actions';


--
-- Name: role_assignment_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_assignment_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_at timestamp with time zone,
    reviewed_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT role_assignment_requests_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[])))
);


--
-- Name: TABLE role_assignment_requests; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.role_assignment_requests IS 'End-user role assignment requests requiring admin approval';


--
-- Name: COLUMN role_assignment_requests.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.role_assignment_requests.status IS 'Request status: pending, approved, rejected';


--
-- Name: role_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
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
    CONSTRAINT check_principal CHECK ((((((user_id IS NOT NULL))::integer + ((group_id IS NOT NULL))::integer) + ((service_account_id IS NOT NULL))::integer) = 1))
);


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL
);


--
-- Name: role_scopes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--



--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    name character varying(100) NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    is_system boolean DEFAULT false
);


--
-- Name: saml_callback_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_callback_states (
    id text NOT NULL,
    redirect_to text NOT NULL,
    user_email character varying(255),
    user_name character varying(255),
    provider_name character varying(255),
    tenant_id uuid,
    client_id uuid,
    login_challenge text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL
);


--
-- Name: saml_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_requests (
    id character varying(255) NOT NULL,
    login_challenge character varying(255) NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    provider_name character varying(255) NOT NULL,
    relay_state text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL
);


--
-- Name: saml_sp_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_sp_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    certificate text NOT NULL,
    private_key text NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--



--
-- Name: services; Type: TABLE; Schema: public; Owner: -
--

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
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: spire_audit_logs; Type: TABLE; Schema: public; Owner: -
--

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
    "timestamp" timestamp with time zone
);


--
-- Name: spire_audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_audit_logs_id_seq OWNED BY public.spire_audit_logs.id;


--
-- Name: spire_oidc_tokens; Type: TABLE; Schema: public; Owner: -
--

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
    revoked boolean
);


--
-- Name: spire_oidc_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_oidc_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_oidc_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_oidc_tokens_id_seq OWNED BY public.spire_oidc_tokens.id;


--
-- Name: spire_policies; Type: TABLE; Schema: public; Owner: -
--

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
    active boolean
);


--
-- Name: spire_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_policies_id_seq OWNED BY public.spire_policies.id;


--
-- Name: spire_policy_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_policy_actions (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    value text
);


--
-- Name: spire_policy_actions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_policy_actions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_policy_actions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_policy_actions_id_seq OWNED BY public.spire_policy_actions.id;


--
-- Name: spire_policy_conditions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_policy_conditions (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    operator text,
    key text,
    value text,
    metadata text
);


--
-- Name: spire_policy_conditions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_policy_conditions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_policy_conditions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_policy_conditions_id_seq OWNED BY public.spire_policy_conditions.id;


--
-- Name: spire_policy_resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_policy_resources (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    value text,
    pattern text
);


--
-- Name: spire_policy_resources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_policy_resources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_policy_resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_policy_resources_id_seq OWNED BY public.spire_policy_resources.id;


--
-- Name: spire_policy_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_policy_rules (
    id bigint NOT NULL,
    policy_id bigint,
    name text,
    effect text,
    priority bigint,
    attributes text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: spire_policy_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_policy_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_policy_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_policy_rules_id_seq OWNED BY public.spire_policy_rules.id;


--
-- Name: spire_policy_subjects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_policy_subjects (
    id bigint NOT NULL,
    rule_id bigint,
    type text,
    value text,
    pattern text
);


--
-- Name: spire_policy_subjects_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_policy_subjects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_policy_subjects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_policy_subjects_id_seq OWNED BY public.spire_policy_subjects.id;


--
-- Name: spire_role_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_role_bindings (
    id bigint NOT NULL,
    subject text,
    role text,
    resource text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: spire_role_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_role_bindings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_role_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_role_bindings_id_seq OWNED BY public.spire_role_bindings.id;


--
-- Name: spire_workloads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spire_workloads (
    id bigint NOT NULL,
    spiffe_id text,
    owner text
);


--
-- Name: spire_workloads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spire_workloads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spire_workloads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spire_workloads_id_seq OWNED BY public.spire_workloads.id;


--
-- Name: sync_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sync_configurations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    project_id uuid NOT NULL,
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
    CONSTRAINT sync_configurations_sync_type_check CHECK (((sync_type)::text = ANY ((ARRAY['active_directory'::character varying, 'entra_id'::character varying])::text[])))
);


--
-- Name: TABLE sync_configurations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.sync_configurations IS 'Stores Active Directory and Entra ID sync configurations with encrypted credentials';


--
-- Name: COLUMN sync_configurations.sync_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.sync_configurations.sync_type IS 'Type of directory sync: active_directory or entra_id';


--
-- Name: COLUMN sync_configurations.ad_password; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.sync_configurations.ad_password IS 'Encrypted AD service account password';


--
-- Name: COLUMN sync_configurations.entra_client_secret; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.sync_configurations.entra_client_secret IS 'Encrypted Entra ID client secret';


--
-- Name: tenant_ciba_auth_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_ciba_auth_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    auth_req_id character varying(255) NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
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
    last_polled_at bigint
);


--
-- Name: TABLE tenant_ciba_auth_requests; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant_ciba_auth_requests IS 'Tracks CIBA push notification authentication requests for tenant users';


--
-- Name: COLUMN tenant_ciba_auth_requests.auth_req_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.auth_req_id IS 'Unique request ID for CIBA authentication flow';


--
-- Name: COLUMN tenant_ciba_auth_requests.device_token_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.device_token_id IS 'Device to send push notification to';


--
-- Name: COLUMN tenant_ciba_auth_requests.binding_message; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.binding_message IS 'Message displayed on user device during approval';


--
-- Name: COLUMN tenant_ciba_auth_requests.scopes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.scopes IS 'OAuth scopes requested by client';


--
-- Name: COLUMN tenant_ciba_auth_requests.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.status IS 'Request status: pending, approved, denied, expired, consumed';


--
-- Name: COLUMN tenant_ciba_auth_requests.biometric_verified; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.biometric_verified IS 'Whether user used biometric verification';


--
-- Name: COLUMN tenant_ciba_auth_requests.responded_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.responded_at IS 'When user approved/denied the request';


--
-- Name: COLUMN tenant_ciba_auth_requests.last_polled_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_ciba_auth_requests.last_polled_at IS 'When client last polled for token';


--
-- Name: tenant_device_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_device_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    device_token character varying(500) NOT NULL,
    platform character varying(20) NOT NULL,
    device_name character varying(100),
    device_model character varying(100),
    app_version character varying(20),
    os_version character varying(20),
    is_active boolean DEFAULT true NOT NULL,
    last_used bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);


--
-- Name: TABLE tenant_device_tokens; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant_device_tokens IS 'Stores push notification device tokens for tenant users';


--
-- Name: COLUMN tenant_device_tokens.device_token; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.device_token IS 'FCM/APNS push notification token from mobile device';


--
-- Name: COLUMN tenant_device_tokens.platform; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.platform IS 'Mobile platform: ios or android';


--
-- Name: COLUMN tenant_device_tokens.device_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.device_name IS 'User-friendly device name (e.g., "John''s iPhone")';


--
-- Name: COLUMN tenant_device_tokens.device_model; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.device_model IS 'Device model (e.g., "iPhone 14 Pro")';


--
-- Name: COLUMN tenant_device_tokens.app_version; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.app_version IS 'AuthSec Mobile app version';


--
-- Name: COLUMN tenant_device_tokens.os_version; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.os_version IS 'Operating system version';


--
-- Name: COLUMN tenant_device_tokens.last_used; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_device_tokens.last_used IS 'Unix timestamp of last authentication using this device';


--
-- Name: tenant_domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    updated_by uuid
);


--
-- Name: tenant_end_user_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_end_user_states (
    tenant_id uuid NOT NULL,
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
    CONSTRAINT chk_teus_status CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text])))
);


--
-- Name: tenant_hydra_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_hydra_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id text NOT NULL,
    tenant_id text NOT NULL,
    tenant_name text NOT NULL,
    hydra_client_id text NOT NULL,
    hydra_client_secret text NOT NULL,
    client_name text NOT NULL,
    scopes text[] DEFAULT ARRAY['openid'::text, 'profile'::text, 'email'::text] NOT NULL,
    client_type text NOT NULL,
    provider_name text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT 'system'::text NOT NULL,
    updated_by text DEFAULT 'system'::text NOT NULL,
    deleted_at timestamp with time zone,
    redirect_uris text[] DEFAULT '{}'::text[]
);


--
-- Name: TABLE tenant_hydra_clients; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant_hydra_clients IS 'Tracks Hydra client provisioning for each tenant';


--
-- Name: COLUMN tenant_hydra_clients.scopes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_hydra_clients.scopes IS 'Default Hydra scopes granted to the client';


--
-- Name: COLUMN tenant_hydra_clients.client_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_hydra_clients.client_type IS 'main or oidc_provider';


--
-- Name: tenant_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: tenant_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    CONSTRAINT chk_tm_type CHECK ((membership_type = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'contractor'::text, 'service_operator'::text, 'readonly_auditor'::text])))
);


--
-- Name: tenant_totp_backup_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_totp_backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    code character varying(64) NOT NULL,
    is_used boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    used_at bigint
);


--
-- Name: TABLE tenant_totp_backup_codes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant_totp_backup_codes IS 'Stores backup recovery codes for tenant user TOTP devices';


--
-- Name: COLUMN tenant_totp_backup_codes.code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_backup_codes.code IS 'SHA-1 hash of backup recovery code';


--
-- Name: COLUMN tenant_totp_backup_codes.is_used; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_backup_codes.is_used IS 'Whether backup code has been used';


--
-- Name: COLUMN tenant_totp_backup_codes.used_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_backup_codes.used_at IS 'When backup code was used';


--
-- Name: tenant_totp_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_totp_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    secret character varying(64) NOT NULL,
    device_name character varying(100),
    device_type character varying(50) DEFAULT 'generic'::character varying,
    last_used bigint,
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT false,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);


--
-- Name: TABLE tenant_totp_secrets; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant_totp_secrets IS 'Stores TOTP authenticator secrets for tenant users';


--
-- Name: COLUMN tenant_totp_secrets.secret; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_secrets.secret IS 'Base32 encoded TOTP secret (never exposed in API responses)';


--
-- Name: COLUMN tenant_totp_secrets.device_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_secrets.device_name IS 'User-friendly device name for TOTP authenticator';


--
-- Name: COLUMN tenant_totp_secrets.device_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_secrets.device_type IS 'Type of TOTP authenticator app';


--
-- Name: COLUMN tenant_totp_secrets.last_used; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_secrets.last_used IS 'Unix timestamp of last TOTP verification';


--
-- Name: COLUMN tenant_totp_secrets.is_primary; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant_totp_secrets.is_primary IS 'Primary device for TOTP login';


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    tenant_db character varying(255),
    email text NOT NULL,
    username character varying(255),
    password_hash text,
    provider text DEFAULT 'local'::character varying,
    provider_id character varying(255),
    avatar text,
    name character varying(255),
    source character varying(50),
    status character varying(50) DEFAULT 'active'::character varying,
    last_login timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    tenant_domain character varying(255) DEFAULT 'app.authsec.dev'::character varying NOT NULL,
    vault_mount character varying(255),
    ca_cert text
);


--
-- Name: totp_backup_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    code character varying(64) NOT NULL,
    is_used boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    used_at bigint
);


--
-- Name: TABLE totp_backup_codes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.totp_backup_codes IS 'Stores recovery codes for TOTP 2FA';


--
-- Name: COLUMN totp_backup_codes.code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.totp_backup_codes.code IS 'SHA1-hashed recovery code (never exposed in plain)';


--
-- Name: totp_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    secret character varying(64) NOT NULL,
    device_name character varying(100) NOT NULL,
    device_type character varying(50) DEFAULT 'generic'::character varying,
    last_used bigint,
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);


--
-- Name: TABLE totp_secrets; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.totp_secrets IS 'Stores TOTP authenticator devices registered by users for 2FA';


--
-- Name: COLUMN totp_secrets.secret; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.totp_secrets.secret IS 'Base32-encoded TOTP secret (never exposed in API responses)';


--
-- Name: TABLE user_auth_preferences; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: COLUMN user_auth_preferences.preferred_method; Type: COMMENT; Schema: public; Owner: -
--



--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    group_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by uuid
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid,
    tenant_id uuid,
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
    is_active boolean DEFAULT true
);


--
-- Name: COLUMN users.temporary_password; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.temporary_password IS 'Indicates if user is using a temporary password from admin invite';


--
-- Name: COLUMN users.temporary_password_expires_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.temporary_password_expires_at IS 'Timestamp when temporary password expires';


--
-- Name: COLUMN users.password_change_required; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.password_change_required IS 'Forces user to change password on next login';


--
-- Name: COLUMN users.invited_by; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.invited_by IS 'UUID of admin who invited this user';


--
-- Name: COLUMN users.invited_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.invited_at IS 'Timestamp when user was invited';


--
-- Name: COLUMN users.is_primary_admin; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.is_primary_admin IS 'Indicates if this user is the primary admin who cannot be deleted. Each tenant should have at least one primary admin.';


--
-- Name: COLUMN users.failed_login_attempts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.failed_login_attempts IS 'Number of consecutive failed login attempts';


--
-- Name: COLUMN users.account_locked_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.account_locked_at IS 'Timestamp when account was locked due to too many failed attempts';


--
-- Name: COLUMN users.password_reset_required; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.password_reset_required IS 'Flag indicating user must reset password before next login';


--
-- Name: voice_identity_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.voice_identity_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    updated_at bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint
);


--
-- Name: TABLE voice_identity_links; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.voice_identity_links IS 'Permanent links between voice assistant accounts and user accounts for passwordless auth';


--
-- Name: COLUMN voice_identity_links.voice_user_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_identity_links.voice_user_id IS 'Platform-specific user ID (e.g., Alexa user amzn1.account.xxx)';


--
-- Name: COLUMN voice_identity_links.is_active; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_identity_links.is_active IS 'Whether link is active (user can deactivate)';


--
-- Name: COLUMN voice_identity_links.last_used_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_identity_links.last_used_at IS 'Unix epoch timestamp (seconds) when last used for authentication';


--
-- Name: COLUMN voice_identity_links.linked_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_identity_links.linked_at IS 'Unix epoch timestamp (seconds) when link was created';


--
-- Name: voice_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.voice_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
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
    CONSTRAINT chk_voice_sessions_status CHECK (((status)::text = ANY ((ARRAY['initiated'::character varying, 'verified'::character varying, 'expired'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: TABLE voice_sessions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.voice_sessions IS 'Voice authentication sessions for voice assistant integration (Alexa, Google, Siri)';


--
-- Name: COLUMN voice_sessions.session_token; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_sessions.session_token IS 'Secret token identifying this voice session';


--
-- Name: COLUMN voice_sessions.voice_otp; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_sessions.voice_otp IS 'Numeric code spoken to user for verification (e.g., 8532)';


--
-- Name: COLUMN voice_sessions.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_sessions.status IS 'Session state: initiated, verified, expired, failed';


--
-- Name: COLUMN voice_sessions.linked_device_code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_sessions.linked_device_code IS 'Optional link to device authorization flow';


--
-- Name: COLUMN voice_sessions.expires_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_sessions.expires_at IS 'Unix epoch timestamp (seconds) when this session expires';


--
-- Name: COLUMN voice_sessions.created_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.voice_sessions.created_at IS 'Unix epoch timestamp (seconds) when created';


--
-- Name: webauthn_sessions; Type: TABLE; Schema: public; Owner: -
--

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
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: TABLE webauthn_sessions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.webauthn_sessions IS 'Stores WebAuthn session data for registration and authentication ceremonies';


--
-- Name: COLUMN webauthn_sessions.session_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.session_key IS 'Unique session identifier in format: operation:email:tenant_id';


--
-- Name: COLUMN webauthn_sessions.challenge; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.challenge IS 'Base64-encoded WebAuthn challenge';


--
-- Name: COLUMN webauthn_sessions.user_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.user_id IS 'Binary user identifier for the WebAuthn ceremony';


--
-- Name: COLUMN webauthn_sessions.user_verification; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.user_verification IS 'Required user verification level (required, preferred, discouraged)';


--
-- Name: COLUMN webauthn_sessions.extensions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.extensions IS 'JSON-encoded WebAuthn extensions data';


--
-- Name: COLUMN webauthn_sessions.cred_params; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.cred_params IS 'JSON-encoded credential parameters for registration';


--
-- Name: COLUMN webauthn_sessions.allowed_credential_ids; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.allowed_credential_ids IS 'JSON-encoded list of allowed credential IDs for authentication';


--
-- Name: COLUMN webauthn_sessions.expires_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.webauthn_sessions.expires_at IS 'Session expiration timestamp (typically 10 minutes from creation)';


--
-- Name: audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);


--
-- Name: spire_audit_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_audit_logs ALTER COLUMN id SET DEFAULT nextval('public.spire_audit_logs_id_seq'::regclass);


--
-- Name: spire_oidc_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_oidc_tokens ALTER COLUMN id SET DEFAULT nextval('public.spire_oidc_tokens_id_seq'::regclass);


--
-- Name: spire_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policies ALTER COLUMN id SET DEFAULT nextval('public.spire_policies_id_seq'::regclass);


--
-- Name: spire_policy_actions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_actions ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_actions_id_seq'::regclass);


--
-- Name: spire_policy_conditions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_conditions ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_conditions_id_seq'::regclass);


--
-- Name: spire_policy_resources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_resources ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_resources_id_seq'::regclass);


--
-- Name: spire_policy_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_rules ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_rules_id_seq'::regclass);


--
-- Name: spire_policy_subjects id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_subjects ALTER COLUMN id SET DEFAULT nextval('public.spire_policy_subjects_id_seq'::regclass);


--
-- Name: spire_role_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_role_bindings ALTER COLUMN id SET DEFAULT nextval('public.spire_role_bindings_id_seq'::regclass);


--
-- Name: spire_workloads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_workloads ALTER COLUMN id SET DEFAULT nextval('public.spire_workloads_id_seq'::regclass);


--
-- Name: agent_action_audit_log agent_action_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_audit_log
    ADD CONSTRAINT agent_action_audit_log_pkey PRIMARY KEY (id);


--
-- Name: agent_action_decisions agent_action_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_decisions
    ADD CONSTRAINT agent_action_decisions_pkey PRIMARY KEY (id);


--
-- Name: agent_action_requests agent_action_requests_action_req_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT agent_action_requests_action_req_id_key UNIQUE (action_req_id);


--
-- Name: agent_action_requests agent_action_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT agent_action_requests_pkey PRIMARY KEY (id);


--
-- Name: agent_guard_settings agent_guard_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_guard_settings
    ADD CONSTRAINT agent_guard_settings_pkey PRIMARY KEY (id);


--
-- Name: agent_guard_settings agent_guard_settings_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_guard_settings
    ADD CONSTRAINT agent_guard_settings_tenant_id_key UNIQUE (tenant_id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: auth_request_contexts auth_request_contexts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_request_contexts
    ADD CONSTRAINT auth_request_contexts_pkey PRIMARY KEY (state);


--
-- Name: ciba_auth_requests ciba_auth_requests_auth_req_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT ciba_auth_requests_auth_req_id_key UNIQUE (auth_req_id);


--
-- Name: ciba_auth_requests ciba_auth_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT ciba_auth_requests_pkey PRIMARY KEY (id);


--
-- Name: clients clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_client_id_key UNIQUE (client_id);


--
-- Name: clients clients_hydra_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_hydra_client_id_key UNIQUE (hydra_client_id);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);


--
-- Name: credentials credentials_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_credential_id_key UNIQUE (credential_id);


--
-- Name: credentials credentials_credential_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_credential_id_unique UNIQUE (credential_id);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


--
-- Name: delegation_policies delegation_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_policies
    ADD CONSTRAINT delegation_policies_pkey PRIMARY KEY (id);


--
-- Name: delegation_tokens delegation_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_tokens
    ADD CONSTRAINT delegation_tokens_pkey PRIMARY KEY (id);


--
-- Name: device_codes device_codes_device_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT device_codes_device_code_key UNIQUE (device_code);


--
-- Name: device_codes device_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT device_codes_pkey PRIMARY KEY (id);


--
-- Name: device_codes device_codes_user_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT device_codes_user_code_key UNIQUE (user_code);


--
-- Name: device_tokens device_tokens_device_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT device_tokens_device_token_key UNIQUE (device_token);


--
-- Name: device_tokens device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT device_tokens_pkey PRIMARY KEY (id);


--
-- Name: tenant_device_tokens fk_tenant_device_token; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT fk_tenant_device_token UNIQUE (device_token, tenant_id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: groups groups_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_tenant_id_id_key UNIQUE (tenant_id, id);


--
-- Name: mcp_oauth_clients mcp_oauth_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_oauth_clients
    ADD CONSTRAINT mcp_oauth_clients_client_id_key UNIQUE (client_id);


--
-- Name: mcp_oauth_clients mcp_oauth_clients_hydra_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_oauth_clients
    ADD CONSTRAINT mcp_oauth_clients_hydra_client_id_key UNIQUE (hydra_client_id);


--
-- Name: mcp_oauth_clients mcp_oauth_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_oauth_clients
    ADD CONSTRAINT mcp_oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: mcp_tool_scope_map mcp_tool_scope_map_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_pkey PRIMARY KEY (tool_id, scope_id);


--
-- Name: mcp_tools mcp_tools_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_pkey PRIMARY KEY (id);


--
-- Name: mcp_tools mcp_tools_resource_server_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_resource_server_id_name_key UNIQUE (resource_server_id, name);


--
-- Name: mfa_methods mfa_methods_client_id_method_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_methods
    ADD CONSTRAINT mfa_methods_client_id_method_type_key UNIQUE (client_id, method_type);


--
-- Name: mfa_methods mfa_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_methods
    ADD CONSTRAINT mfa_methods_pkey PRIMARY KEY (id);


--
-- Name: migration_logs migration_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_logs
    ADD CONSTRAINT migration_logs_pkey PRIMARY KEY (id);


--
-- Name: oauth_consent_grants oauth_consent_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_pkey PRIMARY KEY (id);


--
-- Name: oauth_consent_grants oauth_consent_grants_tenant_id_user_id_client_id_resource_s_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_tenant_id_user_id_client_id_resource_s_key UNIQUE (tenant_id, user_id, client_id, resource_server_id);


--
-- Name: oauth_scope_permissions oauth_scope_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scope_permissions
    ADD CONSTRAINT oauth_scope_permissions_pkey PRIMARY KEY (scope_id, permission_id);


--
-- Name: oauth_scopes oauth_scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_pkey PRIMARY KEY (id);


--
-- Name: oauth_scopes oauth_scopes_tenant_id_resource_server_id_scope_string_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_tenant_id_resource_server_id_scope_string_key UNIQUE (tenant_id, resource_server_id, scope_string);


--
-- Name: oidc_providers oidc_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_providers
    ADD CONSTRAINT oidc_providers_pkey PRIMARY KEY (id);


--
-- Name: oidc_providers oidc_providers_provider_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_providers
    ADD CONSTRAINT oidc_providers_provider_name_key UNIQUE (provider_name);


--
-- Name: oidc_states oidc_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_states
    ADD CONSTRAINT oidc_states_pkey PRIMARY KEY (id);


--
-- Name: oidc_states oidc_states_state_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_states
    ADD CONSTRAINT oidc_states_state_token_key UNIQUE (state_token);


--
-- Name: oidc_user_identities oidc_user_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_user_identities
    ADD CONSTRAINT oidc_user_identities_pkey PRIMARY KEY (id);


--
-- Name: oidc_user_identities oidc_user_identities_provider_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_user_identities
    ADD CONSTRAINT oidc_user_identities_provider_unique UNIQUE (provider_name, provider_user_id);


--
-- Name: oidc_user_identities oidc_user_identities_tenant_user_provider_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_user_identities
    ADD CONSTRAINT oidc_user_identities_tenant_user_provider_unique UNIQUE (tenant_id, user_id, provider_name);


--
-- Name: otp_entries otp_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.otp_entries
    ADD CONSTRAINT otp_entries_pkey PRIMARY KEY (id);


--
-- Name: pending_registrations pending_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_registrations
    ADD CONSTRAINT pending_registrations_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_tenant_resource_action_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_tenant_resource_action_key UNIQUE (tenant_id, resource, action);


--
-- Name: pkce_verifiers pkce_verifiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pkce_verifiers
    ADD CONSTRAINT pkce_verifiers_pkey PRIMARY KEY (key);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: resource_server_access_policies resource_server_access_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_pkey PRIMARY KEY (id);


--
-- Name: resource_server_access_policies resource_server_access_policies_resource_server_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_resource_server_id_key UNIQUE (resource_server_id);


--
-- Name: resource_server_client_registrations resource_server_client_regist_resource_server_id_oauth_clie_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_regist_resource_server_id_oauth_clie_key UNIQUE (resource_server_id, oauth_client_id);


--
-- Name: resource_server_client_registrations resource_server_client_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_pkey PRIMARY KEY (id);


--
-- Name: resource_server_drift_event_dismissals resource_server_drift_event_dismissals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_drift_event_dismissals
    ADD CONSTRAINT resource_server_drift_event_dismissals_pkey PRIMARY KEY (event_id, admin_user_id);


--
-- Name: resource_server_drift_events resource_server_drift_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_drift_events
    ADD CONSTRAINT resource_server_drift_events_pkey PRIMARY KEY (id);


--
-- Name: resource_server_manifest_attempts resource_server_manifest_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_manifest_attempts
    ADD CONSTRAINT resource_server_manifest_attempts_pkey PRIMARY KEY (id);


--
-- Name: resource_servers resource_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_servers
    ADD CONSTRAINT resource_servers_pkey PRIMARY KEY (id);


--
-- Name: resource_servers resource_servers_resource_uri_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_servers
    ADD CONSTRAINT resource_servers_resource_uri_key UNIQUE (resource_uri);


--
-- Name: risk_policies risk_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_policies
    ADD CONSTRAINT risk_policies_pkey PRIMARY KEY (id);


--
-- Name: role_assignment_requests role_assignment_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_pkey PRIMARY KEY (id);


--
-- Name: role_bindings role_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_pkey PRIMARY KEY (id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: roles roles_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_tenant_id_id_key UNIQUE (tenant_id, id);


--
-- Name: roles roles_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_tenant_id_name_key UNIQUE (tenant_id, name);


--
-- Name: roles roles_tenant_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_tenant_name_key UNIQUE (tenant_id, name);


--
-- Name: saml_callback_states saml_callback_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_callback_states
    ADD CONSTRAINT saml_callback_states_pkey PRIMARY KEY (id);


--
-- Name: saml_requests saml_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_requests
    ADD CONSTRAINT saml_requests_pkey PRIMARY KEY (id);


--
-- Name: saml_sp_certificates saml_sp_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_sp_certificates
    ADD CONSTRAINT saml_sp_certificates_pkey PRIMARY KEY (id);


--
-- Name: saml_sp_certificates saml_sp_certificates_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_sp_certificates
    ADD CONSTRAINT saml_sp_certificates_tenant_id_key UNIQUE (tenant_id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--



--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: spire_audit_logs spire_audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_audit_logs
    ADD CONSTRAINT spire_audit_logs_pkey PRIMARY KEY (id);


--
-- Name: spire_oidc_tokens spire_oidc_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_oidc_tokens
    ADD CONSTRAINT spire_oidc_tokens_pkey PRIMARY KEY (id);


--
-- Name: spire_policies spire_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policies
    ADD CONSTRAINT spire_policies_pkey PRIMARY KEY (id);


--
-- Name: spire_policy_actions spire_policy_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_actions
    ADD CONSTRAINT spire_policy_actions_pkey PRIMARY KEY (id);


--
-- Name: spire_policy_conditions spire_policy_conditions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_conditions
    ADD CONSTRAINT spire_policy_conditions_pkey PRIMARY KEY (id);


--
-- Name: spire_policy_resources spire_policy_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_resources
    ADD CONSTRAINT spire_policy_resources_pkey PRIMARY KEY (id);


--
-- Name: spire_policy_rules spire_policy_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_rules
    ADD CONSTRAINT spire_policy_rules_pkey PRIMARY KEY (id);


--
-- Name: spire_policy_subjects spire_policy_subjects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_subjects
    ADD CONSTRAINT spire_policy_subjects_pkey PRIMARY KEY (id);


--
-- Name: spire_role_bindings spire_role_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_role_bindings
    ADD CONSTRAINT spire_role_bindings_pkey PRIMARY KEY (id);


--
-- Name: spire_workloads spire_workloads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_workloads
    ADD CONSTRAINT spire_workloads_pkey PRIMARY KEY (id);


--
-- Name: sync_configurations sync_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_configurations
    ADD CONSTRAINT sync_configurations_pkey PRIMARY KEY (id);


--
-- Name: sync_configurations sync_configurations_tenant_id_config_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_configurations
    ADD CONSTRAINT sync_configurations_tenant_id_config_name_key UNIQUE (tenant_id, config_name);


--
-- Name: tenant_ciba_auth_requests tenant_ciba_auth_requests_auth_req_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ciba_auth_requests
    ADD CONSTRAINT tenant_ciba_auth_requests_auth_req_id_key UNIQUE (auth_req_id);


--
-- Name: tenant_ciba_auth_requests tenant_ciba_auth_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ciba_auth_requests
    ADD CONSTRAINT tenant_ciba_auth_requests_pkey PRIMARY KEY (id);


--
-- Name: tenant_device_tokens tenant_device_tokens_device_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT tenant_device_tokens_device_token_key UNIQUE (device_token);


--
-- Name: tenant_device_tokens tenant_device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT tenant_device_tokens_pkey PRIMARY KEY (id);


--
-- Name: tenant_domains tenant_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_domains
    ADD CONSTRAINT tenant_domains_pkey PRIMARY KEY (id);


--
-- Name: tenant_end_user_states tenant_end_user_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_end_user_states
    ADD CONSTRAINT tenant_end_user_states_pkey PRIMARY KEY (tenant_id, user_id);


--
-- Name: tenant_hydra_clients tenant_hydra_clients_hydra_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_hydra_clients
    ADD CONSTRAINT tenant_hydra_clients_hydra_client_id_key UNIQUE (hydra_client_id);


--
-- Name: tenant_hydra_clients tenant_hydra_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_hydra_clients
    ADD CONSTRAINT tenant_hydra_clients_pkey PRIMARY KEY (id);


--
-- Name: tenant_mappings tenant_mappings_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_mappings
    ADD CONSTRAINT tenant_mappings_client_id_key UNIQUE (client_id);


--
-- Name: tenant_mappings tenant_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_mappings
    ADD CONSTRAINT tenant_mappings_pkey PRIMARY KEY (id);


--
-- Name: tenant_memberships tenant_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_memberships
    ADD CONSTRAINT tenant_memberships_pkey PRIMARY KEY (id);


--
-- Name: tenant_memberships tenant_memberships_tenant_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_memberships
    ADD CONSTRAINT tenant_memberships_tenant_id_user_id_key UNIQUE (tenant_id, user_id);


--
-- Name: tenant_totp_backup_codes tenant_totp_backup_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_backup_codes
    ADD CONSTRAINT tenant_totp_backup_codes_code_key UNIQUE (code);


--
-- Name: tenant_totp_backup_codes tenant_totp_backup_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_backup_codes
    ADD CONSTRAINT tenant_totp_backup_codes_pkey PRIMARY KEY (id);


--
-- Name: tenant_totp_secrets tenant_totp_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_secrets
    ADD CONSTRAINT tenant_totp_secrets_pkey PRIMARY KEY (id);


--
-- Name: tenant_totp_secrets tenant_totp_secrets_user_id_tenant_id_is_primary_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_secrets
    ADD CONSTRAINT tenant_totp_secrets_user_id_tenant_id_is_primary_key UNIQUE (user_id, tenant_id, is_primary);


--
-- Name: tenants tenants_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_email_key UNIQUE (email);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: totp_backup_codes totp_backup_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT totp_backup_codes_code_key UNIQUE (code);


--
-- Name: totp_backup_codes totp_backup_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT totp_backup_codes_pkey PRIMARY KEY (id);


--
-- Name: totp_secrets totp_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT totp_secrets_pkey PRIMARY KEY (id);


--
-- Name: groups uni_groups_tenant_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT uni_groups_tenant_name UNIQUE (tenant_id, name);


--
-- Name: tenants uni_tenants_email; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT uni_tenants_email UNIQUE (email);


--
-- Name: tenants uni_tenants_tenant_domain; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT uni_tenants_tenant_domain UNIQUE (tenant_domain);


--
-- Name: tenants uni_tenants_tenant_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT uni_tenants_tenant_id UNIQUE (tenant_id);


--
-- Name: delegation_policies uq_deleg_policy_tenant_role_agent; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_policies
    ADD CONSTRAINT uq_deleg_policy_tenant_role_agent UNIQUE (tenant_id, role_name, agent_type);


--
-- Name: delegation_tokens uq_delegation_token_client; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_tokens
    ADD CONSTRAINT uq_delegation_token_client UNIQUE (tenant_id, client_id);


--
-- Name: tenant_device_tokens uq_tenant_device_id_tenant; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT uq_tenant_device_id_tenant UNIQUE (id, tenant_id);


--
-- Name: voice_identity_links uq_voice_identity_tenant_platform_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT uq_voice_identity_tenant_platform_user UNIQUE (tenant_id, voice_platform, voice_user_id);


--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (tenant_id, user_id, group_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id);


--
-- Name: voice_identity_links voice_identity_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT voice_identity_links_pkey PRIMARY KEY (id);


--
-- Name: voice_sessions voice_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT voice_sessions_pkey PRIMARY KEY (id);


--
-- Name: voice_sessions voice_sessions_session_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT voice_sessions_session_token_key UNIQUE (session_token);


--
-- Name: webauthn_sessions webauthn_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (id);


--
-- Name: webauthn_sessions webauthn_sessions_session_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_session_key_key UNIQUE (session_key);


--
-- Name: groups_name_tenant_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX groups_name_tenant_unique ON public.groups USING btree (name, tenant_id);


--
-- Name: idx_agent_action_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_agent ON public.agent_action_requests USING btree (agent_id);


--
-- Name: idx_agent_action_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_expires ON public.agent_action_requests USING btree (expires_at);


--
-- Name: idx_agent_action_req_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_req_id ON public.agent_action_requests USING btree (action_req_id);


--
-- Name: idx_agent_action_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_session ON public.agent_action_requests USING btree (session_id);


--
-- Name: idx_agent_action_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_status ON public.agent_action_requests USING btree (status);


--
-- Name: idx_agent_action_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_tenant ON public.agent_action_requests USING btree (tenant_id);


--
-- Name: idx_agent_action_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_user ON public.agent_action_requests USING btree (user_id);


--
-- Name: idx_agent_action_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_user_status ON public.agent_action_requests USING btree (user_id, status);


--
-- Name: idx_agent_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_action ON public.agent_action_audit_log USING btree (action);


--
-- Name: idx_agent_audit_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_agent ON public.agent_action_audit_log USING btree (agent_id);


--
-- Name: idx_agent_audit_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_created ON public.agent_action_audit_log USING btree (created_at);


--
-- Name: idx_agent_audit_risk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_risk ON public.agent_action_audit_log USING btree (risk_level);


--
-- Name: idx_agent_audit_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_status ON public.agent_action_audit_log USING btree (final_status);


--
-- Name: idx_agent_audit_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_tenant ON public.agent_action_audit_log USING btree (tenant_id);


--
-- Name: idx_agent_audit_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_audit_user ON public.agent_action_audit_log USING btree (user_id);


--
-- Name: idx_agent_decision_approver; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_decision_approver ON public.agent_action_decisions USING btree (approver_user_id);


--
-- Name: idx_agent_decision_request; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_decision_request ON public.agent_action_decisions USING btree (action_request_id);


--
-- Name: idx_arc_context_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_arc_context_id ON public.auth_request_contexts USING btree (context_id) WHERE (context_id IS NOT NULL);


--
-- Name: idx_arc_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_arc_expires_at ON public.auth_request_contexts USING btree (expires_at);


--
-- Name: idx_arc_hydra_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_arc_hydra_client_id ON public.auth_request_contexts USING btree (hydra_client_id);


--
-- Name: idx_arc_hydra_request_uri; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_arc_hydra_request_uri ON public.auth_request_contexts USING btree (hydra_request_uri) WHERE ((hydra_request_uri IS NOT NULL) AND ((hydra_request_uri)::text <> ''::text));


--
-- Name: idx_arc_login_challenge; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_arc_login_challenge ON public.auth_request_contexts USING btree (login_challenge) WHERE (login_challenge IS NOT NULL);


--
-- Name: idx_audit_events_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_action ON public.audit_events USING btree (action);


--
-- Name: idx_audit_events_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_request_id ON public.audit_events USING btree (request_id);


--
-- Name: idx_audit_events_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_resource ON public.audit_events USING btree (resource);


--
-- Name: idx_audit_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_tenant_id ON public.audit_events USING btree (tenant_id);


--
-- Name: idx_audit_events_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_timestamp ON public.audit_events USING btree ("timestamp");


--
-- Name: idx_audit_events_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_user_id ON public.audit_events USING btree (user_id);


--
-- Name: idx_backup_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_backup_tenant ON public.totp_backup_codes USING btree (tenant_id);


--
-- Name: idx_backup_used; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_backup_used ON public.totp_backup_codes USING btree (is_used);


--
-- Name: idx_backup_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_backup_user ON public.totp_backup_codes USING btree (user_id);


--
-- Name: idx_ciba_auth_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciba_auth_expires ON public.ciba_auth_requests USING btree (expires_at);


--
-- Name: idx_ciba_auth_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciba_auth_status ON public.ciba_auth_requests USING btree (status);


--
-- Name: idx_ciba_auth_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciba_auth_tenant ON public.ciba_auth_requests USING btree (tenant_id);


--
-- Name: idx_ciba_auth_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciba_auth_user ON public.ciba_auth_requests USING btree (user_id);


--
-- Name: idx_clients_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_deleted ON public.clients USING btree (deleted);


--
-- Name: idx_clients_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_deleted_at ON public.clients USING btree (deleted_at);


--
-- Name: idx_clients_hydra_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_hydra_client_id ON public.clients USING btree (hydra_client_id) WHERE ((hydra_client_id IS NOT NULL) AND (hydra_client_id <> ''::text));


--
-- Name: idx_clients_oidc_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_oidc_enabled ON public.clients USING btree (oidc_enabled);


--
-- Name: idx_clients_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_org_id ON public.clients USING btree (org_id);


--
-- Name: idx_clients_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_owner ON public.clients USING btree (owner_id);


--
-- Name: idx_clients_owner_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_owner_id ON public.clients USING btree (owner_id);


--
-- Name: idx_clients_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_project_id ON public.clients USING btree (project_id);


--
-- Name: idx_clients_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_status ON public.clients USING btree (status);


--
-- Name: idx_clients_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_tags ON public.clients USING btree (tags);


--
-- Name: idx_clients_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_tenant_id ON public.clients USING btree (tenant_id);


--
-- Name: idx_clients_tenant_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_tenant_org ON public.clients USING btree (tenant_id, org_id);


--
-- Name: idx_clients_tenant_org_email_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_clients_tenant_org_email_name ON public.clients USING btree (tenant_id, org_id, email, name) WHERE (deleted_at IS NULL);


--
-- Name: idx_consent_grants_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_consent_grants_tenant ON public.oauth_consent_grants USING btree (tenant_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_consent_grants_user_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_consent_grants_user_client ON public.oauth_consent_grants USING btree (user_id, client_id, resource_server_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_credentials_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_created_at ON public.credentials USING btree (created_at);


--
-- Name: idx_credentials_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_updated_at ON public.credentials USING btree (updated_at);


--
-- Name: idx_deleg_policy_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deleg_policy_client_id ON public.delegation_policies USING btree (client_id);


--
-- Name: idx_deleg_policy_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deleg_policy_lookup ON public.delegation_policies USING btree (tenant_id, role_name, agent_type, enabled);


--
-- Name: idx_deleg_policy_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deleg_policy_tenant_id ON public.delegation_policies USING btree (tenant_id);


--
-- Name: idx_deleg_token_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deleg_token_expires ON public.delegation_tokens USING btree (expires_at) WHERE (status = 'active'::text);


--
-- Name: idx_deleg_token_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deleg_token_lookup ON public.delegation_tokens USING btree (tenant_id, client_id, status);


--
-- Name: idx_deleg_token_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deleg_token_policy ON public.delegation_tokens USING btree (policy_id);


--
-- Name: idx_device_codes_device_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_device_code ON public.device_codes USING btree (device_code);


--
-- Name: idx_device_codes_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_expires_at ON public.device_codes USING btree (expires_at);


--
-- Name: idx_device_codes_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_status ON public.device_codes USING btree (status);


--
-- Name: idx_device_codes_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_tenant_id ON public.device_codes USING btree (tenant_id);


--
-- Name: idx_device_codes_user_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_user_code ON public.device_codes USING btree (user_code);


--
-- Name: idx_device_codes_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_user_id ON public.device_codes USING btree (user_id);


--
-- Name: idx_device_tokens_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_active ON public.device_tokens USING btree (is_active);


--
-- Name: idx_device_tokens_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_tenant ON public.device_tokens USING btree (tenant_id);


--
-- Name: idx_device_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_token ON public.device_tokens USING btree (device_token);


--
-- Name: idx_device_tokens_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_user ON public.device_tokens USING btree (user_id);


--
-- Name: idx_groups_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_created_at ON public.groups USING btree (created_at);


--
-- Name: idx_groups_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_name ON public.groups USING btree (name);


--
-- Name: idx_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_tenant_id ON public.groups USING btree (tenant_id);


--
-- Name: idx_groups_tenant_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_tenant_name ON public.groups USING btree (tenant_id, name);


--
-- Name: idx_groups_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_updated_at ON public.groups USING btree (updated_at);


--
-- Name: idx_mcp_oauth_clients_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_oauth_clients_client_id ON public.mcp_oauth_clients USING btree (client_id);


--
-- Name: idx_mcp_oauth_clients_hydra_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_oauth_clients_hydra_client_id ON public.mcp_oauth_clients USING btree (hydra_client_id);


--
-- Name: idx_mcp_tools_rs; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_tools_rs ON public.mcp_tools USING btree (resource_server_id);


--
-- Name: idx_mcp_tools_rs_generation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_tools_rs_generation ON public.mcp_tools USING btree (resource_server_id, last_scan_generation);


--
-- Name: idx_mcp_tools_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_tools_tenant ON public.mcp_tools USING btree (tenant_id);


--
-- Name: idx_mfa_methods_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mfa_methods_client_id ON public.mfa_methods USING btree (client_id);


--
-- Name: idx_mfa_methods_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mfa_methods_enabled ON public.mfa_methods USING btree (enabled);


--
-- Name: idx_mfa_methods_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mfa_methods_type ON public.mfa_methods USING btree (method_type);


--
-- Name: idx_mfa_methods_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mfa_methods_user_id ON public.mfa_methods USING btree (user_id);


--
-- Name: idx_migration_logs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_migration_logs_tenant_id ON public.migration_logs USING btree (tenant_id);


--
-- Name: idx_migration_logs_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_migration_logs_version ON public.migration_logs USING btree (version);


--
-- Name: idx_oauth_scope_perms_permission; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_scope_perms_permission ON public.oauth_scope_permissions USING btree (permission_id);


--
-- Name: idx_oauth_scopes_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_scopes_parent ON public.oauth_scopes USING btree (parent_scope_id);


--
-- Name: idx_oauth_scopes_rs; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_scopes_rs ON public.oauth_scopes USING btree (resource_server_id);


--
-- Name: idx_oauth_scopes_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_scopes_tenant ON public.oauth_scopes USING btree (tenant_id);


--
-- Name: idx_oauth_scopes_tenant_global_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_oauth_scopes_tenant_global_scope ON public.oauth_scopes USING btree (tenant_id, scope_string) WHERE (resource_server_id IS NULL);


--
-- Name: idx_oidc_identities_provider_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_identities_provider_user ON public.oidc_user_identities USING btree (provider_name, provider_user_id);


--
-- Name: idx_oidc_identities_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_identities_tenant ON public.oidc_user_identities USING btree (tenant_id);


--
-- Name: idx_oidc_identities_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_identities_user ON public.oidc_user_identities USING btree (tenant_id, user_id);


--
-- Name: idx_oidc_providers_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_providers_active ON public.oidc_providers USING btree (is_active);


--
-- Name: idx_oidc_states_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_states_expires ON public.oidc_states USING btree (expires_at);


--
-- Name: idx_oidc_states_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_states_token ON public.oidc_states USING btree (state_token);


--
-- Name: idx_otp_entries_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otp_entries_email ON public.otp_entries USING btree (email);


--
-- Name: idx_otp_entries_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otp_entries_expires_at ON public.otp_entries USING btree (expires_at);


--
-- Name: idx_otp_entries_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_otp_entries_verified ON public.otp_entries USING btree (verified);


--
-- Name: idx_pending_registrations_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_registrations_email ON public.pending_registrations USING btree (email);


--
-- Name: idx_pending_registrations_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_registrations_expires_at ON public.pending_registrations USING btree (expires_at);


--
-- Name: idx_pending_registrations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_registrations_tenant_id ON public.pending_registrations USING btree (tenant_id);


--
-- Name: idx_permissions_global_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_permissions_global_id ON public.permissions USING btree (id) WHERE (tenant_id IS NULL);


--
-- Name: idx_permissions_global_resource_action; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_permissions_global_resource_action ON public.permissions USING btree (resource, action) WHERE (tenant_id IS NULL);


--
-- Name: idx_permissions_tenant_resource_action_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_permissions_tenant_resource_action_unique ON public.permissions USING btree (tenant_id, resource, action);


--
-- Name: idx_pkce_verifiers_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pkce_verifiers_expires_at ON public.pkce_verifiers USING btree (expires_at);


--
-- Name: idx_projects_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_active ON public.projects USING btree (active);


--
-- Name: idx_projects_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_client_id ON public.projects USING btree (client_id);


--
-- Name: idx_projects_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_created_at ON public.projects USING btree (created_at);


--
-- Name: idx_projects_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_tenant_id ON public.projects USING btree (tenant_id);


--
-- Name: idx_projects_timestamps; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_timestamps ON public.projects USING btree (created_at, updated_at);


--
-- Name: idx_projects_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_updated_at ON public.projects USING btree (updated_at);


--
-- Name: idx_projects_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_user_id ON public.projects USING btree (user_id);


--
-- Name: idx_rb_tenant_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rb_tenant_group ON public.role_bindings USING btree (tenant_id, group_id) WHERE (group_id IS NOT NULL);


--
-- Name: idx_resource_servers_resource_uri; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resource_servers_resource_uri ON public.resource_servers USING btree (resource_uri);


--
-- Name: idx_resource_servers_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resource_servers_state ON public.resource_servers USING btree (state);


--
-- Name: idx_resource_servers_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resource_servers_tenant_id ON public.resource_servers USING btree (tenant_id);


--
-- Name: idx_risk_policies_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_policies_action ON public.risk_policies USING btree (action_pattern);


--
-- Name: idx_risk_policies_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_policies_active ON public.risk_policies USING btree (is_active);


--
-- Name: idx_risk_policies_name_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_risk_policies_name_tenant ON public.risk_policies USING btree (tenant_id, name);


--
-- Name: idx_risk_policies_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_risk_policies_tenant ON public.risk_policies USING btree (tenant_id);


--
-- Name: idx_role_assignment_requests_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_assignment_requests_role_id ON public.role_assignment_requests USING btree (role_id);


--
-- Name: idx_role_assignment_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_assignment_requests_status ON public.role_assignment_requests USING btree (status);


--
-- Name: idx_role_assignment_requests_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_assignment_requests_tenant_id ON public.role_assignment_requests USING btree (tenant_id);


--
-- Name: idx_role_assignment_requests_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_assignment_requests_user_id ON public.role_assignment_requests USING btree (user_id);


--
-- Name: idx_role_bindings_user_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_bindings_user_tenant ON public.role_bindings USING btree (user_id, tenant_id);


--
-- Name: idx_role_permissions_permission_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_permissions_permission_id ON public.role_permissions USING btree (permission_id);


--
-- Name: idx_role_permissions_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_permissions_role_id ON public.role_permissions USING btree (role_id);


--
-- Name: idx_roles_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_created_at ON public.roles USING btree (created_at);


--
-- Name: idx_roles_global_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_roles_global_id ON public.roles USING btree (id) WHERE (tenant_id IS NULL);


--
-- Name: idx_roles_global_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_roles_global_name ON public.roles USING btree (name) WHERE (tenant_id IS NULL);


--
-- Name: idx_roles_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_name ON public.roles USING btree (name);


--
-- Name: idx_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_tenant_id ON public.roles USING btree (tenant_id);


--
-- Name: idx_roles_tenant_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_tenant_name ON public.roles USING btree (tenant_id, name);


--
-- Name: idx_roles_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_updated_at ON public.roles USING btree (updated_at);


--
-- Name: idx_rs_access_policies_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rs_access_policies_tenant_id ON public.resource_server_access_policies USING btree (tenant_id);


--
-- Name: idx_rs_drift_events_rs_occurred; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rs_drift_events_rs_occurred ON public.resource_server_drift_events USING btree (rs_id, occurred_at DESC);


--
-- Name: idx_rs_manifest_attempts_rs_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rs_manifest_attempts_rs_at ON public.resource_server_manifest_attempts USING btree (rs_id, attempted_at DESC);


--
-- Name: idx_rs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rs_status ON public.resource_servers USING btree (status) WHERE ((active = true) AND (deleted_at IS NULL));


--
-- Name: idx_rscr_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rscr_client_id ON public.resource_server_client_registrations USING btree (oauth_client_id);


--
-- Name: idx_rscr_rs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rscr_rs_id ON public.resource_server_client_registrations USING btree (resource_server_id);


--
-- Name: idx_saml_callback_states_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_callback_states_expires_at ON public.saml_callback_states USING btree (expires_at);


--
-- Name: idx_saml_callback_states_login_challenge; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_callback_states_login_challenge ON public.saml_callback_states USING btree (login_challenge);


--
-- Name: idx_saml_callback_states_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_callback_states_tenant_id ON public.saml_callback_states USING btree (tenant_id);


--
-- Name: idx_saml_requests_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_requests_client_id ON public.saml_requests USING btree (client_id);


--
-- Name: idx_saml_requests_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_requests_expires_at ON public.saml_requests USING btree (expires_at);


--
-- Name: idx_saml_requests_login_challenge; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_requests_login_challenge ON public.saml_requests USING btree (login_challenge);


--
-- Name: idx_saml_requests_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_requests_tenant_id ON public.saml_requests USING btree (tenant_id);


--
-- Name: idx_saml_sp_certificates_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_sp_certificates_expires_at ON public.saml_sp_certificates USING btree (expires_at);


--
-- Name: idx_saml_sp_certificates_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_sp_certificates_tenant_id ON public.saml_sp_certificates USING btree (tenant_id);


--
-- Name: idx_services_agent_accessible; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_services_agent_accessible ON public.services USING btree (agent_accessible);


--
-- Name: idx_services_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_services_created_by ON public.services USING btree (created_by);


--
-- Name: idx_services_resource_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_services_resource_id ON public.services USING btree (resource_id);


--
-- Name: idx_services_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_services_type ON public.services USING btree (type);


--
-- Name: idx_spire_oidc_tokens_jwt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_spire_oidc_tokens_jwt_id ON public.spire_oidc_tokens USING btree (jwt_id);


--
-- Name: idx_spire_policies_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_spire_policies_name ON public.spire_policies USING btree (name);


--
-- Name: idx_spire_workloads_spiffe_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_spire_workloads_spiffe_id ON public.spire_workloads USING btree (spiffe_id);


--
-- Name: idx_sync_configs_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sync_configs_active ON public.sync_configurations USING btree (is_active);


--
-- Name: idx_sync_configs_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sync_configs_client_id ON public.sync_configurations USING btree (client_id);


--
-- Name: idx_sync_configs_sync_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sync_configs_sync_type ON public.sync_configurations USING btree (sync_type);


--
-- Name: idx_sync_configs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sync_configs_tenant_id ON public.sync_configurations USING btree (tenant_id);


--
-- Name: idx_sync_configs_tenant_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sync_configs_tenant_type ON public.sync_configurations USING btree (tenant_id, sync_type);


--
-- Name: idx_tenant_backup_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_backup_code ON public.tenant_totp_backup_codes USING btree (code);


--
-- Name: idx_tenant_backup_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_backup_created_at ON public.tenant_totp_backup_codes USING btree (created_at);


--
-- Name: idx_tenant_backup_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_backup_tenant ON public.tenant_totp_backup_codes USING btree (tenant_id);


--
-- Name: idx_tenant_backup_used; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_backup_used ON public.tenant_totp_backup_codes USING btree (is_used);


--
-- Name: idx_tenant_backup_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_backup_user ON public.tenant_totp_backup_codes USING btree (user_id);


--
-- Name: idx_tenant_backup_user_unused; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_backup_user_unused ON public.tenant_totp_backup_codes USING btree (user_id, is_used);


--
-- Name: idx_tenant_ciba_auth_req_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_auth_req_id ON public.tenant_ciba_auth_requests USING btree (auth_req_id);


--
-- Name: idx_tenant_ciba_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_created_at ON public.tenant_ciba_auth_requests USING btree (created_at);


--
-- Name: idx_tenant_ciba_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_expires_at ON public.tenant_ciba_auth_requests USING btree (expires_at);


--
-- Name: idx_tenant_ciba_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_status ON public.tenant_ciba_auth_requests USING btree (status);


--
-- Name: idx_tenant_ciba_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_tenant ON public.tenant_ciba_auth_requests USING btree (tenant_id);


--
-- Name: idx_tenant_ciba_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_user ON public.tenant_ciba_auth_requests USING btree (user_id);


--
-- Name: idx_tenant_ciba_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_ciba_user_status ON public.tenant_ciba_auth_requests USING btree (user_id, status);


--
-- Name: idx_tenant_device_token_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_device_token_active ON public.tenant_device_tokens USING btree (is_active);


--
-- Name: idx_tenant_device_token_device_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_device_token_device_token ON public.tenant_device_tokens USING btree (device_token);


--
-- Name: idx_tenant_device_token_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_device_token_tenant ON public.tenant_device_tokens USING btree (tenant_id);


--
-- Name: idx_tenant_device_token_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_device_token_user ON public.tenant_device_tokens USING btree (user_id);


--
-- Name: idx_tenant_domains_domain_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_tenant_domains_domain_unique ON public.tenant_domains USING btree (domain);


--
-- Name: idx_tenant_domains_domain_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_domain_verified ON public.tenant_domains USING btree (domain, is_verified);


--
-- Name: idx_tenant_domains_primary_per_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_tenant_domains_primary_per_tenant ON public.tenant_domains USING btree (tenant_id) WHERE (is_primary = true);


--
-- Name: idx_tenant_domains_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_status ON public.tenant_domains USING btree (is_verified, kind);


--
-- Name: idx_tenant_domains_tenant_id_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_tenant_id_primary ON public.tenant_domains USING btree (tenant_id, is_primary);


--
-- Name: idx_tenant_domains_tenant_id_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_tenant_id_verified ON public.tenant_domains USING btree (tenant_id, is_verified);


--
-- Name: idx_tenant_hydra_clients_client_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_hydra_clients_client_type ON public.tenant_hydra_clients USING btree (client_type);


--
-- Name: idx_tenant_hydra_clients_hydra_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_tenant_hydra_clients_hydra_client_id ON public.tenant_hydra_clients USING btree (hydra_client_id);


--
-- Name: idx_tenant_hydra_clients_org_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_hydra_clients_org_tenant ON public.tenant_hydra_clients USING btree (org_id, tenant_id);


--
-- Name: idx_tenant_mappings_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_mappings_client_id ON public.tenant_mappings USING btree (client_id);


--
-- Name: idx_tenant_mappings_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_mappings_tenant ON public.tenant_mappings USING btree (tenant_id);


--
-- Name: idx_tenant_mappings_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_mappings_tenant_id ON public.tenant_mappings USING btree (tenant_id);


--
-- Name: idx_tenant_totp_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_active ON public.tenant_totp_secrets USING btree (is_active);


--
-- Name: idx_tenant_totp_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_created_at ON public.tenant_totp_secrets USING btree (created_at);


--
-- Name: idx_tenant_totp_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_primary ON public.tenant_totp_secrets USING btree (is_primary);


--
-- Name: idx_tenant_totp_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_tenant ON public.tenant_totp_secrets USING btree (tenant_id);


--
-- Name: idx_tenant_totp_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_user ON public.tenant_totp_secrets USING btree (user_id);


--
-- Name: idx_tenant_totp_user_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_user_active ON public.tenant_totp_secrets USING btree (user_id, is_active);


--
-- Name: idx_tenants_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_email ON public.tenants USING btree (email);


--
-- Name: idx_tenants_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_provider ON public.tenants USING btree (provider);


--
-- Name: idx_tenants_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_status ON public.tenants USING btree (status);


--
-- Name: idx_tenants_tenant_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_tenant_domain ON public.tenants USING btree (tenant_domain);


--
-- Name: idx_tenants_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_tenant_id ON public.tenants USING btree (tenant_id);


--
-- Name: idx_tenants_vault_mount; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_vault_mount ON public.tenants USING btree (vault_mount);


--
-- Name: idx_teus_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teus_last_seen ON public.tenant_end_user_states USING btree (tenant_id, last_seen_at DESC);


--
-- Name: idx_teus_tenant_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teus_tenant_plan ON public.tenant_end_user_states USING btree (tenant_id, plan_tier) WHERE (plan_tier IS NOT NULL);


--
-- Name: idx_teus_tenant_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teus_tenant_status ON public.tenant_end_user_states USING btree (tenant_id, status);


--
-- Name: idx_tm_invited_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tm_invited_by ON public.tenant_memberships USING btree (invited_by) WHERE (invited_by IS NOT NULL);


--
-- Name: idx_tm_tenant_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tm_tenant_status ON public.tenant_memberships USING btree (tenant_id, status);


--
-- Name: idx_tm_tenant_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tm_tenant_type ON public.tenant_memberships USING btree (tenant_id, membership_type);


--
-- Name: idx_tm_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tm_user ON public.tenant_memberships USING btree (user_id);


--
-- Name: idx_totp_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_active ON public.totp_secrets USING btree (is_active, is_primary);


--
-- Name: idx_totp_primary_device; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_totp_primary_device ON public.totp_secrets USING btree (user_id, tenant_id) WHERE (is_primary = true);


--
-- Name: idx_totp_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_tenant ON public.totp_secrets USING btree (tenant_id);


--
-- Name: idx_totp_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_user ON public.totp_secrets USING btree (user_id);


--
-- Name: idx_ug_tenant_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ug_tenant_group ON public.user_groups USING btree (tenant_id, group_id);


--
-- Name: idx_ug_tenant_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ug_tenant_user ON public.user_groups USING btree (tenant_id, user_id);


--
-- Name: idx_users_account_locked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_account_locked ON public.users USING btree (account_locked_at) WHERE (account_locked_at IS NOT NULL);


--
-- Name: idx_users_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_active ON public.users USING btree (active);


--
-- Name: idx_users_client_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_client_email ON public.users USING btree (client_id, email);


--
-- Name: idx_users_client_email_lower; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_client_email_lower ON public.users USING btree (client_id, lower((email)::text));


--
-- Name: idx_users_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_client_id ON public.users USING btree (client_id);


--
-- Name: idx_users_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_created_at ON public.users USING btree (created_at);


--
-- Name: idx_users_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_created_at_desc ON public.users USING btree (created_at DESC);


--
-- Name: idx_users_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_deleted_at ON public.users USING btree (deleted_at);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_email_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email_client ON public.users USING btree (email, client_id);


--
-- Name: idx_users_email_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email_tenant ON public.users USING btree (email, tenant_id);


--
-- Name: idx_users_external_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_external_id ON public.users USING btree (external_id);


--
-- Name: idx_users_is_primary_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_is_primary_admin ON public.users USING btree (is_primary_admin) WHERE (is_primary_admin = true);


--
-- Name: idx_users_last_login; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_last_login ON public.users USING btree (last_login DESC) WHERE (last_login IS NOT NULL);


--
-- Name: idx_users_mfa; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_mfa ON public.users USING btree (mfa_enabled, mfa_verified);


--
-- Name: idx_users_mfa_method; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_mfa_method ON public.users USING gin (mfa_method);


--
-- Name: idx_users_password_change_required; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_password_change_required ON public.users USING btree (password_change_required) WHERE (password_change_required = true);


--
-- Name: idx_users_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_project_id ON public.users USING btree (project_id);


--
-- Name: idx_users_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_provider ON public.users USING btree (provider, provider_id);


--
-- Name: idx_users_provider_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_provider_data ON public.users USING gin (provider_data);


--
-- Name: idx_users_provider_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_users_provider_provider_id ON public.users USING btree (provider, provider_id) WHERE (provider_id IS NOT NULL);


--
-- Name: idx_users_provider_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_provider_status ON public.users USING btree (provider, active);


--
-- Name: idx_users_sync_info; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_sync_info ON public.users USING btree (sync_source, is_synced_user);


--
-- Name: idx_users_sync_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_sync_source ON public.users USING btree (sync_source);


--
-- Name: idx_users_temp_password_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_temp_password_expires_at ON public.users USING btree (temporary_password_expires_at) WHERE (temporary_password_expires_at IS NOT NULL);


--
-- Name: idx_users_temporary_password; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_temporary_password ON public.users USING btree (temporary_password) WHERE (temporary_password = true);


--
-- Name: idx_users_tenant_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_domain ON public.users USING btree (tenant_domain);


--
-- Name: idx_users_tenant_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_email ON public.users USING btree (tenant_id, email);


--
-- Name: idx_users_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_id ON public.users USING btree (tenant_id);


--
-- Name: idx_users_tenant_id_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_id_active ON public.users USING btree (tenant_id, active) WHERE (active = true);


--
-- Name: idx_users_tenant_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_project ON public.users USING btree (tenant_id, project_id);


--
-- Name: idx_users_timestamps; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_timestamps ON public.users USING btree (created_at, updated_at);


--
-- Name: idx_users_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_updated_at ON public.users USING btree (updated_at);


--
-- Name: idx_voice_identity_links_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_is_active ON public.voice_identity_links USING btree (is_active);


--
-- Name: idx_voice_identity_links_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_tenant_id ON public.voice_identity_links USING btree (tenant_id);


--
-- Name: idx_voice_identity_links_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_user_id ON public.voice_identity_links USING btree (user_id);


--
-- Name: idx_voice_identity_links_voice_platform_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_voice_platform_user ON public.voice_identity_links USING btree (voice_platform, voice_user_id);


--
-- Name: idx_voice_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_expires_at ON public.voice_sessions USING btree (expires_at);


--
-- Name: idx_voice_sessions_session_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_session_token ON public.voice_sessions USING btree (session_token);


--
-- Name: idx_voice_sessions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_status ON public.voice_sessions USING btree (status);


--
-- Name: idx_voice_sessions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_tenant_id ON public.voice_sessions USING btree (tenant_id);


--
-- Name: idx_voice_sessions_voice_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_voice_user_id ON public.voice_sessions USING btree (voice_user_id);


--
-- Name: idx_webauthn_sessions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_sessions_created_at ON public.webauthn_sessions USING btree (created_at);


--
-- Name: idx_webauthn_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_sessions_expires_at ON public.webauthn_sessions USING btree (expires_at);


--
-- Name: idx_webauthn_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_sessions_user_id ON public.webauthn_sessions USING btree (user_id);


--
-- Name: roles_name_tenant_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX roles_name_tenant_unique ON public.roles USING btree (name, tenant_id);


--
-- Name: oidc_providers oidc_providers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER oidc_providers_updated_at BEFORE UPDATE ON public.oidc_providers FOR EACH ROW EXECUTE FUNCTION public.update_oidc_providers_updated_at();


--
-- Name: oidc_user_identities oidc_user_identities_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER oidc_user_identities_updated_at BEFORE UPDATE ON public.oidc_user_identities FOR EACH ROW EXECUTE FUNCTION public.update_oidc_user_identities_updated_at();


--
-- Name: device_codes trigger_device_codes_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_device_codes_updated_at BEFORE UPDATE ON public.device_codes FOR EACH ROW EXECUTE FUNCTION public.update_device_codes_updated_at();


--
-- Name: voice_identity_links trigger_voice_identity_links_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_voice_identity_links_updated_at BEFORE UPDATE ON public.voice_identity_links FOR EACH ROW EXECUTE FUNCTION public.update_voice_identity_links_updated_at();


--
-- Name: voice_sessions trigger_voice_sessions_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_voice_sessions_updated_at BEFORE UPDATE ON public.voice_sessions FOR EACH ROW EXECUTE FUNCTION public.update_voice_sessions_updated_at();


--
-- Name: services update_services_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_services_updated_at BEFORE UPDATE ON public.services FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: tenant_hydra_clients update_tenant_hydra_clients_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_tenant_hydra_clients_updated_at BEFORE UPDATE ON public.tenant_hydra_clients FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: users users_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: delegation_tokens delegation_tokens_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_tokens
    ADD CONSTRAINT delegation_tokens_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.delegation_policies(id) ON DELETE SET NULL;


--
-- Name: agent_action_requests fk_agent_action_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT fk_agent_action_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: agent_action_requests fk_agent_action_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_requests
    ADD CONSTRAINT fk_agent_action_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: agent_guard_settings fk_agent_guard_settings_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_guard_settings
    ADD CONSTRAINT fk_agent_guard_settings_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: totp_backup_codes fk_backup_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT fk_backup_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: totp_backup_codes fk_backup_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_backup_codes
    ADD CONSTRAINT fk_backup_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: ciba_auth_requests fk_ciba_auth_device; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_device FOREIGN KEY (device_token_id) REFERENCES public.device_tokens(id) ON DELETE CASCADE;


--
-- Name: ciba_auth_requests fk_ciba_auth_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: ciba_auth_requests fk_ciba_auth_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ciba_auth_requests
    ADD CONSTRAINT fk_ciba_auth_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: agent_action_decisions fk_decision_action; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_decisions
    ADD CONSTRAINT fk_decision_action FOREIGN KEY (action_request_id) REFERENCES public.agent_action_requests(id) ON DELETE CASCADE;


--
-- Name: device_tokens fk_device_token_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_token_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: device_tokens fk_device_token_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_token_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: role_bindings fk_rb_creator; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_creator FOREIGN KEY (tenant_id, created_by) REFERENCES public.users(tenant_id, id) ON DELETE SET NULL;


--
-- Name: role_bindings fk_rb_group; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_group FOREIGN KEY (tenant_id, group_id) REFERENCES public.groups(tenant_id, id) ON DELETE CASCADE;


--
-- Name: role_bindings fk_rb_role; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_role FOREIGN KEY (tenant_id, role_id) REFERENCES public.roles(tenant_id, id) ON DELETE CASCADE;


--
-- Name: role_bindings fk_rb_sa; Type: FK CONSTRAINT; Schema: public; Owner: -
--



--
-- Name: role_bindings fk_rb_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT fk_rb_user FOREIGN KEY (tenant_id, user_id) REFERENCES public.users(tenant_id, id) ON DELETE CASCADE;


--
-- Name: risk_policies fk_risk_policy_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_policies
    ADD CONSTRAINT fk_risk_policy_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: saml_sp_certificates fk_saml_sp_cert_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_sp_certificates
    ADD CONSTRAINT fk_saml_sp_cert_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: spire_policy_rules fk_spire_policies_rules; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_rules
    ADD CONSTRAINT fk_spire_policies_rules FOREIGN KEY (policy_id) REFERENCES public.spire_policies(id) ON DELETE CASCADE;


--
-- Name: spire_policy_actions fk_spire_policy_rules_actions; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_actions
    ADD CONSTRAINT fk_spire_policy_rules_actions FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;


--
-- Name: spire_policy_conditions fk_spire_policy_rules_conditions; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_conditions
    ADD CONSTRAINT fk_spire_policy_rules_conditions FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;


--
-- Name: spire_policy_resources fk_spire_policy_rules_resources; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_resources
    ADD CONSTRAINT fk_spire_policy_rules_resources FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;


--
-- Name: spire_policy_subjects fk_spire_policy_rules_subjects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spire_policy_subjects
    ADD CONSTRAINT fk_spire_policy_rules_subjects FOREIGN KEY (rule_id) REFERENCES public.spire_policy_rules(id) ON DELETE CASCADE;


--
-- Name: tenant_totp_backup_codes fk_tenant_backup_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_backup_codes
    ADD CONSTRAINT fk_tenant_backup_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_totp_backup_codes fk_tenant_backup_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_backup_codes
    ADD CONSTRAINT fk_tenant_backup_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_ciba_auth_requests fk_tenant_ciba_device; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ciba_auth_requests
    ADD CONSTRAINT fk_tenant_ciba_device FOREIGN KEY (device_token_id, tenant_id) REFERENCES public.tenant_device_tokens(id, tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_ciba_auth_requests fk_tenant_ciba_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ciba_auth_requests
    ADD CONSTRAINT fk_tenant_ciba_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_ciba_auth_requests fk_tenant_ciba_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ciba_auth_requests
    ADD CONSTRAINT fk_tenant_ciba_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_device_tokens fk_tenant_device_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT fk_tenant_device_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_device_tokens fk_tenant_device_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT fk_tenant_device_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_domains fk_tenant_domains_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_domains
    ADD CONSTRAINT fk_tenant_domains_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_totp_secrets fk_tenant_totp_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_secrets
    ADD CONSTRAINT fk_tenant_totp_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_totp_secrets fk_tenant_totp_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_totp_secrets
    ADD CONSTRAINT fk_tenant_totp_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_end_user_states fk_teus_suspended_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_end_user_states
    ADD CONSTRAINT fk_teus_suspended_by FOREIGN KEY (suspended_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: tenant_end_user_states fk_teus_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_end_user_states
    ADD CONSTRAINT fk_teus_user FOREIGN KEY (tenant_id, user_id) REFERENCES public.users(tenant_id, id) ON DELETE CASCADE;


--
-- Name: tenant_memberships fk_tm_invited_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_memberships
    ADD CONSTRAINT fk_tm_invited_by FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: tenant_memberships fk_tm_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_memberships
    ADD CONSTRAINT fk_tm_user FOREIGN KEY (tenant_id, user_id) REFERENCES public.users(tenant_id, id) ON DELETE CASCADE;


--
-- Name: totp_secrets fk_totp_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT fk_totp_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: totp_secrets fk_totp_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT fk_totp_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;


--
-- Name: user_groups fk_ug_added_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_added_by FOREIGN KEY (added_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_groups fk_ug_group; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_group FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: user_groups fk_ug_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_ug_user FOREIGN KEY (tenant_id, user_id) REFERENCES public.users(tenant_id, id) ON DELETE CASCADE;


--
-- Name: mcp_tool_scope_map mcp_tool_scope_map_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.oauth_scopes(id) ON DELETE CASCADE;


--
-- Name: mcp_tool_scope_map mcp_tool_scope_map_tool_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tool_scope_map
    ADD CONSTRAINT mcp_tool_scope_map_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.mcp_tools(id) ON DELETE CASCADE;


--
-- Name: mcp_tools mcp_tools_is_public_acknowledged_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_is_public_acknowledged_by_fkey FOREIGN KEY (is_public_acknowledged_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mcp_tools mcp_tools_resource_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;


--
-- Name: mcp_tools mcp_tools_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: oauth_consent_grants oauth_consent_grants_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.mcp_oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_consent_grants oauth_consent_grants_resource_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;


--
-- Name: oauth_consent_grants oauth_consent_grants_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_consent_grants
    ADD CONSTRAINT oauth_consent_grants_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: oauth_scope_permissions oauth_scope_permissions_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scope_permissions
    ADD CONSTRAINT oauth_scope_permissions_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.oauth_scopes(id) ON DELETE CASCADE;


--
-- Name: oauth_scopes oauth_scopes_parent_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_parent_scope_id_fkey FOREIGN KEY (parent_scope_id) REFERENCES public.oauth_scopes(id) ON DELETE SET NULL;


--
-- Name: oauth_scopes oauth_scopes_resource_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;


--
-- Name: oauth_scopes oauth_scopes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_scopes
    ADD CONSTRAINT oauth_scopes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: oidc_user_identities oidc_user_identities_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_user_identities
    ADD CONSTRAINT oidc_user_identities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: resource_server_access_policies resource_server_access_policies_default_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_default_role_id_fkey FOREIGN KEY (default_role_id) REFERENCES public.roles(id) ON DELETE SET NULL;


--
-- Name: resource_server_access_policies resource_server_access_policies_resource_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_access_policies
    ADD CONSTRAINT resource_server_access_policies_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;


--
-- Name: resource_server_client_registrations resource_server_client_registrations_oauth_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_oauth_client_id_fkey FOREIGN KEY (oauth_client_id) REFERENCES public.mcp_oauth_clients(id);


--
-- Name: resource_server_client_registrations resource_server_client_registrations_resource_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_client_registrations
    ADD CONSTRAINT resource_server_client_registrations_resource_server_id_fkey FOREIGN KEY (resource_server_id) REFERENCES public.resource_servers(id);


--
-- Name: resource_server_drift_event_dismissals resource_server_drift_event_dismissals_admin_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_drift_event_dismissals
    ADD CONSTRAINT resource_server_drift_event_dismissals_admin_user_id_fkey FOREIGN KEY (admin_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: resource_server_drift_event_dismissals resource_server_drift_event_dismissals_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_drift_event_dismissals
    ADD CONSTRAINT resource_server_drift_event_dismissals_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.resource_server_drift_events(id) ON DELETE CASCADE;


--
-- Name: resource_server_drift_events resource_server_drift_events_occurred_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_drift_events
    ADD CONSTRAINT resource_server_drift_events_occurred_by_fkey FOREIGN KEY (occurred_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: resource_server_drift_events resource_server_drift_events_rs_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_drift_events
    ADD CONSTRAINT resource_server_drift_events_rs_id_fkey FOREIGN KEY (rs_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;


--
-- Name: resource_server_manifest_attempts resource_server_manifest_attempts_rs_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_server_manifest_attempts
    ADD CONSTRAINT resource_server_manifest_attempts_rs_id_fkey FOREIGN KEY (rs_id) REFERENCES public.resource_servers(id) ON DELETE CASCADE;


--
-- Name: resource_servers resource_servers_setup_completed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_servers
    ADD CONSTRAINT resource_servers_setup_completed_by_fkey FOREIGN KEY (setup_completed_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: role_assignment_requests role_assignment_requests_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES public.users(id);


--
-- Name: role_assignment_requests role_assignment_requests_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: role_assignment_requests role_assignment_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignment_requests
    ADD CONSTRAINT role_assignment_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: role_bindings role_bindings_role_fk_simple; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_role_fk_simple FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: role_bindings role_bindings_tenant_role_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_tenant_role_fk FOREIGN KEY (tenant_id, role_id) REFERENCES public.roles(tenant_id, id) ON DELETE CASCADE;


--
-- Name: role_bindings role_bindings_tenant_user_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_tenant_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES public.users(tenant_id, id) ON DELETE CASCADE;


--
-- Name: role_bindings role_bindings_user_fk_simple; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_user_fk_simple FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: tenant_end_user_states tenant_end_user_states_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_end_user_states
    ADD CONSTRAINT tenant_end_user_states_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_memberships tenant_memberships_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_memberships
    ADD CONSTRAINT tenant_memberships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: user_groups user_groups_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: voice_identity_links voice_identity_links_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT voice_identity_links_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: voice_sessions voice_sessions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT voice_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


-- ============================================================================
-- Seed data: system tenant + base permissions + role bindings
-- ============================================================================
-- Migration 103: Add permissions for User Flow Service
-- Fixed to use production schema (no resources table, permissions uses tenant_id/resource/action)
-- Fixed: uses check-before-insert instead of ON CONFLICT ON CONSTRAINT (constraint may not exist yet)
-- Fixed: removed full_permission_string column (added by migration 109, not available yet)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Ensure system tenant exists
    INSERT INTO tenants (id, tenant_id, email, tenant_domain, name, created_at)
    VALUES (sys_tenant, sys_tenant, 'system@authsec.local', 'system.authsec.dev', 'System', NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Ensure users:delete permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE tenant_id = sys_tenant AND resource = 'users' AND action = 'delete'
    ) THEN
        INSERT INTO permissions (id, tenant_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_tenant, 'users', 'delete', 'Delete a user', NOW());
    END IF;

    -- Ensure users:read permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE tenant_id = sys_tenant AND resource = 'users' AND action = 'read'
    ) THEN
        INSERT INTO permissions (id, tenant_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_tenant, 'users', 'read', 'Read user information', NOW());
    END IF;

    -- Ensure users:write permission exists
    IF NOT EXISTS (
        SELECT 1 FROM permissions
        WHERE tenant_id = sys_tenant AND resource = 'users' AND action = 'write'
    ) THEN
        INSERT INTO permissions (id, tenant_id, resource, action, description, created_at)
        VALUES (gen_random_uuid(), sys_tenant, 'users', 'write', 'Create and update users', NOW());
    END IF;

    -- Assign permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id
    FROM roles r, permissions p
    WHERE r.name = 'admin' AND r.tenant_id = sys_tenant
      AND p.tenant_id = sys_tenant
      AND p.resource = 'users'
      AND p.action IN ('delete', 'read', 'write')
    ON CONFLICT DO NOTHING;
END $$;

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
    owner_user_id uuid NOT NULL,
    workspace_type text NOT NULL DEFAULT 'personal',
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
    CONSTRAINT scim_connections_status_chk CHECK (status IN ('active', 'revoked', 'disabled'))
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
-- v4 shape: workspace-scoped via tenant_id (no client_id; per-Application
-- restriction lives in application_identity_provider_policies).
CREATE TABLE public.saml_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
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
    CONSTRAINT idx_saml_provider_unique UNIQUE (tenant_id, provider_name)
);

CREATE INDEX idx_saml_providers_tenant_id ON public.saml_providers(tenant_id);

-- oidc_providers patch — v4 makes OIDC IDPs workspace-owned. Migration 124
-- equivalent applied inline so the bootstrap exits with the v4 shape.
ALTER TABLE public.oidc_providers
    ADD COLUMN IF NOT EXISTS workspace_id uuid,
    ADD COLUMN IF NOT EXISTS display_name_override text;

ALTER TABLE public.oidc_providers
    DROP CONSTRAINT IF EXISTS oidc_providers_provider_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS oidc_providers_provider_name_workspace_uq
    ON public.oidc_providers (workspace_id, provider_name);

CREATE INDEX IF NOT EXISTS idx_oidc_providers_workspace
    ON public.oidc_providers(workspace_id);

-- Note: workspace_id is intentionally left nullable in the bootstrap so the
-- v4 backend can boot before any workspace exists. The application code
-- enforces NOT NULL semantics at insert time (oidc_providers rows are only
-- written through IdentityProviderService, which always sets workspace_id).

--
-- Name: scope_catalog_entries; Type: TABLE; Schema: public; Owner: authsec
--
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
    updated_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.scope_catalog_entries OWNER TO authsec;

ALTER TABLE ONLY public.scope_catalog_entries
    ADD CONSTRAINT scope_catalog_entries_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX idx_scope_catalog_workspace_key
    ON public.scope_catalog_entries USING btree (workspace_id, key);

CREATE INDEX idx_scope_catalog_workspace_id
    ON public.scope_catalog_entries USING btree (workspace_id);

-- Migration 200: RBAC permissions for authsec-migration service
-- Fixed to use production permissions schema (tenant_id, resource, action) instead of old (resource_id, action)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Ensure system tenant exists
    INSERT INTO tenants (id, tenant_id, email, tenant_domain, name, created_at)
    VALUES (sys_tenant, sys_tenant, 'system@authsec.local', 'system.authsec.dev', 'System', NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Create migrations permissions
    INSERT INTO permissions (id, tenant_id, resource, action, description, full_permission_string, created_at)
    VALUES
        (gen_random_uuid(), sys_tenant, 'migrations', 'admin', 'Full admin access to migration operations', 'migrations:admin', NOW()),
        (gen_random_uuid(), sys_tenant, 'migrations', 'run', 'Execute database migrations', 'migrations:run', NOW()),
        (gen_random_uuid(), sys_tenant, 'migrations', 'view', 'View migration status and history', 'migrations:view', NOW()),
        (gen_random_uuid(), sys_tenant, 'migrations', 'create_tenant_db', 'Create new tenant databases', 'migrations:create_tenant_db', NOW())
    ON CONFLICT ON CONSTRAINT permissions_tenant_resource_action_key DO NOTHING;

    -- Assign migration admin permissions to super_admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'super_admin' AND ro.tenant_id = sys_tenant
      AND p.tenant_id = sys_tenant AND p.resource = 'migrations'
    ON CONFLICT DO NOTHING;

    -- Assign migration permissions to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'admin' AND ro.tenant_id = sys_tenant
      AND p.tenant_id = sys_tenant AND p.resource = 'migrations'
      AND p.action IN ('admin', 'run', 'create_tenant_db')
    ON CONFLICT DO NOTHING;
END $$;
-- Migration 201: RBAC permission for template-based tenant DB creation
-- Requires JWT + admin role (not service token)

DO $$
DECLARE
    sys_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    -- Ensure system tenant exists
    INSERT INTO tenants (id, tenant_id, email, tenant_domain, name, created_at)
    VALUES (sys_tenant, sys_tenant, 'system@authsec.local', 'system.authsec.dev', 'System', NOW())
    ON CONFLICT (id) DO NOTHING;

    -- Create template cloning permission
    INSERT INTO permissions (id, tenant_id, resource, action, description, full_permission_string, created_at)
    VALUES
        (gen_random_uuid(), sys_tenant, 'migrations', 'create_tenant_from_template', 'Create tenant databases by cloning golden template', 'migrations:create_tenant_from_template', NOW())
    ON CONFLICT ON CONSTRAINT permissions_tenant_resource_action_key DO NOTHING;

    -- Assign to super_admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'super_admin' AND ro.tenant_id = sys_tenant
      AND p.tenant_id = sys_tenant AND p.resource = 'migrations'
      AND p.action = 'create_tenant_from_template'
    ON CONFLICT DO NOTHING;

    -- Assign to admin role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ro.id, p.id
    FROM roles ro
    CROSS JOIN permissions p
    WHERE ro.name = 'admin' AND ro.tenant_id = sys_tenant
      AND p.tenant_id = sys_tenant AND p.resource = 'migrations'
      AND p.action = 'create_tenant_from_template'
    ON CONFLICT DO NOTHING;
END $$;
