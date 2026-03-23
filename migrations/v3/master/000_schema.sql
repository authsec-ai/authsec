--
-- PostgreSQL database dump
--

-- Dumped from database version 16.13
-- Dumped by pg_dump version 16.13

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET search_path = public;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

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
-- Name: update_saml_providers_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_saml_providers_updated_at() RETURNS trigger
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

SET default_tablespace = '';

SET default_table_access_method = heap;

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
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action character varying(50) NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id character varying(255),
    details jsonb,
    created_at timestamp without time zone DEFAULT now(),
    tenant_id uuid,
    event_type character varying(50),
    workload_id character varying(255),
    certificate_id character varying(255),
    spiffe_id character varying(500),
    success boolean,
    error_message text,
    metadata jsonb,
    ip_address character varying(100),
    user_agent text
);

--
-- Name: backup_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid,
    code text NOT NULL,
    is_used boolean DEFAULT false,
    created_at bigint NOT NULL,
    used_at bigint
);

--
-- Name: client_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_groups (
    client_id uuid NOT NULL,
    group_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: client_resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_resources (
    client_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: client_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_roles (
    client_id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    email text,
    status text DEFAULT 'Active'::text,
    tags text[],
    active boolean DEFAULT true,
    deleted boolean DEFAULT false,
    last_login timestamp with time zone,
    mfa_enabled boolean DEFAULT false NOT NULL,
    mfa_method text[],
    mfa_default_method text,
    mfa_enrolled_at timestamp with time zone,
    mfa_verified boolean DEFAULT false,
    hydra_client_id text,
    oidc_enabled boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    description text
);

--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    backup_eligible boolean DEFAULT false,
    backup_state boolean DEFAULT false,
    transports text[],
    rp_id character varying(255),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    aaguid uuid
);

--
-- Name: external_service_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.external_service_migrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    migration_name character varying(255) NOT NULL,
    service_name character varying(255),
    status character varying(50) DEFAULT 'pending'::character varying,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: fluent_bit_export_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fluent_bit_export_configs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL,
    host text NOT NULL,
    alias text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: grant_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.grant_audit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    actor_user_id uuid,
    action text,
    target_type text,
    target_id uuid,
    before jsonb,
    after jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: group_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_roles (
    group_id uuid NOT NULL,
    role_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    tenant_id uuid,
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    name text NOT NULL,
    description text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);

--
-- Name: migration_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.migration_logs (
    id uuid NOT NULL,
    version integer NOT NULL,
    name text NOT NULL,
    success boolean NOT NULL,
    error_msg text,
    db_type character varying(20) NOT NULL,
    tenant_id uuid,
    execution_ms integer,
    executed_at timestamp with time zone DEFAULT now()
);

--
-- Name: oauth_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_sessions (
    session_id character varying(36) NOT NULL,
    user_email character varying(255),
    user_info jsonb,
    access_token text,
    refresh_token text,
    authorization_code text,
    token_expires_at bigint,
    created_at bigint NOT NULL,
    last_activity bigint NOT NULL,
    oauth_state character varying(255),
    pkce_verifier text,
    pkce_challenge text,
    is_active boolean DEFAULT true,
    client_identifier character varying(255),
    org_id character varying(255),
    tenant_id character varying(255),
    user_id character varying(255),
    provider character varying(100),
    provider_id character varying(255),
    accessible_tools jsonb
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
-- Name: oidc_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_states (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    state_token character varying(255) NOT NULL,
    tenant_id uuid,
    tenant_domain character varying(255) NOT NULL,
    provider_name character varying(50) NOT NULL,
    action character varying(20) NOT NULL,
    code_verifier character varying(255),
    redirect_after character varying(500),
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    request_host character varying(255)
);

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
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_login_at timestamp with time zone
);

--
-- Name: otp_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.otp_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text,
    otp text,
    expires_at timestamp with time zone,
    verified boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);

--
-- Name: pending_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_registrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text,
    password_hash text,
    first_name text DEFAULT ''::text,
    last_name text DEFAULT ''::text,
    tenant_id uuid,
    project_id uuid,
    client_id uuid,
    expires_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    tenant_domain text
);

--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    resource text NOT NULL,
    action text NOT NULL,
    description text,
    full_permission_string text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    user_id uuid,
    tenant_id uuid,
    client_id uuid,
    active boolean DEFAULT true,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

--
-- Name: resource_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_methods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    resource_id uuid NOT NULL,
    method character varying(10) NOT NULL,
    path_pattern character varying(255) NOT NULL,
    requires_admin boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resources (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    name character varying(100) NOT NULL,
    description text,
    type character varying(255) DEFAULT 'generic'::character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone
);

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
-- Name: role_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    service_account_id uuid,
    role_id uuid NOT NULL,
    scope_type text DEFAULT '*'::text,
    scope_id uuid,
    conditions jsonb DEFAULT '{}'::jsonb,
    expires_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    role_name text,
    username text,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT check_principal CHECK ((((user_id IS NOT NULL) AND (service_account_id IS NULL)) OR ((user_id IS NULL) AND (service_account_id IS NOT NULL))))
);

--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL
);

--
-- Name: role_scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    is_system boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
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
    tenant_id text,
    login_challenge text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone NOT NULL
);

--
-- Name: saml_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    provider_name character varying(255) NOT NULL,
    display_name character varying(255) NOT NULL,
    entity_id character varying(500) NOT NULL,
    sso_url character varying(500) NOT NULL,
    slo_url character varying(500),
    certificate text NOT NULL,
    metadata_url character varying(500),
    name_id_format character varying(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'::character varying,
    attribute_mapping jsonb,
    is_active boolean DEFAULT true,
    sort_order integer DEFAULT 0,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version integer NOT NULL,
    name text NOT NULL,
    applied_at timestamp with time zone DEFAULT now()
);

--
-- Name: scope_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scope_permissions (
    scope_id uuid NOT NULL,
    permission_id uuid NOT NULL
);

--
-- Name: scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    usage text DEFAULT 'internal'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT scopes_usage_check CHECK ((usage = ANY (ARRAY['internal'::text, 'oauth'::text, 'both'::text])))
);

--
-- Name: service_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    name text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.services (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    type text,
    url text,
    description text,
    tags text[],
    resource_id uuid NOT NULL,
    auth_type text NOT NULL,
    auth_config text,
    vault_path text,
    created_by text NOT NULL,
    agent_accessible boolean DEFAULT true,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
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
-- Name: tenant_databases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_databases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    database_name character varying(255) NOT NULL,
    migration_status character varying(50) DEFAULT 'pending'::character varying,
    last_migration integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

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
    verification_token character varying(255) NOT NULL,
    verification_method character varying(32) DEFAULT 'dns_txt'::character varying NOT NULL,
    verification_txt_name character varying(255),
    verification_txt_value character varying(255),
    verified_at timestamp with time zone,
    last_checked_at timestamp with time zone,
    failure_reason text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
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
    redirect_uris jsonb DEFAULT '[]'::jsonb NOT NULL,
    scopes text[] DEFAULT ARRAY['openid'::text, 'profile'::text, 'email'::text] NOT NULL,
    client_type text NOT NULL,
    provider_name text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_by text DEFAULT 'system'::text NOT NULL,
    updated_by text DEFAULT 'system'::text NOT NULL,
    deleted_at timestamp with time zone
);

--
-- Name: tenant_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);

--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    tenant_db text,
    email text NOT NULL,
    username text,
    password_hash text,
    provider text DEFAULT 'local'::text,
    provider_id text,
    avatar text,
    name text,
    source text,
    status text,
    last_login timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    tenant_domain text NOT NULL,
    vault_mount character varying(255),
    ca_cert text,
    migration_status character varying(50) DEFAULT 'pending'::character varying,
    last_migration integer
);

--
-- Name: totp_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid,
    secret text NOT NULL,
    device_name text,
    device_type text DEFAULT 'generic'::text,
    last_used bigint,
    is_active boolean DEFAULT true,
    is_primary boolean DEFAULT false,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);

--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    tenant_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: user_resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_resources (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    resource_id uuid DEFAULT gen_random_uuid() NOT NULL
);

--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_roles (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    name text,
    username text,
    email text NOT NULL,
    password_hash text,
    tenant_domain text NOT NULL,
    provider text NOT NULL,
    provider_id text,
    provider_data jsonb DEFAULT '{}'::jsonb,
    avatar_url text,
    active boolean DEFAULT true,
    mfa_enabled boolean DEFAULT false NOT NULL,
    mfa_method text[],
    mfa_default_method text,
    mfa_enrolled_at timestamp with time zone,
    mfa_verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    last_login timestamp with time zone,
    external_id text,
    sync_source text,
    last_sync_at timestamp with time zone,
    is_synced_user boolean DEFAULT false,
    deleted_at timestamp with time zone,
    role_name character varying(255),
    temporary_password boolean DEFAULT false,
    password_change_required boolean DEFAULT false,
    invited_by uuid,
    invited_at timestamp with time zone,
    temporary_password_expires_at timestamp with time zone,
    is_primary_admin boolean DEFAULT false,
    is_voice_enrolled boolean DEFAULT false,
    voice_enrolled boolean DEFAULT false,
    voice_enrollment_date timestamp without time zone,
    voice_last_verified timestamp without time zone,
    failed_login_attempts integer DEFAULT 0,
    account_locked_at timestamp with time zone,
    password_reset_required boolean DEFAULT false
);

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
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    cred_params bytea,
    allowed_credential_ids bytea
);

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
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);

--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

--
-- Name: backup_codes backup_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_code_key UNIQUE (code);

--
-- Name: backup_codes backup_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (id);

--
-- Name: client_groups client_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_groups
    ADD CONSTRAINT client_groups_pkey PRIMARY KEY (client_id, group_id);

--
-- Name: client_resources client_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_resources
    ADD CONSTRAINT client_resources_pkey PRIMARY KEY (client_id, resource_id);

--
-- Name: client_roles client_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_roles
    ADD CONSTRAINT client_roles_pkey PRIMARY KEY (client_id, role_id);

--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);

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
-- Name: external_service_migrations external_service_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_service_migrations
    ADD CONSTRAINT external_service_migrations_pkey PRIMARY KEY (id);

--
-- Name: external_service_migrations external_service_migrations_tenant_id_migration_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_service_migrations
    ADD CONSTRAINT external_service_migrations_tenant_id_migration_name_key UNIQUE (tenant_id, migration_name);

--
-- Name: fluent_bit_export_configs fluent_bit_export_configs_alias_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fluent_bit_export_configs
    ADD CONSTRAINT fluent_bit_export_configs_alias_key UNIQUE (alias);

--
-- Name: fluent_bit_export_configs fluent_bit_export_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fluent_bit_export_configs
    ADD CONSTRAINT fluent_bit_export_configs_pkey PRIMARY KEY (id);

--
-- Name: grant_audit grant_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.grant_audit
    ADD CONSTRAINT grant_audit_pkey PRIMARY KEY (id);

--
-- Name: group_roles group_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_roles
    ADD CONSTRAINT group_roles_pkey PRIMARY KEY (group_id, role_id);

--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);

--
-- Name: migration_logs migration_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_logs
    ADD CONSTRAINT migration_logs_pkey PRIMARY KEY (id);

--
-- Name: oauth_sessions oauth_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_sessions
    ADD CONSTRAINT oauth_sessions_pkey PRIMARY KEY (session_id);

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
-- Name: permissions permissions_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_tenant_id_id_key UNIQUE (tenant_id, id);

--
-- Name: permissions permissions_tenant_resource_action_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_tenant_resource_action_key UNIQUE (tenant_id, resource, action);

--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);

--
-- Name: resource_methods resource_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_methods
    ADD CONSTRAINT resource_methods_pkey PRIMARY KEY (id);

--
-- Name: resource_methods resource_methods_resource_id_method_path_pattern_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_methods
    ADD CONSTRAINT resource_methods_resource_id_method_path_pattern_key UNIQUE (resource_id, method, path_pattern);

--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);

--
-- Name: resources resources_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_tenant_id_name_key UNIQUE (tenant_id, name);

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
-- Name: role_scopes role_scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_scopes
    ADD CONSTRAINT role_scopes_pkey PRIMARY KEY (id);

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
-- Name: saml_providers saml_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_providers
    ADD CONSTRAINT saml_providers_pkey PRIMARY KEY (id);

--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);

--
-- Name: scope_permissions scope_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scope_permissions
    ADD CONSTRAINT scope_permissions_pkey PRIMARY KEY (scope_id, permission_id);

--
-- Name: scopes scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_pkey PRIMARY KEY (id);

--
-- Name: scopes scopes_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_tenant_id_id_key UNIQUE (tenant_id, id);

--
-- Name: scopes scopes_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_tenant_id_name_key UNIQUE (tenant_id, name);

--
-- Name: service_accounts service_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);

--
-- Name: service_accounts service_accounts_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_tenant_id_id_key UNIQUE (tenant_id, id);

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
-- Name: tenant_databases tenant_databases_database_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_databases
    ADD CONSTRAINT tenant_databases_database_name_key UNIQUE (database_name);

--
-- Name: tenant_databases tenant_databases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_databases
    ADD CONSTRAINT tenant_databases_pkey PRIMARY KEY (id);

--
-- Name: tenant_databases tenant_databases_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_databases
    ADD CONSTRAINT tenant_databases_tenant_id_key UNIQUE (tenant_id);

--
-- Name: tenant_domains tenant_domains_domain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_domains
    ADD CONSTRAINT tenant_domains_domain_key UNIQUE (domain);

--
-- Name: tenant_domains tenant_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_domains
    ADD CONSTRAINT tenant_domains_pkey PRIMARY KEY (id);

--
-- Name: tenant_domains tenant_domains_tenant_id_domain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_domains
    ADD CONSTRAINT tenant_domains_tenant_id_domain_key UNIQUE (tenant_id, domain);

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
-- Name: tenant_mappings tenant_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_mappings
    ADD CONSTRAINT tenant_mappings_pkey PRIMARY KEY (id);

--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

--
-- Name: tenants tenants_tenant_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_tenant_id_unique UNIQUE (tenant_id);

--
-- Name: totp_secrets totp_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT totp_secrets_pkey PRIMARY KEY (id);

--
-- Name: totp_secrets totp_secrets_user_tenant_device_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT totp_secrets_user_tenant_device_key UNIQUE (user_id, tenant_id, device_name);

--
-- Name: clients uni_clients_hydra_client_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT uni_clients_hydra_client_id UNIQUE (hydra_client_id);

--
-- Name: groups uni_groups_tenant_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT uni_groups_tenant_name UNIQUE (tenant_id, name);

--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (user_id, group_id);

--
-- Name: user_resources user_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_resources
    ADD CONSTRAINT user_resources_pkey PRIMARY KEY (user_id, resource_id);

--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);

--
-- Name: user_roles user_roles_user_role_tenant_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_role_tenant_key UNIQUE (user_id, role_id, tenant_id);

--
-- Name: users users_email_client_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_client_unique UNIQUE (email, client_id);

--
-- Name: users users_email_tenant_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_tenant_unique UNIQUE (email, tenant_id);

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
-- Name: idx_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_action ON public.audit_logs USING btree (action);

--
-- Name: idx_audit_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_created_at ON public.audit_logs USING btree (created_at);

--
-- Name: idx_audit_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_event_type ON public.audit_logs USING btree (event_type);

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
-- Name: idx_audit_success; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_success ON public.audit_logs USING btree (success);

--
-- Name: idx_audit_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_tenant_id ON public.audit_logs USING btree (tenant_id);

--
-- Name: idx_audit_workload_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_workload_id ON public.audit_logs USING btree (workload_id);

--
-- Name: idx_backup_codes_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_backup_codes_tenant_id ON public.backup_codes USING btree (tenant_id);

--
-- Name: idx_backup_codes_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_backup_codes_user_id ON public.backup_codes USING btree (user_id);

--
-- Name: idx_client_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_client_roles_tenant_id ON public.client_roles USING btree (tenant_id);

--
-- Name: idx_clients_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_clients_client_id ON public.clients USING btree (client_id);

--
-- Name: idx_clients_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_deleted_at ON public.clients USING btree (deleted_at);

--
-- Name: idx_clients_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_status ON public.clients USING btree (status);

--
-- Name: idx_credentials_credential_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_credentials_credential_id ON public.credentials USING btree (credential_id);

--
-- Name: idx_credentials_rp_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_rp_id ON public.credentials USING btree (rp_id);

--
-- Name: idx_credentials_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_user_id ON public.credentials USING btree (user_id);

--
-- Name: idx_fb_export_configs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fb_export_configs_tenant_id ON public.fluent_bit_export_configs USING btree (tenant_id);

--
-- Name: idx_groups_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_groups_name ON public.groups USING btree (name);

--
-- Name: idx_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_tenant_id ON public.groups USING btree (tenant_id);

--
-- Name: idx_migration_logs_db_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_migration_logs_db_type ON public.migration_logs USING btree (db_type);

--
-- Name: idx_migration_logs_success; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_migration_logs_success ON public.migration_logs USING btree (success);

--
-- Name: idx_migration_logs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_migration_logs_tenant_id ON public.migration_logs USING btree (tenant_id);

--
-- Name: idx_migration_logs_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_migration_logs_version ON public.migration_logs USING btree (version);

--
-- Name: idx_oauth_sessions_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_client ON public.oauth_sessions USING btree (client_identifier) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_org_id ON public.oauth_sessions USING btree (org_id) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_state ON public.oauth_sessions USING btree (oauth_state) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_tenant ON public.oauth_sessions USING btree (tenant_id) WHERE (is_active = true);

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
-- Name: idx_resources_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resources_name ON public.resources USING btree (name);

--
-- Name: idx_resources_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resources_tenant_id ON public.resources USING btree (tenant_id);

--
-- Name: idx_role_scopes_role_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_role_scopes_role_scope ON public.role_scopes USING btree (role_id, scope_id);

--
-- Name: idx_role_scopes_scope_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_scopes_scope_id ON public.role_scopes USING btree (scope_id);

--
-- Name: idx_roles_global_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_roles_global_id ON public.roles USING btree (id) WHERE (tenant_id IS NULL);

--
-- Name: idx_roles_global_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_roles_global_name ON public.roles USING btree (name) WHERE (tenant_id IS NULL);

--
-- Name: idx_saml_callback_states_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_callback_states_expires_at ON public.saml_callback_states USING btree (expires_at);

--
-- Name: idx_saml_callback_states_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_callback_states_id ON public.saml_callback_states USING btree (id);

--
-- Name: idx_saml_provider_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_saml_provider_unique ON public.saml_providers USING btree (tenant_id, client_id, provider_name);

--
-- Name: idx_saml_providers_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_providers_client_id ON public.saml_providers USING btree (client_id);

--
-- Name: idx_saml_providers_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_providers_is_active ON public.saml_providers USING btree (is_active);

--
-- Name: idx_saml_providers_sort_order; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_providers_sort_order ON public.saml_providers USING btree (sort_order);

--
-- Name: idx_saml_providers_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_providers_tenant_id ON public.saml_providers USING btree (tenant_id);

--
-- Name: idx_scopes_global_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_scopes_global_id ON public.scopes USING btree (id) WHERE (tenant_id IS NULL);

--
-- Name: idx_service_accounts_global_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_service_accounts_global_id ON public.service_accounts USING btree (id) WHERE (tenant_id IS NULL);

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
-- Name: idx_spire_audit_logs_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_audit_logs_request_id ON public.spire_audit_logs USING btree (request_id);

--
-- Name: idx_spire_audit_logs_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_audit_logs_timestamp ON public.spire_audit_logs USING btree ("timestamp");

--
-- Name: idx_spire_oidc_tokens_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_oidc_tokens_expires_at ON public.spire_oidc_tokens USING btree (expires_at);

--
-- Name: idx_spire_oidc_tokens_jwt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_spire_oidc_tokens_jwt_id ON public.spire_oidc_tokens USING btree (jwt_id);

--
-- Name: idx_spire_oidc_tokens_revoked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_oidc_tokens_revoked ON public.spire_oidc_tokens USING btree (revoked);

--
-- Name: idx_spire_policies_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_spire_policies_name ON public.spire_policies USING btree (name);

--
-- Name: idx_spire_policy_actions_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_policy_actions_rule_id ON public.spire_policy_actions USING btree (rule_id);

--
-- Name: idx_spire_policy_conditions_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_policy_conditions_rule_id ON public.spire_policy_conditions USING btree (rule_id);

--
-- Name: idx_spire_policy_resources_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_policy_resources_rule_id ON public.spire_policy_resources USING btree (rule_id);

--
-- Name: idx_spire_policy_rules_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_policy_rules_policy_id ON public.spire_policy_rules USING btree (policy_id);

--
-- Name: idx_spire_policy_subjects_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_policy_subjects_rule_id ON public.spire_policy_subjects USING btree (rule_id);

--
-- Name: idx_spire_role_bindings_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_role_bindings_role ON public.spire_role_bindings USING btree (role);

--
-- Name: idx_spire_role_bindings_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spire_role_bindings_subject ON public.spire_role_bindings USING btree (subject);

--
-- Name: idx_spire_workloads_spiffe_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_spire_workloads_spiffe_id ON public.spire_workloads USING btree (spiffe_id);

--
-- Name: idx_tenant_databases_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_databases_status ON public.tenant_databases USING btree (migration_status);

--
-- Name: idx_tenant_databases_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_databases_tenant_id ON public.tenant_databases USING btree (tenant_id);

--
-- Name: idx_tenant_domains_is_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_is_primary ON public.tenant_domains USING btree (is_primary);

--
-- Name: idx_tenant_domains_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_tenant_id ON public.tenant_domains USING btree (tenant_id);

--
-- Name: idx_tenant_hydra_clients_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_hydra_clients_deleted_at ON public.tenant_hydra_clients USING btree (deleted_at);

--
-- Name: idx_tenant_hydra_clients_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_hydra_clients_org_id ON public.tenant_hydra_clients USING btree (org_id);

--
-- Name: idx_tenant_hydra_clients_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_hydra_clients_tenant_id ON public.tenant_hydra_clients USING btree (tenant_id);

--
-- Name: idx_tenant_mappings_client_id_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_tenant_mappings_client_id_unique ON public.tenant_mappings USING btree (client_id);

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
-- Name: idx_tenants_vault_mount; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_vault_mount ON public.tenants USING btree (vault_mount);

--
-- Name: idx_totp_secrets_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_secrets_tenant_id ON public.totp_secrets USING btree (tenant_id);

--
-- Name: idx_totp_secrets_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_secrets_user_id ON public.totp_secrets USING btree (user_id);

--
-- Name: idx_user_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_groups_tenant_id ON public.user_groups USING btree (tenant_id);

--
-- Name: idx_user_groups_user_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_groups_user_tenant ON public.user_groups USING btree (user_id, tenant_id);

--
-- Name: idx_user_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_roles_tenant_id ON public.user_roles USING btree (tenant_id);

--
-- Name: idx_user_roles_user_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_roles_user_tenant ON public.user_roles USING btree (user_id, tenant_id);

--
-- Name: idx_users_account_locked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_account_locked ON public.users USING btree (account_locked_at) WHERE (account_locked_at IS NOT NULL);

--
-- Name: idx_users_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_active ON public.users USING btree (active);

--
-- Name: idx_users_client_email_lower; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_client_email_lower ON public.users USING btree (client_id, lower(email));

--
-- Name: idx_users_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_client_id ON public.users USING btree (client_id);

--
-- Name: idx_users_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_deleted_at ON public.users USING btree (deleted_at);

--
-- Name: idx_users_email_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email_client ON public.users USING btree (email, client_id);

--
-- Name: idx_users_external_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_external_id ON public.users USING btree (external_id);

--
-- Name: idx_users_is_primary_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_is_primary_admin ON public.users USING btree (is_primary_admin) WHERE (is_primary_admin = true);

--
-- Name: idx_users_mfa; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_mfa ON public.users USING btree (mfa_enabled, mfa_verified);

--
-- Name: idx_users_password_change_required; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_password_change_required ON public.users USING btree (password_change_required) WHERE (password_change_required = true);

--
-- Name: idx_users_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_project_id ON public.users USING btree (project_id);

--
-- Name: idx_users_provider_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_provider_status ON public.users USING btree (provider, active);

--
-- Name: idx_users_sync_info; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_sync_info ON public.users USING btree (sync_source, is_synced_user);

--
-- Name: idx_users_temporary_password; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_temporary_password ON public.users USING btree (temporary_password) WHERE (temporary_password = true);

--
-- Name: idx_users_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_id ON public.users USING btree (tenant_id);

--
-- Name: idx_users_tenant_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_project ON public.users USING btree (tenant_id, project_id);

--
-- Name: idx_users_timestamps; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_timestamps ON public.users USING btree (created_at, updated_at);

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
-- Name: oidc_user_identities_provider_name_provider_user_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX oidc_user_identities_provider_name_provider_user_id_key ON public.oidc_user_identities USING btree (provider_name, provider_user_id);

--
-- Name: oidc_user_identities_tenant_id_user_id_provider_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX oidc_user_identities_tenant_id_user_id_provider_name_key ON public.oidc_user_identities USING btree (tenant_id, user_id, provider_name);

--
-- Name: saml_providers saml_providers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER saml_providers_updated_at BEFORE UPDATE ON public.saml_providers FOR EACH ROW EXECUTE FUNCTION public.update_saml_providers_updated_at();

--
-- Name: group_roles update_group_roles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_group_roles_updated_at BEFORE UPDATE ON public.group_roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: services update_services_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_services_updated_at BEFORE UPDATE ON public.services FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: user_groups update_user_groups_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_user_groups_updated_at BEFORE UPDATE ON public.user_groups FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: user_roles update_user_roles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_user_roles_updated_at BEFORE UPDATE ON public.user_roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: backup_codes backup_codes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: backup_codes backup_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: credentials credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: client_roles fk_client_roles_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_roles
    ADD CONSTRAINT fk_client_roles_client FOREIGN KEY (client_id) REFERENCES public.clients(id);

--
-- Name: projects fk_projects_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_projects_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

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
-- Name: user_groups fk_user_groups_group; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_user_groups_group FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

--
-- Name: user_groups fk_user_groups_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_user_groups_user FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: user_resources fk_user_resources_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_resources
    ADD CONSTRAINT fk_user_resources_user FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: permissions permissions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: resource_methods resource_methods_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_methods
    ADD CONSTRAINT resource_methods_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.resources(id) ON DELETE CASCADE;

--
-- Name: role_bindings role_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);

--
-- Name: role_bindings role_bindings_role_fk_simple; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_role_fk_simple FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

--
-- Name: role_bindings role_bindings_role_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_role_fkey FOREIGN KEY (tenant_id, role_id) REFERENCES public.roles(tenant_id, id);

--
-- Name: role_bindings role_bindings_sa_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_sa_fkey FOREIGN KEY (tenant_id, service_account_id) REFERENCES public.service_accounts(tenant_id, id);

--
-- Name: role_bindings role_bindings_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: role_bindings role_bindings_tenant_id_service_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_tenant_id_service_account_id_fkey FOREIGN KEY (tenant_id, service_account_id) REFERENCES public.service_accounts(tenant_id, id);

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
-- Name: role_bindings role_bindings_user_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_user_fkey FOREIGN KEY (tenant_id, user_id) REFERENCES public.users(tenant_id, id);

--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;

--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

--
-- Name: role_scopes role_scopes_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_scopes
    ADD CONSTRAINT role_scopes_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

--
-- Name: role_scopes role_scopes_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_scopes
    ADD CONSTRAINT role_scopes_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.scopes(id) ON DELETE CASCADE;

--
-- Name: roles roles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: scope_permissions scope_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scope_permissions
    ADD CONSTRAINT scope_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;

--
-- Name: scope_permissions scope_permissions_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scope_permissions
    ADD CONSTRAINT scope_permissions_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.scopes(id) ON DELETE CASCADE;

--
-- Name: scopes scopes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: service_accounts service_accounts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: tenant_domains tenant_domains_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_domains
    ADD CONSTRAINT tenant_domains_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: totp_secrets totp_secrets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT totp_secrets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: totp_secrets totp_secrets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_secrets
    ADD CONSTRAINT totp_secrets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- PostgreSQL database dump complete
--


-- Name: role_scopes role_scopes_role_id_scope_id_key; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.role_scopes
    ADD CONSTRAINT role_scopes_role_id_scope_id_key UNIQUE (role_id, scope_id);


-- Name: idx_scopes_usage; Type: INDEX; Schema: public; Owner: -

CREATE INDEX idx_scopes_usage ON public.scopes USING btree (usage);
