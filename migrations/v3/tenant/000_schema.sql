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
    NEW.updated_at = NOW();
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
    client_id uuid NOT NULL,
    role_id uuid NOT NULL,
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
    project_id uuid,
    owner_id uuid NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    description text,
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
    client_type text,
    agent_type text,
    spiffe_id text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text,
    aaguid uuid,
    sign_count bigint DEFAULT 0 NOT NULL,
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
    allowed_permissions jsonb DEFAULT '[]'::jsonb NOT NULL,
    max_ttl_seconds integer DEFAULT 3600 NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    client_id uuid,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
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
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: device_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid,
    device_code character varying(128) NOT NULL,
    user_code character varying(16) NOT NULL,
    verification_uri text NOT NULL,
    verification_uri_complete text,
    user_id uuid,
    user_email text,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb,
    device_info jsonb DEFAULT '{}'::jsonb,
    expires_at bigint NOT NULL,
    last_polled_at bigint,
    authorized_at bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);

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
-- Name: external_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.external_services (
    id text NOT NULL,
    tenant_id uuid,
    name text NOT NULL,
    service_type text,
    auth_type text NOT NULL,
    url text,
    credentials text,
    metadata text,
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
    tenant_id uuid,
    created_at timestamp with time zone DEFAULT now(),
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
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
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
    expires_at timestamp with time zone,
    created_at bigint NOT NULL,
    last_activity bigint NOT NULL,
    oauth_state character varying(255),
    pkce_verifier text,
    pkce_challenge text,
    is_active boolean DEFAULT true NOT NULL,
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
    request_host character varying(255),
    provider_name character varying(50) NOT NULL,
    action character varying(20) NOT NULL,
    code_verifier character varying(255),
    redirect_after character varying(500),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
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
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
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
    role_id uuid,
    scope_id uuid,
    resource_id uuid,
    resource_method_id uuid,
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
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
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
    reason text,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    reviewed_at timestamp with time zone,
    reviewed_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
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
    username text,
    role_name text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT role_bindings_one_principal CHECK ((((user_id IS NOT NULL) AND (service_account_id IS NULL)) OR ((user_id IS NULL) AND (service_account_id IS NOT NULL))))
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
    tenant_id uuid,
    client_id uuid,
    login_challenge text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone NOT NULL
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
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
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
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone NOT NULL
);

--
-- Name: saml_sp_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_sp_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    certificate text NOT NULL,
    private_key text NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone
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
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.services (
    id text NOT NULL,
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
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
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
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
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
-- Name: totp_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    secret character varying(64) NOT NULL,
    device_name character varying(100),
    device_type character varying(50) DEFAULT 'generic'::character varying,
    last_used bigint,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);

--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups (
    user_id uuid NOT NULL,
    group_id uuid NOT NULL,
    tenant_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_roles (
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
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
    provider text DEFAULT 'local'::text NOT NULL,
    provider_id text,
    provider_data jsonb DEFAULT '{}'::jsonb,
    avatar_url text,
    active boolean DEFAULT true,
    mfa_enabled boolean DEFAULT false NOT NULL,
    mfa_method text[],
    mfa_default_method text,
    mfa_enrolled_at timestamp with time zone,
    mfa_verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
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
-- Name: COLUMN users.is_primary_admin; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.is_primary_admin IS 'Indicates if this user is the primary user who cannot be deleted. Each tenant should have at least one primary user.';

--
-- Name: voice_active_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.voice_active_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid,
    user_id uuid NOT NULL,
    user_email text NOT NULL,
    session_id character varying(128) NOT NULL,
    voice_platform character varying(50),
    voice_user_id text,
    device_info jsonb DEFAULT '{}'::jsonb,
    device_name text,
    access_token_hash character varying(64),
    refresh_token_hash character varying(64),
    login_at bigint NOT NULL,
    last_activity_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    revoked_at bigint,
    revoked_reason character varying(100),
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);

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
    is_active boolean DEFAULT true NOT NULL,
    link_method character varying(50),
    last_used_at bigint,
    linked_at bigint NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
);

--
-- Name: voice_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.voice_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid,
    session_token character varying(128) NOT NULL,
    voice_otp character varying(10) NOT NULL,
    otp_attempts integer DEFAULT 0 NOT NULL,
    voice_platform character varying(50),
    voice_user_id text,
    device_info jsonb DEFAULT '{}'::jsonb,
    user_id uuid,
    user_email text,
    status character varying(20) DEFAULT 'initiated'::character varying NOT NULL,
    linked_device_code character varying(128),
    scopes jsonb DEFAULT '[]'::jsonb,
    expires_at bigint NOT NULL,
    verified_at bigint,
    pending_approval boolean DEFAULT false NOT NULL,
    approval_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    approved_at bigint,
    approved_by uuid,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL
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
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);

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
-- Name: clients clients_tenant_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_tenant_id_id_key UNIQUE (tenant_id, id);

--
-- Name: credentials credentials_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_credential_id_key UNIQUE (credential_id);

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
-- Name: device_codes device_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT device_codes_pkey PRIMARY KEY (id);

--
-- Name: device_tokens device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT device_tokens_pkey PRIMARY KEY (id);

--
-- Name: external_services external_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_services
    ADD CONSTRAINT external_services_pkey PRIMARY KEY (id);

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
-- Name: icp_tenant_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.icp_tenant_migrations (
    version integer NOT NULL,
    name text NOT NULL,
    applied_at timestamp with time zone DEFAULT now()
);

-- Name: icp_tenant_migrations icp_tenant_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.icp_tenant_migrations
    ADD CONSTRAINT icp_tenant_migrations_pkey PRIMARY KEY (version);

--
-- Name: groups groups_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_tenant_id_name_key UNIQUE (tenant_id, name);

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
-- Name: permissions permissions_tenant_id_resource_action_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_tenant_id_resource_action_key UNIQUE (tenant_id, resource, action);

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
-- Name: role_scopes role_scopes_role_id_scope_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_scopes
    ADD CONSTRAINT role_scopes_role_id_scope_id_key UNIQUE (role_id, scope_id);

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
-- Name: saml_providers saml_providers_tenant_id_client_id_provider_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_providers
    ADD CONSTRAINT saml_providers_tenant_id_client_id_provider_name_key UNIQUE (tenant_id, client_id, provider_name);

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
-- Name: tenant_device_tokens tenant_device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_device_tokens
    ADD CONSTRAINT tenant_device_tokens_pkey PRIMARY KEY (id);

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
-- Name: delegation_policies uq_delegation_policy_tenant_role_agent; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_policies
    ADD CONSTRAINT uq_delegation_policy_tenant_role_agent UNIQUE (tenant_id, role_name, agent_type);

--
-- Name: delegation_tokens uq_delegation_token_tenant_client; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.delegation_tokens
    ADD CONSTRAINT uq_delegation_token_tenant_client UNIQUE (tenant_id, client_id);

--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (user_id, group_id);

--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);

--
-- Name: users users_email_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_tenant_id_key UNIQUE (email, tenant_id);

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
-- Name: voice_active_sessions voice_active_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_active_sessions
    ADD CONSTRAINT voice_active_sessions_pkey PRIMARY KEY (id);

--
-- Name: voice_active_sessions voice_active_sessions_session_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_active_sessions
    ADD CONSTRAINT voice_active_sessions_session_id_key UNIQUE (session_id);

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
-- Name: idx_ciba_auth_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciba_auth_expires_at ON public.ciba_auth_requests USING btree (expires_at);

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
-- Name: idx_ciba_auth_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ciba_auth_user_status ON public.ciba_auth_requests USING btree (user_id, status);

--
-- Name: idx_client_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_client_roles_tenant_id ON public.client_roles USING btree (tenant_id);

--
-- Name: idx_clients_tenant_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_tenant_active ON public.clients USING btree (tenant_id, active);

--
-- Name: idx_clients_tenant_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_tenant_client ON public.clients USING btree (tenant_id, client_id);

--
-- Name: idx_credentials_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_client_id ON public.credentials USING btree (client_id);

--
-- Name: idx_credentials_rp_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_rp_id ON public.credentials USING btree (rp_id);

--
-- Name: idx_credentials_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_user_id ON public.credentials USING btree (user_id);

--
-- Name: idx_delegation_policies_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_delegation_policies_enabled ON public.delegation_policies USING btree (tenant_id, enabled);

--
-- Name: idx_delegation_policies_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_delegation_policies_tenant_id ON public.delegation_policies USING btree (tenant_id);

--
-- Name: idx_delegation_tokens_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_delegation_tokens_client_id ON public.delegation_tokens USING btree (tenant_id, client_id);

--
-- Name: idx_delegation_tokens_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_delegation_tokens_status ON public.delegation_tokens USING btree (tenant_id, status);

--
-- Name: idx_delegation_tokens_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_delegation_tokens_tenant_id ON public.delegation_tokens USING btree (tenant_id);

--
-- Name: idx_device_codes_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_client ON public.device_codes USING btree (client_id);

--
-- Name: idx_device_codes_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_expires_at ON public.device_codes USING btree (expires_at);

--
-- Name: idx_device_codes_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_status ON public.device_codes USING btree (status);

--
-- Name: idx_device_codes_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_codes_tenant ON public.device_codes USING btree (tenant_id);

--
-- Name: idx_device_tokens_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_active ON public.device_tokens USING btree (is_active);

--
-- Name: idx_device_tokens_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_tenant ON public.device_tokens USING btree (tenant_id);

--
-- Name: idx_device_tokens_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_tokens_user ON public.device_tokens USING btree (user_id);

--
-- Name: idx_group_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_group_roles_tenant_id ON public.group_roles USING btree (tenant_id);

--
-- Name: idx_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_groups_tenant_id ON public.groups USING btree (tenant_id);

--
-- Name: idx_oauth_sessions_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_client ON public.oauth_sessions USING btree (client_identifier) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_org ON public.oauth_sessions USING btree (org_id) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_org_id ON public.oauth_sessions USING btree (org_id) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_oauth_sessions_session_id ON public.oauth_sessions USING btree (session_id);

--
-- Name: idx_oauth_sessions_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_state ON public.oauth_sessions USING btree (oauth_state) WHERE (is_active = true);

--
-- Name: idx_oauth_sessions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_sessions_tenant ON public.oauth_sessions USING btree (tenant_id) WHERE (is_active = true);

--
-- Name: idx_oidc_states_state_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_states_state_token ON public.oidc_states USING btree (state_token);

--
-- Name: idx_oidc_states_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oidc_states_tenant ON public.oidc_states USING btree (tenant_id);

--
-- Name: idx_oidc_user_identities_provider_name_provider_user_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_oidc_user_identities_provider_name_provider_user_id_key ON public.oidc_user_identities USING btree (provider_name, provider_user_id);

--
-- Name: idx_oidc_user_identities_tenant_id_user_id_provider_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_oidc_user_identities_tenant_id_user_id_provider_name_key ON public.oidc_user_identities USING btree (tenant_id, user_id, provider_name);

--
-- Name: idx_permissions_resource_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_permissions_resource_action ON public.permissions USING btree (resource, action);

--
-- Name: idx_permissions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_permissions_tenant_id ON public.permissions USING btree (tenant_id);

--
-- Name: idx_resource_methods_resource_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resource_methods_resource_id ON public.resource_methods USING btree (resource_id);

--
-- Name: idx_role_bindings_service_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_bindings_service_account_id ON public.role_bindings USING btree (service_account_id);

--
-- Name: idx_role_bindings_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_bindings_tenant_id ON public.role_bindings USING btree (tenant_id);

--
-- Name: idx_role_bindings_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_bindings_user_id ON public.role_bindings USING btree (user_id);

--
-- Name: idx_role_scopes_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_scopes_role_id ON public.role_scopes USING btree (role_id);

--
-- Name: idx_role_scopes_scope_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_scopes_scope_id ON public.role_scopes USING btree (scope_id);

--
-- Name: idx_roles_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_name ON public.roles USING btree (name);

--
-- Name: idx_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_tenant_id ON public.roles USING btree (tenant_id);

--
-- Name: idx_saml_callback_states_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_callback_states_expires_at ON public.saml_callback_states USING btree (expires_at);

--
-- Name: idx_saml_providers_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_providers_client_id ON public.saml_providers USING btree (client_id);

--
-- Name: idx_saml_providers_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saml_providers_tenant_id ON public.saml_providers USING btree (tenant_id);

--
-- Name: idx_scopes_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scopes_tenant_id ON public.scopes USING btree (tenant_id);

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
-- Name: idx_tenant_device_token_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_device_token_tenant ON public.tenant_device_tokens USING btree (tenant_id);

--
-- Name: idx_tenant_device_token_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_device_token_user ON public.tenant_device_tokens USING btree (user_id);

--
-- Name: idx_tenant_domains_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_tenant_id ON public.tenant_domains USING btree (tenant_id);

--
-- Name: idx_tenant_domains_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_domains_verified ON public.tenant_domains USING btree (tenant_id, is_verified);

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
-- Name: idx_tenant_totp_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_active ON public.tenant_totp_secrets USING btree (is_active);

--
-- Name: idx_tenant_totp_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_tenant ON public.tenant_totp_secrets USING btree (tenant_id);

--
-- Name: idx_tenant_totp_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_user ON public.tenant_totp_secrets USING btree (user_id);

--
-- Name: idx_tenant_totp_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_totp_verified ON public.tenant_totp_secrets USING btree (is_verified);

--
-- Name: idx_totp_backup_codes_user_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_backup_codes_user_tenant ON public.totp_backup_codes USING btree (user_id, tenant_id);

--
-- Name: idx_totp_secrets_user_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_totp_secrets_user_tenant ON public.totp_secrets USING btree (user_id, tenant_id);

--
-- Name: idx_user_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_groups_tenant_id ON public.user_groups USING btree (tenant_id);

--
-- Name: idx_user_roles_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_roles_tenant_id ON public.user_roles USING btree (tenant_id);

--
-- Name: idx_users_account_locked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_account_locked ON public.users USING btree (account_locked_at) WHERE (account_locked_at IS NOT NULL);

--
-- Name: idx_users_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_client_id ON public.users USING btree (client_id);

--
-- Name: idx_users_is_primary_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_is_primary_admin ON public.users USING btree (is_primary_admin) WHERE (is_primary_admin = true);

--
-- Name: idx_users_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_project_id ON public.users USING btree (project_id);

--
-- Name: idx_users_tenant_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_email ON public.users USING btree (tenant_id, email);

--
-- Name: idx_voice_active_sessions_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_active ON public.voice_active_sessions USING btree (is_active);

--
-- Name: idx_voice_active_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_expires_at ON public.voice_active_sessions USING btree (expires_at);

--
-- Name: idx_voice_active_sessions_refresh_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_refresh_hash ON public.voice_active_sessions USING btree (refresh_token_hash);

--
-- Name: idx_voice_active_sessions_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_session_id ON public.voice_active_sessions USING btree (session_id);

--
-- Name: idx_voice_active_sessions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_tenant ON public.voice_active_sessions USING btree (tenant_id);

--
-- Name: idx_voice_active_sessions_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_token_hash ON public.voice_active_sessions USING btree (access_token_hash);

--
-- Name: idx_voice_active_sessions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_active_sessions_user ON public.voice_active_sessions USING btree (user_id);

--
-- Name: idx_voice_identity_links_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_active ON public.voice_identity_links USING btree (is_active);

--
-- Name: idx_voice_identity_links_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_tenant ON public.voice_identity_links USING btree (tenant_id);

--
-- Name: idx_voice_identity_links_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_identity_links_user ON public.voice_identity_links USING btree (user_id);

--
-- Name: idx_voice_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_expires_at ON public.voice_sessions USING btree (expires_at);

--
-- Name: idx_voice_sessions_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_pending ON public.voice_sessions USING btree (tenant_id, pending_approval, approval_status);

--
-- Name: idx_voice_sessions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_status ON public.voice_sessions USING btree (status);

--
-- Name: idx_voice_sessions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_tenant ON public.voice_sessions USING btree (tenant_id);

--
-- Name: idx_voice_sessions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_voice_sessions_user ON public.voice_sessions USING btree (user_id);

--
-- Name: idx_webauthn_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_sessions_expires_at ON public.webauthn_sessions USING btree (expires_at);

--
-- Name: idx_webauthn_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webauthn_sessions_user_id ON public.webauthn_sessions USING btree (user_id);

--
-- Name: uq_device_codes_device_code; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_device_codes_device_code ON public.device_codes USING btree (device_code);

--
-- Name: uq_device_codes_user_code; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_device_codes_user_code ON public.device_codes USING btree (user_code);

--
-- Name: uq_device_tokens_device_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_device_tokens_device_token ON public.device_tokens USING btree (device_token);

--
-- Name: uq_tenant_device_id_per_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tenant_device_id_per_tenant ON public.tenant_device_tokens USING btree (id, tenant_id);

--
-- Name: uq_tenant_device_token_per_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tenant_device_token_per_tenant ON public.tenant_device_tokens USING btree (device_token, tenant_id);

--
-- Name: uq_tenant_totp_primary_device; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tenant_totp_primary_device ON public.tenant_totp_secrets USING btree (user_id, tenant_id) WHERE (is_primary = true);

--
-- Name: uq_voice_identity_links_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_voice_identity_links_identity ON public.voice_identity_links USING btree (tenant_id, voice_platform, voice_user_id);

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
-- Name: device_codes fk_device_codes_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT fk_device_codes_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE SET NULL;

--
-- Name: device_codes fk_device_codes_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT fk_device_codes_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: device_codes fk_device_codes_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_codes
    ADD CONSTRAINT fk_device_codes_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

--
-- Name: device_tokens fk_device_tokens_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_tokens_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: device_tokens fk_device_tokens_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tokens
    ADD CONSTRAINT fk_device_tokens_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

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
-- Name: voice_active_sessions fk_voice_active_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_active_sessions
    ADD CONSTRAINT fk_voice_active_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE SET NULL;

--
-- Name: voice_active_sessions fk_voice_active_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_active_sessions
    ADD CONSTRAINT fk_voice_active_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: voice_active_sessions fk_voice_active_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_active_sessions
    ADD CONSTRAINT fk_voice_active_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

--
-- Name: voice_identity_links fk_voice_links_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT fk_voice_links_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: voice_identity_links fk_voice_links_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_identity_links
    ADD CONSTRAINT fk_voice_links_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

--
-- Name: voice_sessions fk_voice_sessions_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT fk_voice_sessions_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE SET NULL;

--
-- Name: voice_sessions fk_voice_sessions_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT fk_voice_sessions_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: voice_sessions fk_voice_sessions_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.voice_sessions
    ADD CONSTRAINT fk_voice_sessions_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE;

--
-- Name: role_bindings role_bindings_role_fk_simple; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_role_fk_simple FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

--
-- Name: role_bindings role_bindings_user_fk_simple; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_user_fk_simple FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- PostgreSQL database dump complete
--


-- Name: idx_scopes_usage; Type: INDEX; Schema: public; Owner: -

CREATE INDEX idx_scopes_usage ON public.scopes USING btree (usage);
