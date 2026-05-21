-- Migration: 117_identity_providers_scim_spiffe.sql
-- Description: Add workspace-owned IDP, opaque SCIM connection, and Application SPIFFE identity tables.

CREATE TABLE IF NOT EXISTS identity_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    provider_type text NOT NULL,
    display_name text NOT NULL,
    config_ref text NOT NULL,
    status text NOT NULL DEFAULT 'configured',
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT identity_providers_type_chk CHECK (provider_type IN ('google', 'oidc', 'saml', 'ad', 'entra', 'scim'))
);

CREATE INDEX IF NOT EXISTS idx_identity_providers_workspace ON identity_providers(workspace_id);
CREATE INDEX IF NOT EXISTS idx_identity_providers_type ON identity_providers(provider_type);

CREATE TABLE IF NOT EXISTS application_identity_provider_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    identity_provider_id uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT application_identity_provider_policies_uq UNIQUE (application_id, identity_provider_id)
);

CREATE INDEX IF NOT EXISTS idx_app_idp_policies_workspace ON application_identity_provider_policies(workspace_id);

CREATE TABLE IF NOT EXISTS scim_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    identity_provider_id uuid REFERENCES identity_providers(id) ON DELETE SET NULL,
    token_hash text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT scim_connections_status_chk CHECK (status IN ('active', 'revoked', 'disabled'))
);

CREATE INDEX IF NOT EXISTS idx_scim_connections_workspace ON scim_connections(workspace_id);
CREATE INDEX IF NOT EXISTS idx_scim_connections_identity_provider ON scim_connections(identity_provider_id);

CREATE TABLE IF NOT EXISTS application_spiffe_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    spiffe_id text NOT NULL UNIQUE,
    trust_domain text NOT NULL,
    selectors jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT application_spiffe_identities_status_chk CHECK (status IN ('active', 'revoked', 'disabled'))
);

CREATE INDEX IF NOT EXISTS idx_app_spiffe_workspace ON application_spiffe_identities(workspace_id);
CREATE INDEX IF NOT EXISTS idx_app_spiffe_application ON application_spiffe_identities(application_id);
