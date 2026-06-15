-- xaa_client_apps: requesting-app identities for Cross-App Access (XAA / ID-JAG).
--
-- An XAA client app is an authenticated piece of software (typically an agent
-- or a chained MCP server) that wants to exchange a user's identity assertion
-- for a scoped access token at one of AuthSec's protected MCPs. The flow is
-- the IETF draft-ietf-oauth-identity-assertion-authz-grant ("ID-JAG").
--
-- This is deliberately separate from mcp_oauth_clients:
--   * mcp_oauth_clients are user-driven, anonymously DCR'd, and untrusted.
--   * xaa_client_apps are admin-registered, have stable credentials, and
--     are subject to per-(client, resource) policy in application_xaa_policies.
--
-- Lives in master because the same client app may target resources across
-- multiple tenants. tenant_id pins ownership of the row (who can manage it)
-- but does NOT scope which tenants the app may reach — that's policy.

CREATE TABLE IF NOT EXISTS xaa_client_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    client_id TEXT NOT NULL UNIQUE,
    -- bcrypt; nullable so external-IdP-issued ID-JAGs (where the client
    -- authenticates at the external IdP, not at us) can still be registered
    -- without forcing a secret we'll never check.
    client_secret_hash TEXT,
    name TEXT NOT NULL,
    display_name TEXT,
    -- 'internal' = ID-JAGs are issued by AuthSec itself (client authenticates
    -- against POST /authsec/oauth/v2/idjag/token using client_secret_hash).
    -- 'external' = ID-JAGs come from a trusted external IdP and we just trust
    -- the signature; client_secret_hash is unused.
    issuance_mode TEXT NOT NULL DEFAULT 'internal',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_xaa_client_apps_tenant_id ON xaa_client_apps (tenant_id);
CREATE INDEX IF NOT EXISTS idx_xaa_client_apps_active ON xaa_client_apps (active) WHERE deleted_at IS NULL;
