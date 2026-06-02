-- identity_providers: the tenant's IDP registry. provider_type discriminates
-- ('oidc', 'saml', 'ad', 'entra', 'scim'); config_ref points at the
-- underlying protocol-specific row (oidc_providers.id, saml_providers.id,
-- sync_configurations.id) by string-stringified UUID.
--
-- The underlying oidc_providers table is currently global in this branch.
-- That's tolerable for shared system IDPs but blocks per-tenant Google
-- client_id/secret. Adding a tenant_id column to oidc_providers is a
-- follow-up (out of scope for this phase).

CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    provider_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    config_ref TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'configured',
    created_by_user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT identity_providers_type_chk
        CHECK (provider_type IN ('oidc', 'saml', 'ad', 'entra', 'scim'))
);

CREATE INDEX IF NOT EXISTS idx_identity_providers_tenant ON identity_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_identity_providers_type ON identity_providers(provider_type);
