-- application_identity_provider_policies: per-Application opt-in whitelist of
-- which IDPs an Application accepts. When an Application has zero policy
-- rows, all of the tenant's identity_providers are allowed (default-allow).
-- When it has any row, only those marked enabled=true are allowed
-- (whitelist mode).

CREATE TABLE IF NOT EXISTS application_identity_provider_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT application_idp_policies_uq UNIQUE (application_id, identity_provider_id)
);

CREATE INDEX IF NOT EXISTS idx_app_idp_policies_tenant ON application_identity_provider_policies(tenant_id);
