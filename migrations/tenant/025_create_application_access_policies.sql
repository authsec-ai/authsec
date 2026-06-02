-- application_access_policies: minimal per-Application default-role policy.
-- Tenant DB. The dev branch stores richer per-RS policy with role-option
-- enumeration and scope-grant validation — that's intentionally not ported
-- here to keep the backport away from the full RBAC stack. Callers should
-- expect the GET endpoint to return only the stored row's fields plus an
-- empty role_options array.

CREATE TABLE IF NOT EXISTS application_access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    default_role_id UUID,
    assignment_trigger TEXT NOT NULL DEFAULT 'first_successful_login',
    assignment_source TEXT NOT NULL DEFAULT 'default_policy',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT application_access_policies_application_uq UNIQUE (application_id)
);

CREATE INDEX IF NOT EXISTS idx_application_access_policies_tenant ON application_access_policies(tenant_id);
