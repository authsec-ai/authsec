-- Migration 124: Resource server onboarding access policy + validation metadata

CREATE TABLE IF NOT EXISTS resource_server_access_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    resource_server_id uuid NOT NULL UNIQUE REFERENCES resource_servers(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    default_role_id uuid REFERENCES roles(id) ON DELETE SET NULL,
    assignment_trigger text NOT NULL DEFAULT 'first_successful_login',
    assignment_source text NOT NULL DEFAULT 'default_policy',
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rs_access_policies_tenant_id
    ON resource_server_access_policies (tenant_id);

ALTER TABLE role_bindings
    ADD COLUMN IF NOT EXISTS assignment_source text NOT NULL DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS assignment_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS last_validated_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_validation_status text,
    ADD COLUMN IF NOT EXISTS last_validation_error text;
