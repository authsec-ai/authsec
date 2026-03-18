-- Migration: Create scope_resource_mappings for tenant databases
-- Description: Adds the missing scope_resource_mappings table used by /uflow/user|enduser scopes endpoints.

CREATE TABLE IF NOT EXISTS scope_resource_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    scope_name TEXT NOT NULL DEFAULT '*',
    resource_name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scope_resource_mappings_tenant_scope_resource
    ON scope_resource_mappings (tenant_id, scope_name, resource_name);
