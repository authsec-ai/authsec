-- Scope Catalog is a governance/reuse layer. Runtime authorization continues
-- to use application-owned oauth_scopes.

CREATE TABLE IF NOT EXISTS scope_catalog_entries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    key text NOT NULL,
    display_name text NOT NULL,
    description text NOT NULL DEFAULT '',
    risk_level text NOT NULL DEFAULT 'low',
    source text NOT NULL DEFAULT 'manual',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scope_catalog_entries_risk_check
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT scope_catalog_entries_source_check
        CHECK (source IN ('preset', 'manual', 'imported'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scope_catalog_workspace_key
    ON scope_catalog_entries(workspace_id, key);

CREATE INDEX IF NOT EXISTS idx_scope_catalog_workspace
    ON scope_catalog_entries(workspace_id);
