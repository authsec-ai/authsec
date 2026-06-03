-- oauth_scopes: per-Application scope registry. Rows here are the
-- authoritative source for what scopes an Application supports; the
-- resource_servers.scopes_supported array column remains for back-compat
-- with the SDK's /sdk-policy reader and is kept in sync by application code.
--
-- Backport-lean equivalent of dev's oauth_scopes table. Dev has
-- parent_scope_id, is_auto_discovered, scope hierarchy, etc.; we keep just
-- what an admin UI needs to CRUD: scope_string + display fields + risk.

CREATE TABLE IF NOT EXISTS oauth_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    scope_string TEXT NOT NULL,
    display_name TEXT,
    description TEXT,
    risk_level TEXT NOT NULL DEFAULT 'low',
    source TEXT NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_scopes_application_string_uq UNIQUE (application_id, scope_string),
    CONSTRAINT oauth_scopes_risk_level_chk CHECK (risk_level IN ('low','medium','high','critical')),
    CONSTRAINT oauth_scopes_source_chk CHECK (source IN ('admin','application_create','sdk_discovered'))
);

CREATE INDEX IF NOT EXISTS idx_oauth_scopes_tenant      ON oauth_scopes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_application ON oauth_scopes(application_id);

-- Backfill: any scope already in resource_servers.scopes_supported gets a
-- row here with source='application_create'. Idempotent — re-running just
-- skips duplicates via the unique constraint.
INSERT INTO oauth_scopes (tenant_id, application_id, scope_string, display_name, source)
SELECT
    rs.tenant_id,
    rs.id,
    scope,
    scope,
    'application_create'
  FROM resource_servers rs
  CROSS JOIN LATERAL unnest(rs.scopes_supported) AS scope
 WHERE rs.deleted_at IS NULL
   AND scope IS NOT NULL
   AND scope <> ''
ON CONFLICT (application_id, scope_string) DO NOTHING;
