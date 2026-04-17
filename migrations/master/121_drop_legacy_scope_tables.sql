-- Migration 121: Drop legacy scope tables
-- These are fully replaced by oauth_scopes + oauth_scope_permissions (migration 118).
-- Data was already backfilled into the new tables by migration 118.

-- Drop the join table first (FK dependency)
DROP TABLE IF EXISTS api_scope_permissions;

-- Drop the legacy scope tables
DROP TABLE IF EXISTS api_scopes;
DROP TABLE IF EXISTS scope_permissions;
DROP TABLE IF EXISTS scope_resource_mappings;
