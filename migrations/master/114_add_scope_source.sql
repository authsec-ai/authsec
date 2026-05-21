-- 114_add_scope_source.sql
--
-- Adds a `source` column to oauth_scopes that records WHERE a scope came from:
--   'discovered' — auto-discovered via PRM /.well-known/oauth-protected-resource
--   'preset'     — seeded at Application registration from the 12-preset catalog
--   'manifest'   — published by the SDK via PUT /sdk-manifest (suggested_scopes)
--   'manual'     — created by an operator from the admin UI
--
-- The legacy `is_auto_discovered` flag is preserved for backward compatibility;
-- new code should read `source` instead.

ALTER TABLE oauth_scopes
  ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'discovered'
  CHECK (source IN ('discovered', 'preset', 'manifest', 'manual'));

-- Backfill from the existing is_auto_discovered flag.
UPDATE oauth_scopes
   SET source = CASE WHEN is_auto_discovered THEN 'discovered' ELSE 'manual' END;
