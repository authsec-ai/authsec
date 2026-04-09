-- Migration 110: Add pending redirect URI fields for CIMD redirect review gate.
-- When a CIMD document changes redirect_uris, they are staged here for admin approval
-- instead of being auto-applied to the Hydra client.

ALTER TABLE mcp_oauth_clients ADD COLUMN IF NOT EXISTS pending_redirect_uris TEXT[] DEFAULT '{}';
ALTER TABLE mcp_oauth_clients ADD COLUMN IF NOT EXISTS redirect_review_pending BOOLEAN DEFAULT false;
