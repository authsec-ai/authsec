-- Add OIDC provider fields to mcp_oauth_clients.
-- post_logout_redirect_uris: RP-initiated logout (OIDC RP-Initiated Logout 1.0)
-- supports_refresh_token: gate refresh_token grant per-client (OAuth 2.1 / MCP draft)
ALTER TABLE mcp_oauth_clients
  ADD COLUMN IF NOT EXISTS post_logout_redirect_uris TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS supports_refresh_token BOOLEAN DEFAULT false;
