-- Migration: 120_add_mcp_oauth_client_sync_status.sql
-- Description:
--   Track Hydra synchronisation state for each AuthSec mcp_oauth_clients row.
--   AuthSec is the policy/registration source of truth; Hydra is the OAuth
--   protocol executor. When the two get out of step (network blip during
--   create, partial delete during revocation, etc.) we mark the row sync_error
--   so the reconciler service can re-attempt the Hydra side asynchronously
--   instead of stranding the operator with a permanent half-sync.

ALTER TABLE mcp_oauth_clients
    ADD COLUMN IF NOT EXISTS sync_status text NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS sync_last_error text,
    ADD COLUMN IF NOT EXISTS sync_last_error_at timestamptz;

ALTER TABLE mcp_oauth_clients
    DROP CONSTRAINT IF EXISTS mcp_oauth_clients_sync_status_chk;

ALTER TABLE mcp_oauth_clients
    ADD CONSTRAINT mcp_oauth_clients_sync_status_chk
    CHECK (sync_status IN ('active', 'sync_error', 'pending_delete'));

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_sync_status
    ON mcp_oauth_clients(sync_status)
    WHERE sync_status <> 'active';
