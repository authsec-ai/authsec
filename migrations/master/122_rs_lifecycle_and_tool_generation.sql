-- Migration 122: Resource Server Lifecycle Tracking + Tool Generation Tracking
-- Adds scan lifecycle state to resource_servers and last_scan_generation to mcp_tools.
-- All DDL is idempotent (IF NOT EXISTS / conditional UPDATEs).

-- ── resource_servers: lifecycle columns ─────────────────────────────────────

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending_scan'
        CHECK (status IN ('pending_scan', 'ready', 'degraded'));

ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS scan_generation              INTEGER NOT NULL DEFAULT 0;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_successful_generation   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS scan_in_progress             BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE resource_servers
    ADD COLUMN IF NOT EXISTS last_scan_status TEXT
        CHECK (last_scan_status IS NULL OR last_scan_status IN ('success', 'failure', 'partial'));

ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_scan_error          TEXT;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_scan_started_at     TIMESTAMPTZ;
ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS last_scan_completed_at   TIMESTAMPTZ;

-- Transitional approximation: active RSs with existing tools are promoted to
-- ready/gen=1. This is operationally convenient but not semantically guaranteed —
-- pre-migration data may be stale or partial. Inactive (soft-deleted) RSs are
-- intentionally left at pending_scan/gen=0.
UPDATE resource_servers rs
SET    status                    = 'ready',
       scan_generation           = 1,
       last_successful_generation = 1,
       last_scan_status          = 'success'
WHERE  active = true
  AND  deleted_at IS NULL
  AND  EXISTS (SELECT 1 FROM mcp_tools mt WHERE mt.resource_server_id = rs.id);

-- ── mcp_tools: generation tracking ──────────────────────────────────────────

ALTER TABLE mcp_tools ADD COLUMN IF NOT EXISTS last_scan_generation INTEGER NOT NULL DEFAULT 0;

-- Back-fill existing tools to match their RS's last_successful_generation.
UPDATE mcp_tools mt
SET    last_scan_generation = 1
WHERE  EXISTS (
    SELECT 1 FROM resource_servers rs
    WHERE  rs.id = mt.resource_server_id
      AND  rs.last_successful_generation = 1
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_mcp_tools_rs_generation
    ON mcp_tools(resource_server_id, last_scan_generation);

CREATE INDEX IF NOT EXISTS idx_rs_status
    ON resource_servers(status)
    WHERE active = true AND deleted_at IS NULL;
