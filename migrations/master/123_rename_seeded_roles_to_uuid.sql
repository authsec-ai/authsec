-- Migration 123: Rename auto-generated role names from rs:<name>:suffix to rs-<id>:suffix
-- for RSes whose name has NOT changed since seeding.
--
-- This is a best-effort transition. Roles for RSes that were renamed before this
-- migration runs will not be matched and must be cleaned up manually.
-- See: docs/DEV_MCP_INTEGRATION_RUNBOOK.md for manual cleanup steps.

UPDATE roles r
SET name = 'rs-' || rs.id::text || ':' || split_part(r.name, ':', 3)
FROM resource_servers rs
WHERE r.tenant_id = rs.tenant_id
  AND r.name ~ ('^rs:' || rs.name || ':(admin|readonly)$')
  AND r.description LIKE '%auto-generated%';
