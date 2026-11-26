-- 145_cloud_scan_schedule_tenancy_index.sql
--
-- cloud_scan_schedule's workspace-leading index, idx_<table>_tenancy_ws, as 048
-- gives every workspace table. 048 reads the catalog when it runs, so a fresh
-- database -- where 001 creates cloud_scan_schedule before 048 runs -- has it,
-- and a database that reached 139 after 048 had run does not. This brings the
-- two to the same schema (scripts/schema-parity.sh).
--
-- Expand only: one index on a small table. Plain CREATE INDEX, as 048: the
-- runner wraps each migration in a transaction. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.

CREATE INDEX IF NOT EXISTS idx_cloud_scan_schedule_tenancy_ws
    ON public.cloud_scan_schedule (workspace_id);
