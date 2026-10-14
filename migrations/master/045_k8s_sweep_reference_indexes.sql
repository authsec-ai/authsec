-- 045_k8s_sweep_reference_indexes.sql — index the references to a Kubernetes
-- sweep, so pruning sweep history does not scan the workspace.
--
-- expand only.
--
-- WHY
-- Each successful Kubernetes ingest now prunes iga_k8s_sweep to the newest N
-- projected sweeps per (workspace, source, cluster), keeping any sweep a row
-- still names in last_confirmed_sweep_id. That NOT EXISTS check -- and the
-- foreign keys' ON DELETE SET NULL (last_confirmed_sweep_id) action -- probe
-- three tables by sweep id, and none of them had an index on it, so every prune
-- candidate scanned the workspace's support rows, assignments and grants.
--
-- Partial (only rows that name a sweep: Kubernetes rows), so AWS-only
-- workspaces pay nothing. Plain CREATE INDEX: migrations run in a transaction,
-- and these tables' Kubernetes slice is small.

CREATE INDEX IF NOT EXISTS idx_iga_os_last_sweep
    ON public.iga_object_support (workspace_id, last_confirmed_sweep_id)
    WHERE last_confirmed_sweep_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_iga_pa_last_sweep
    ON public.iga_policy_assignment (workspace_id, last_confirmed_sweep_id)
    WHERE last_confirmed_sweep_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_iga_ae_last_sweep
    ON public.iga_access_edges (workspace_id, last_confirmed_sweep_id)
    WHERE last_confirmed_sweep_id IS NOT NULL;
