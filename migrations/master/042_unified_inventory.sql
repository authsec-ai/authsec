-- 042_unified_inventory.sql — GitHub joins the shared graph's provenance, and
-- the inventory reads every provider.
--
-- expand only.
--
-- WHY
-- AWS (027-036) and Kubernetes (038-041) already write their discovered
-- workloads, identities and resources into the shared iga_* tables, each with a
-- record of WHICH reading last confirmed a row: iga_object_support names a
-- cloud_connector (AWS) or a discovery_sources row (Kubernetes), and grants
-- name the scan run or sweep that last saw them. That record is what lets a
-- row be retired when a complete reading no longer sees it, and what the
-- inventory requires before it lists a row at all.
--
-- GitHub scans are recorded in iga_integrations / iga_scan_runs, and nothing
-- in the support or grant tables can point there. So a GitHub row can neither
-- be listed as supported nor ever be retired. This migration gives GitHub the
-- same third provenance, exactly as 041 gave Kubernetes its second:
--
--   iga_object_support  + integration_id, last_confirmed_scan_run_id
--   iga_access_edges    + integration_id, last_confirmed_scan_run_id
--
-- Existing rows are untouched: every new column is nullable and every widened
-- CHECK accepts all rows the old one accepted.
--
-- The legacy GitHub IGA writer keeps writing its own rows (source_key = '',
-- no support). The unified projection writes separate, keyed rows; readers of
-- the legacy rows select source_key = '' and are unaffected.

-- 1. Support rows can name a GitHub integration ------------------------------
ALTER TABLE public.iga_object_support
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS last_confirmed_scan_run_id uuid;

ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_os_integration_fkey;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_os_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE;

ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_os_scan_run_fkey;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_os_scan_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_scan_run_id);

-- Exactly one source, now of three.
ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_object_support_source_chk;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_object_support_source_chk CHECK (
        (connector_id IS NOT NULL)::integer
      + (discovery_source_id IS NOT NULL)::integer
      + (integration_id IS NOT NULL)::integer = 1);

-- A row may only claim a reading of its own source's kind.
ALTER TABLE public.iga_object_support
    DROP CONSTRAINT IF EXISTS iga_object_support_confirm_chk;
ALTER TABLE public.iga_object_support
    ADD CONSTRAINT iga_object_support_confirm_chk CHECK (
        (last_confirmed_run_id      IS NULL OR connector_id        IS NOT NULL)
    AND (last_confirmed_sweep_id    IS NULL OR discovery_source_id IS NOT NULL)
    AND (last_confirmed_scan_run_id IS NULL OR integration_id      IS NOT NULL));

-- 2. source_ref covers the third source -------------------------------------
-- The five unique indexes the support upserts conflict on are keyed on
-- source_ref (041). Left as COALESCE(connector_id, discovery_source_id) it
-- would be NULL for every GitHub row, and NULLs never conflict, so each scan
-- would insert a new support row for the same object. It is generated, so it
-- is dropped and re-added with its indexes.
DROP INDEX IF EXISTS public.uq_iga_os_identity;
DROP INDEX IF EXISTS public.uq_iga_os_workload;
DROP INDEX IF EXISTS public.uq_iga_os_resource;
DROP INDEX IF EXISTS public.uq_iga_os_entitlement;
DROP INDEX IF EXISTS public.uq_iga_os_policy;

ALTER TABLE public.iga_object_support DROP COLUMN IF EXISTS source_ref;
ALTER TABLE public.iga_object_support
    ADD COLUMN source_ref uuid
        GENERATED ALWAYS AS (COALESCE(connector_id, discovery_source_id, integration_id)) STORED;

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_identity
    ON public.iga_object_support (workspace_id, identity_account_id, source_ref, partition_key)
    WHERE identity_account_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_workload
    ON public.iga_object_support (workspace_id, workload_id, source_ref, partition_key)
    WHERE workload_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_resource
    ON public.iga_object_support (workspace_id, resource_id, source_ref, partition_key)
    WHERE resource_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_entitlement
    ON public.iga_object_support (workspace_id, entitlement_id, source_ref, partition_key)
    WHERE entitlement_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_policy
    ON public.iga_object_support (workspace_id, policy_id, source_ref, partition_key)
    WHERE policy_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_iga_object_support_integration
    ON public.iga_object_support (workspace_id, integration_id, partition_key)
    WHERE state <> 'ended' AND integration_id IS NOT NULL;

-- 3. Grants can name a GitHub integration ------------------------------------
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS last_confirmed_scan_run_id uuid;

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_integration_fkey;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id) ON DELETE CASCADE;

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_scan_run_fkey;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_scan_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_scan_run_id);

-- A GitHub grant may not claim an AWS scan run confirmed it (041 states the
-- same for Kubernetes). Legacy GitHub edges never set last_confirmed_by.
ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_github_confirm_chk;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_github_confirm_chk CHECK (
        provider <> 'github' OR last_confirmed_by IS NULL);

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_scan_run_source_chk;
ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_scan_run_source_chk CHECK (
        last_confirmed_scan_run_id IS NULL OR integration_id IS NOT NULL);

-- 4. The inventory lists by provider -----------------------------------------
-- iga_identity_accounts and iga_resources have (workspace_id, provider,
-- lifecycle) since 028; iga_workload did not need one while it was AWS-only.
CREATE INDEX IF NOT EXISTS idx_iga_workload_provider
    ON public.iga_workload (workspace_id, provider, lifecycle);

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM information_schema.columns
     WHERE table_name = 'iga_object_support' AND column_name = 'source_ref'
       AND is_generated = 'ALWAYS'
       AND generation_expression LIKE '%integration_id%';
    IF n <> 1 THEN
        RAISE EXCEPTION '042: iga_object_support.source_ref does not cover integration_id';
    END IF;

    SELECT count(*) INTO n FROM pg_indexes
     WHERE schemaname = 'public'
       AND indexname IN ('uq_iga_os_identity', 'uq_iga_os_workload',
                         'uq_iga_os_resource', 'uq_iga_os_entitlement',
                         'uq_iga_os_policy')
       AND indexdef LIKE '%source_ref%';
    IF n <> 5 THEN
        RAISE EXCEPTION '042: expected 5 support indexes on source_ref, found %', n;
    END IF;

    SELECT count(*) INTO n FROM information_schema.columns
     WHERE table_name IN ('iga_object_support', 'iga_access_edges')
       AND column_name IN ('integration_id', 'last_confirmed_scan_run_id');
    IF n <> 4 THEN
        RAISE EXCEPTION '042: expected 4 new provenance columns, found %', n;
    END IF;
END $$;
