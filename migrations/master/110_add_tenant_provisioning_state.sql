-- Track whether a tenant's POST-COMMIT provisioning finished.
--
-- Tenant registration commits the master rows (tenants/projects/users/roles) in
-- one transaction, then performs non-transactional post-commit work: create the
-- tenant database, run its migrations, write tenant_mappings, register Hydra/
-- Vault, etc. If the process is interrupted in that window (e.g. a Karpenter
-- node-consolidation eviction mid-registration) the tenant row exists and looks
-- active but its database is missing or half-migrated.
--
-- provisioning_state makes that window observable and repairable:
--   'pending'  — master rows committed; post-commit infra not yet confirmed.
--   'complete' — tenant DB created+migrated and mappings present.
-- A startup/periodic resumer re-runs the idempotent infra for any tenant left
-- 'pending'. Existing tenants default to 'complete' (they are already live).
DO $$
BEGIN
    IF to_regclass('public.tenants') IS NOT NULL THEN
        ALTER TABLE public.tenants
            ADD COLUMN IF NOT EXISTS provisioning_state TEXT NOT NULL DEFAULT 'complete';
        CREATE INDEX IF NOT EXISTS idx_tenants_provisioning_state
            ON public.tenants(provisioning_state);
    END IF;
END $$;
