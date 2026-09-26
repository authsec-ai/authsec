-- Validate the 045 checks and foreign keys outside the deploy transaction.
--
-- 045 adds them NOT VALID so the deploy transaction does not scan existing
-- rows under ACCESS EXCLUSIVE. This script takes SHARE UPDATE EXCLUSIVE for
-- each VALIDATE. Run it with autocommit, not inside psql -1 and not inside
-- the migration runner's transaction:
--
--   psql -v ON_ERROR_STOP=1 -f scripts/validate-045-ad-hardening.sql
--
-- Re-runnable. VALIDATE on an already-valid constraint is a no-op.
--
-- After the composite keys are valid, the 039 single-column foreign keys are
-- dropped. Nothing in the schema or the application references those names
-- (ad_inventory_scopes_config_fkey, ad_inventory_runs_config_fkey,
-- ad_directory_instances_config_fkey, ad_inventory_cursors_scope_fkey): they
-- are created only in 039. The composite keys keep the same ON DELETE CASCADE
-- behaviour. DROP runs only if every VALIDATE above succeeded (ON_ERROR_STOP).

ALTER TABLE public.sync_configurations VALIDATE CONSTRAINT sync_configurations_ad_tracking_mode_chk;
ALTER TABLE public.ad_inventory_cursors VALIDATE CONSTRAINT ad_inventory_cursors_tracking_mode_chk;

ALTER TABLE public.ad_inventory_scopes VALIDATE CONSTRAINT ad_inventory_scopes_config_ws_fkey;
ALTER TABLE public.ad_inventory_runs VALIDATE CONSTRAINT ad_inventory_runs_config_ws_fkey;
ALTER TABLE public.ad_directory_instances VALIDATE CONSTRAINT ad_directory_instances_config_ws_fkey;
ALTER TABLE public.ad_inventory_cursors VALIDATE CONSTRAINT ad_inventory_cursors_scope_ws_fkey;
ALTER TABLE public.ad_directory_posture VALIDATE CONSTRAINT ad_directory_posture_run_fkey;

ALTER TABLE public.ad_inventory_scopes DROP CONSTRAINT IF EXISTS ad_inventory_scopes_config_fkey;
ALTER TABLE public.ad_inventory_runs DROP CONSTRAINT IF EXISTS ad_inventory_runs_config_fkey;
ALTER TABLE public.ad_directory_instances DROP CONSTRAINT IF EXISTS ad_directory_instances_config_fkey;
ALTER TABLE public.ad_inventory_cursors DROP CONSTRAINT IF EXISTS ad_inventory_cursors_scope_fkey;
