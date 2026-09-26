-- Validate the 042 checks and foreign keys outside the deploy transaction.
--
-- 042 adds them NOT VALID so the deploy transaction does not scan
-- iga_agent_instances under ACCESS EXCLUSIVE. This script takes
-- SHARE UPDATE EXCLUSIVE only. Run it with autocommit, not inside psql -1
-- and not inside the migration runner's transaction:
--
--   psql -v ON_ERROR_STOP=1 -f scripts/validate-042-agent-instance-link.sql
--
-- Re-runnable. VALIDATE on an already-valid constraint is a no-op.
-- discovered_agent_workloads is created empty with valid constraints, so
-- it is not listed here.

ALTER TABLE public.iga_agent_instances VALIDATE CONSTRAINT iga_agent_instances_workload_authority_chk;
ALTER TABLE public.iga_agent_instances VALIDATE CONSTRAINT iga_agent_instances_observation_arm_chk;
ALTER TABLE public.iga_agent_instances VALIDATE CONSTRAINT iga_agent_instances_workload_fkey;
ALTER TABLE public.iga_agent_instances VALIDATE CONSTRAINT iga_agent_instances_observation_fkey;
ALTER TABLE public.iga_agent_instances VALIDATE CONSTRAINT iga_agent_instances_cloud_observation_fkey;
