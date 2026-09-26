-- Validate the 040 checks and foreign keys outside the deploy transaction.
--
-- 040 adds them NOT VALID so the deploy transaction does not scan the big
-- tables under ACCESS EXCLUSIVE. This script takes SHARE UPDATE EXCLUSIVE
-- only. Run it with autocommit, not inside psql -1 and not inside the
-- migration runner's transaction:
--
--   psql -v ON_ERROR_STOP=1 -f scripts/validate-040-typed-provenance.sql
--
-- Re-runnable. VALIDATE on an already-valid constraint is a no-op.

ALTER TABLE public.iga_object_support VALIDATE CONSTRAINT iga_object_support_arm_xor;
ALTER TABLE public.iga_relationship VALIDATE CONSTRAINT iga_relationship_arm_xor;
ALTER TABLE public.iga_access_edges VALIDATE CONSTRAINT iga_access_edges_arm_xor;
ALTER TABLE public.iga_policy_assignment VALIDATE CONSTRAINT iga_policy_assignment_arm_xor;
ALTER TABLE public.iga_access_edge_evidence VALIDATE CONSTRAINT iga_access_edge_evidence_arm_xor;
ALTER TABLE public.iga_relationship_evidence VALIDATE CONSTRAINT iga_relationship_evidence_arm_xor;
ALTER TABLE public.iga_assignment_evidence VALIDATE CONSTRAINT iga_assignment_evidence_arm_xor;
ALTER TABLE public.iga_projection_job VALIDATE CONSTRAINT iga_projection_job_arm_xor;
ALTER TABLE public.iga_projection_state VALIDATE CONSTRAINT iga_projection_state_arm_xor;
ALTER TABLE public.iga_publication VALIDATE CONSTRAINT iga_publication_arm_xor;
ALTER TABLE public.iga_pipeline_lease VALIDATE CONSTRAINT iga_pipeline_lease_arm_xor;
ALTER TABLE public.iga_pipeline_lease VALIDATE CONSTRAINT iga_pipeline_lease_busy_chk;

ALTER TABLE public.iga_object_support VALIDATE CONSTRAINT iga_object_support_integration_fkey;
ALTER TABLE public.iga_object_support VALIDATE CONSTRAINT iga_object_support_confirming_iga_run_fkey;
ALTER TABLE public.iga_relationship VALIDATE CONSTRAINT iga_relationship_integration_fkey;
ALTER TABLE public.iga_relationship VALIDATE CONSTRAINT iga_relationship_confirming_iga_run_fkey;
ALTER TABLE public.iga_access_edges VALIDATE CONSTRAINT iga_access_edges_integration_fkey;
ALTER TABLE public.iga_access_edges VALIDATE CONSTRAINT iga_access_edges_confirming_iga_run_fkey;
ALTER TABLE public.iga_policy_assignment VALIDATE CONSTRAINT iga_policy_assignment_integration_fkey;
ALTER TABLE public.iga_policy_assignment VALIDATE CONSTRAINT iga_policy_assignment_confirming_iga_run_fkey;
ALTER TABLE public.iga_access_edge_evidence VALIDATE CONSTRAINT iga_access_edge_evidence_iga_observation_fkey;
ALTER TABLE public.iga_relationship_evidence VALIDATE CONSTRAINT iga_relationship_evidence_iga_observation_fkey;
ALTER TABLE public.iga_assignment_evidence VALIDATE CONSTRAINT iga_assignment_evidence_iga_observation_fkey;
ALTER TABLE public.iga_projection_job VALIDATE CONSTRAINT iga_projection_job_iga_run_fkey;
ALTER TABLE public.iga_projection_state VALIDATE CONSTRAINT iga_projection_state_integration_fkey;
ALTER TABLE public.iga_projection_state VALIDATE CONSTRAINT iga_projection_state_iga_run_fkey;
ALTER TABLE public.iga_publication VALIDATE CONSTRAINT iga_publication_iga_run_fkey;
ALTER TABLE public.iga_pipeline_lease VALIDATE CONSTRAINT iga_pipeline_lease_iga_run_fkey;
