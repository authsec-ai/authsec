-- Validate the 041 checks and the assignment foreign key outside the
-- deploy transaction.
--
-- 041 adds them NOT VALID so the deploy transaction does not scan the big
-- tables under ACCESS EXCLUSIVE. This script takes SHARE UPDATE EXCLUSIVE
-- only. Run it with autocommit, not inside psql -1 and not inside the
-- migration runner's transaction:
--
--   psql -v ON_ERROR_STOP=1 -f scripts/validate-041-runtime-graph.sql
--
-- Re-runnable. VALIDATE on an already-valid constraint is a no-op.
-- Rollback of 041 is the feature flag off; do not drop these constraints
-- to roll back.

ALTER TABLE public.iga_policy VALIDATE CONSTRAINT iga_policy_kind_chk;
ALTER TABLE public.iga_policy_assignment VALIDATE CONSTRAINT iga_pa_kind_chk;
ALTER TABLE public.iga_relationship VALIDATE CONSTRAINT iga_relationship_pair_chk;
ALTER TABLE public.iga_identity_accounts VALIDATE CONSTRAINT iga_identity_accounts_account_state_chk;
ALTER TABLE public.iga_identity_accounts VALIDATE CONSTRAINT iga_identity_accounts_provider_kind_chk;
ALTER TABLE public.iga_resources VALIDATE CONSTRAINT iga_resources_reference_status_chk;
ALTER TABLE public.iga_policy VALIDATE CONSTRAINT iga_policy_provider_kind_chk;
ALTER TABLE public.iga_policy VALIDATE CONSTRAINT iga_policy_rights_schema_chk;
ALTER TABLE public.iga_policy_assignment VALIDATE CONSTRAINT iga_pa_scope_kind_chk;
ALTER TABLE public.iga_policy_assignment VALIDATE CONSTRAINT iga_pa_estate_scope_fkey;
ALTER TABLE public.iga_relationship VALIDATE CONSTRAINT iga_relationship_backed_by_basis_chk;
ALTER TABLE public.iga_relationship VALIDATE CONSTRAINT iga_relationship_executes_as_basis_chk;
ALTER TABLE public.iga_access_edges VALIDATE CONSTRAINT iga_access_edges_k8s_grant_chk;
