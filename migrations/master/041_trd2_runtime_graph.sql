-- 041_trd2_runtime_graph.sql — TRD 2 M3 vocabulary, runtime instances and
-- observed access (WP-A4).
--
-- Additive and re-runnable. No transaction wrapper: the runner and CI apply
-- this file with psql -1. Nothing here uses CREATE INDEX CONCURRENTLY.
-- 042, 043, 044 and 045 are not required and are not referenced.
--
-- estate_scope_id is the column the rest of the graph already uses. The
-- specification's estate_id is this column.
--
-- provider_attrs stays display-only. reference_status, native_kind,
-- kind_metadata and account_state are the queryable fields. Nothing in this
-- migration treats provider_attrs as an authorization filter.
--
-- linux_nftables is included with the Linux policy kinds. Folding nftables
-- into linux_lsm would drop the original firewall semantics (S8.1a).
--
-- backed_by_directory is vocabulary only. Deriving it is WP-A9 part 2.
-- executes_as stays basis=declared. A container UID is a runtime binding,
-- not this relationship.
--
-- Lock and runtime. Checks and the new assignment foreign key on tables that
-- already hold rows are NOT VALID. New tables are empty, so their keys are
-- valid immediately. VALIDATE is scripts/validate-041-runtime-graph.sql,
-- outside this transaction.
--
--   Statement                         Lock                         Notes
--   ADD COLUMN ... DEFAULT            ACCESS EXCLUSIVE, brief      constant default, no rewrite (PG 11+)
--   DROP/ADD CHECK NOT VALID          ACCESS EXCLUSIVE, catalog    no full-table scan; union with the live check
--   ADD FK NOT VALID                  SHARE ROW EXCLUSIVE          no full-table scan
--   CREATE TABLE / INDEX              SHARE on the new table       empty
--   VALIDATE CONSTRAINT               not in this file             scripts/validate-041-runtime-graph.sql
--
-- Down: forward-only. Rollback is IGA_V2_PROJECTION off. The columns stay.

CREATE OR REPLACE FUNCTION public.trd2_extend_check(
    p_table regclass,
    p_name text,
    p_token text,
    p_or text
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    def text;
    expr text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def
      FROM pg_constraint
     WHERE conrelid = p_table AND conname = p_name AND contype = 'c';
    IF def IS NULL THEN
        RAISE EXCEPTION 'missing check %.%', p_table, p_name;
    END IF;
    IF position(p_token in def) > 0 THEN
        RETURN;
    END IF;
    expr := btrim(def);
    expr := regexp_replace(expr, '^CHECK\s*', '', 'i');
    IF left(expr, 1) <> '(' OR right(expr, 1) <> ')' THEN
        RAISE EXCEPTION 'cannot read %: %', p_name, def;
    END IF;
    expr := substring(expr FROM 2 FOR char_length(expr) - 2);
    EXECUTE 'ALTER TABLE ' || p_table::text || ' DROP CONSTRAINT ' || quote_ident(p_name);
    EXECUTE 'ALTER TABLE ' || p_table::text || ' ADD CONSTRAINT ' || quote_ident(p_name)
        || ' CHECK ((' || expr || ') OR (' || p_or || ')) NOT VALID';
END $$;

SELECT public.trd2_extend_check(
    'public.iga_policy'::regclass,
    'iga_policy_kind_chk',
    'k8s_role',
    'policy_kind IN (''k8s_role'',''k8s_cluster_role'',''k8s_network_policy'',''linux_posix_acl'',''linux_systemd'',''linux_lsm'',''linux_nftables'')');

SELECT public.trd2_extend_check(
    'public.iga_policy_assignment'::regclass,
    'iga_pa_kind_chk',
    'k8s_role_binding',
    'assignment_kind IN (''k8s_role_binding'',''k8s_cluster_role_binding'')');

SELECT public.trd2_extend_check(
    'public.iga_relationship'::regclass,
    'iga_relationship_pair_chk',
    'backed_by_directory',
    'relationship_type = ''backed_by_directory'' AND source_identity_account_id IS NOT NULL');

DROP FUNCTION public.trd2_extend_check(regclass, text, text, text);

ALTER TABLE public.iga_identity_accounts
    ADD COLUMN IF NOT EXISTS account_state text NOT NULL DEFAULT 'enabled';
ALTER TABLE public.iga_resources
    ADD COLUMN IF NOT EXISTS reference_status text NOT NULL DEFAULT 'referenced',
    ADD COLUMN IF NOT EXISTS native_kind text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS kind_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE public.iga_policy
    ADD COLUMN IF NOT EXISTS rights_schema text NOT NULL DEFAULT '';
ALTER TABLE public.iga_policy
    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE public.iga_policy_assignment
    ADD COLUMN IF NOT EXISTS binding_native_uid text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS assignment_scope_kind text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS assignment_estate_scope_id uuid,
    ADD COLUMN IF NOT EXISTS namespace_uid text NOT NULL DEFAULT '';

COMMENT ON COLUMN public.iga_resources.provider_attrs IS
    'Display-only provider fact. Not an authorization filter. Query reference_status, native_kind and kind_metadata.';
COMMENT ON COLUMN public.iga_resources.reference_status IS
    'referenced, observed, or inventoried. Inventoried means an authoritative inventory, not a name match.';
COMMENT ON COLUMN public.iga_identity_accounts.account_state IS
    'enabled, disabled, or unknown. Disabled is a state. It is not retirement.';
COMMENT ON COLUMN public.iga_policy.rights_schema IS
    'Which native document native_rights holds. Empty on rows this migration did not project.';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_identity_accounts_account_state_chk') THEN
        ALTER TABLE public.iga_identity_accounts
            ADD CONSTRAINT iga_identity_accounts_account_state_chk
            CHECK (account_state IN ('enabled', 'disabled', 'unknown')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_identity_accounts_provider_kind_chk') THEN
        ALTER TABLE public.iga_identity_accounts
            ADD CONSTRAINT iga_identity_accounts_provider_kind_chk
            CHECK (CASE provider
                WHEN 'linux' THEN account_kind IN ('local_user', 'local_group')
                WHEN 'kubernetes' THEN account_kind IN ('k8s_service_account', 'k8s_group')
                WHEN 'ad' THEN account_kind IN ('ad_user', 'ad_group', 'ad_computer', 'ad_managed_service_account')
                ELSE true
            END) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_resources_reference_status_chk') THEN
        ALTER TABLE public.iga_resources
            ADD CONSTRAINT iga_resources_reference_status_chk
            CHECK (reference_status IN ('referenced', 'observed', 'inventoried')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_policy_provider_kind_chk') THEN
        ALTER TABLE public.iga_policy
            ADD CONSTRAINT iga_policy_provider_kind_chk
            CHECK (CASE provider
                WHEN 'linux' THEN policy_kind IN ('linux_posix_acl', 'linux_systemd', 'linux_lsm', 'linux_nftables')
                WHEN 'kubernetes' THEN policy_kind IN ('k8s_role', 'k8s_cluster_role', 'k8s_network_policy')
                ELSE true
            END) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_policy_rights_schema_chk') THEN
        ALTER TABLE public.iga_policy
            ADD CONSTRAINT iga_policy_rights_schema_chk
            CHECK (rights_schema IN ('', 'aws', 'k8s_rbac', 'posix_acl', 'systemd', 'lsm', 'nftables', 'network_policy')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_pa_scope_kind_chk') THEN
        ALTER TABLE public.iga_policy_assignment
            ADD CONSTRAINT iga_pa_scope_kind_chk
            CHECK (assignment_scope_kind IN ('', 'namespace', 'cluster', 'host', 'estate')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_pa_estate_scope_fkey') THEN
        ALTER TABLE public.iga_policy_assignment
            ADD CONSTRAINT iga_pa_estate_scope_fkey
            FOREIGN KEY (workspace_id, assignment_estate_scope_id)
            REFERENCES public.iga_estate_scopes (workspace_id, id) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_relationship_backed_by_basis_chk') THEN
        ALTER TABLE public.iga_relationship
            ADD CONSTRAINT iga_relationship_backed_by_basis_chk
            CHECK (relationship_type <> 'backed_by_directory' OR basis IN ('derived', 'asserted')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_relationship_executes_as_basis_chk') THEN
        ALTER TABLE public.iga_relationship
            ADD CONSTRAINT iga_relationship_executes_as_basis_chk
            CHECK (relationship_type <> 'executes_as' OR basis = 'declared') NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_access_edges_k8s_grant_chk') THEN
        ALTER TABLE public.iga_access_edges
            ADD CONSTRAINT iga_access_edges_k8s_grant_chk
            CHECK (provider <> 'kubernetes' OR (calculation_state = 'partial' AND effective_conclusion = 'unknown')) NOT VALID;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.iga_runtime_instances (
    id                      uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id            uuid NOT NULL,
    workload_id             uuid NOT NULL,
    estate_scope_id         uuid,
    runtime_key             text NOT NULL,
    runtime_kind            text NOT NULL,
    boot_or_pod_incarnation text NOT NULL DEFAULT '',
    parent_runtime_id       uuid,
    started_at              timestamptz,
    ended_at                timestamptz,
    last_observed_at        timestamptz NOT NULL,
    native_attributes       jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT iga_runtime_instances_pkey PRIMARY KEY (id),
    CONSTRAINT iga_runtime_instances_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT iga_runtime_instances_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_runtime_instances_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id),
    CONSTRAINT iga_runtime_instances_parent_fkey FOREIGN KEY (workspace_id, parent_runtime_id)
        REFERENCES public.iga_runtime_instances (workspace_id, id),
    CONSTRAINT iga_runtime_instances_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_runtime_instances_workload_id_key UNIQUE (workspace_id, workload_id, id),
    CONSTRAINT iga_runtime_instances_key_key UNIQUE (workspace_id, runtime_key),
    CONSTRAINT iga_runtime_instances_key_chk CHECK (runtime_key <> '')
);

CREATE INDEX IF NOT EXISTS idx_iga_runtime_instances_workload
    ON public.iga_runtime_instances (workspace_id, workload_id, last_observed_at DESC);

CREATE TABLE IF NOT EXISTS public.iga_runtime_identity_bindings (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    runtime_instance_id  uuid NOT NULL,
    identity_account_id  uuid NOT NULL,
    binding_kind         text NOT NULL,
    basis                text NOT NULL DEFAULT 'observed',
    observation_id       uuid NOT NULL,
    valid_from           timestamptz NOT NULL,
    valid_to             timestamptz,
    CONSTRAINT iga_runtime_identity_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT iga_runtime_identity_bindings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT iga_rib_runtime_fkey FOREIGN KEY (workspace_id, runtime_instance_id)
        REFERENCES public.iga_runtime_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rib_identity_fkey FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rib_observation_fkey FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_runtime_identity_bindings_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_rib_key UNIQUE (workspace_id, runtime_instance_id, identity_account_id, binding_kind),
    CONSTRAINT iga_rib_kind_chk CHECK (binding_kind IN ('uid', 'gid', 'supplementary_group', 'container_uid')),
    CONSTRAINT iga_rib_basis_chk CHECK (basis = 'observed')
);

CREATE TABLE IF NOT EXISTS public.iga_observed_access (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    workload_id          uuid NOT NULL,
    runtime_instance_id  uuid NOT NULL,
    identity_account_id  uuid,
    resource_id          uuid NOT NULL,
    observation_id       uuid NOT NULL,
    action               text NOT NULL,
    outcome              text NOT NULL,
    observed_at          timestamptz NOT NULL,
    attribution          text NOT NULL DEFAULT '',
    CONSTRAINT iga_observed_access_pkey PRIMARY KEY (id),
    CONSTRAINT iga_observed_access_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT iga_observed_access_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observed_access_runtime_fkey FOREIGN KEY (workspace_id, runtime_instance_id)
        REFERENCES public.iga_runtime_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observed_access_runtime_workload_fkey
        FOREIGN KEY (workspace_id, workload_id, runtime_instance_id)
        REFERENCES public.iga_runtime_instances (workspace_id, workload_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observed_access_identity_fkey FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id),
    CONSTRAINT iga_observed_access_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observed_access_observation_fkey FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_observed_access_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_observed_access_fact_key UNIQUE (workspace_id, observation_id, action, resource_id),
    CONSTRAINT iga_observed_access_action_chk CHECK (action <> ''),
    CONSTRAINT iga_observed_access_outcome_chk CHECK (outcome IN ('attempted', 'success', 'denied', 'unknown'))
);

CREATE INDEX IF NOT EXISTS iga_observed_access_workload_time
    ON public.iga_observed_access (workspace_id, workload_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS public.iga_workload_resource_bindings (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    workload_id    uuid NOT NULL,
    resource_id    uuid NOT NULL,
    binding_kind   text NOT NULL,
    state          text NOT NULL DEFAULT 'current',
    observation_id uuid,
    source_key     text NOT NULL,
    CONSTRAINT iga_workload_resource_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT iga_wrb_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT iga_wrb_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wrb_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wrb_observation_fkey FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_workload_resource_bindings_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_wrb_kind_chk CHECK (binding_kind IN ('mount', 'secret_ref', 'service_dependency', 'declared')),
    CONSTRAINT iga_wrb_state_chk CHECK (state IN ('current', 'ended')),
    CONSTRAINT iga_wrb_key_chk CHECK (source_key <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_wrb_live
    ON public.iga_workload_resource_bindings (workspace_id, source_key) WHERE state <> 'ended';

CREATE TABLE IF NOT EXISTS public.iga_workload_policy_bindings (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    workload_id    uuid NOT NULL,
    policy_id      uuid NOT NULL,
    binding_kind   text NOT NULL,
    state          text NOT NULL DEFAULT 'current',
    observation_id uuid,
    source_key     text NOT NULL,
    CONSTRAINT iga_workload_policy_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT iga_wpb_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT iga_wpb_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wpb_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wpb_observation_fkey FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_workload_policy_bindings_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_wpb_kind_chk CHECK (binding_kind IN ('systemd', 'lsm', 'nftables', 'network_policy', 'posix_acl')),
    CONSTRAINT iga_wpb_state_chk CHECK (state IN ('current', 'ended')),
    CONSTRAINT iga_wpb_key_chk CHECK (source_key <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_wpb_live
    ON public.iga_workload_policy_bindings (workspace_id, source_key) WHERE state <> 'ended';

COMMENT ON TABLE public.iga_observed_access IS
    'An observed attempt or success. Not an iga_access_edges grant. The runtime instance must belong to the named workload.';
COMMENT ON TABLE public.iga_workload_policy_bindings IS
    'Native constraints (systemd, LSM, nftables, NetworkPolicy, POSIX ACL). Not Allow grants.';
