-- 038_k8s_graph_provider.sql — Kubernetes joins the shared IGA graph.
--
-- expand only. SPEC-iga-phase2-graph.md §1.5 states the graph model is
-- provider-neutral "so they can project into it later" and names Kubernetes
-- explicitly. This is that: no new tables, no new columns, only two widened
-- CHECKs so the Kubernetes vocabulary can be written into the columns that
-- already exist.
--
-- WHY THE CHECKS NEEDED WIDENING AT ALL
-- iga_policy.policy_kind and iga_policy_assignment.assignment_kind were closed
-- to the AWS vocabulary ('aws_managed'/'customer_managed'/'inline' and
-- 'attached'/'inline'/'boundary'). A Kubernetes Role is none of those, and
-- forcing one into 'inline' would lose the distinction between a namespaced
-- Role and a cluster-scoped ClusterRole — which is the whole difference between
-- access in one namespace and access everywhere.
--
-- The provider column itself is NOT check-constrained, so 'k8s' needs nothing.
--
-- WHAT IS DELIBERATELY NOT HERE
-- No iga_agents or iga_agent_instances rows are ever written for Kubernetes, and
-- nothing in this migration enables that. The Kubernetes bridge
-- (services/iga_bridge_service.go) matches every discovered sighting against all
-- active iga_agents by normalised display name; rows written by a projector
-- would fabricate self-correlations and break genuine ones by making the match
-- ambiguous. AWS avoids this for the same reason (§2.2, E16).

-- iga_policy.policy_kind ------------------------------------------------------
ALTER TABLE public.iga_policy
    DROP CONSTRAINT IF EXISTS iga_policy_kind_chk;

ALTER TABLE public.iga_policy
    ADD CONSTRAINT iga_policy_kind_chk CHECK (
        policy_kind IN (
            -- AWS, unchanged.
            'aws_managed', 'customer_managed', 'inline',
            -- Kubernetes. Namespaced and cluster-scoped are distinct kinds
            -- because they are distinct objects that may share a name.
            'k8s_role', 'k8s_cluster_role'
        ));

-- iga_policy_assignment.assignment_kind ---------------------------------------
ALTER TABLE public.iga_policy_assignment
    DROP CONSTRAINT IF EXISTS iga_pa_kind_chk;

ALTER TABLE public.iga_policy_assignment
    ADD CONSTRAINT iga_pa_kind_chk CHECK (
        assignment_kind IN (
            -- AWS, unchanged.
            'attached', 'inline', 'boundary',
            -- Kubernetes. A RoleBinding may reference a ClusterRole, so the
            -- binding's own scope is what this records — not the role's.
            'k8s_role_binding', 'k8s_cluster_role_binding'
        ));

-- verify ----------------------------------------------------------------------
-- Both constraints must exist and must accept the Kubernetes vocabulary.
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n
      FROM pg_constraint
     WHERE conname IN ('iga_policy_kind_chk', 'iga_pa_kind_chk');
    IF n <> 2 THEN
        RAISE EXCEPTION '038: expected both kind CHECKs to exist, found %', n;
    END IF;
END $$;
