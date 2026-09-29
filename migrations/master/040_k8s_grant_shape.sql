-- 040_k8s_grant_shape.sql — what a Kubernetes access edge must look like.
--
-- expand only. 036 added iga_access_edges_aws_grant_chk, which states the shape
-- an AWS grant edge must have. This is the Kubernetes equivalent, written the
-- same provider-conditional way so neither provider constrains the other.
--
-- THE INVARIANT
-- A Kubernetes edge always names a holder and the binding it came through, and
-- never names a resource. The last part is the one worth stating: Kubernetes
-- RBAC grants verbs on RESOURCE TYPES ("secrets in namespace prod"), not on
-- resource instances the way an AWS policy names an ARN. There is no per-object
-- row to point at, so a k8s edge carrying resource_id would mean somebody had
-- invented one.
--
-- NEITHER entitlement_id NOR assignment_id is required, and that is deliberate
-- rather than lax. A binding whose role could not be resolved — one referencing
-- a role outside the swept scope, or one that does not exist — is written as
-- partial/unknown with neither, because:
--
--   * its entitlement is precisely what could not be resolved, and
--   * its assignment could not be written either: iga_policy_assignment.policy_id
--     is NOT NULL, so there is no row to point at.
--
-- Dropping such an edge instead would read as "no access", which is a stronger
-- claim than the truth — "something is bound to something we could not see".
-- The honesty CHECK already guarantees such a row cannot claim a conclusion, so
-- requiring the ids here would buy nothing and would reject exactly the rows
-- that record missing coverage.
--
-- (An earlier draft of this migration did require assignment_id. It would have
-- rejected every partial edge the projector is designed to produce.)

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_k8s_grant_chk;

ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_k8s_grant_chk CHECK (
        provider <> 'k8s'
        OR (subject_identity_account_id IS NOT NULL
            AND resource_id IS NULL));

-- verify ----------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'iga_access_edges_k8s_grant_chk'
    ) THEN
        RAISE EXCEPTION '040: the k8s grant-shape CHECK was not created';
    END IF;
END $$;
