-- 012_cloud_assume_edge.sql
--
-- Ticket [2] of AWS cloud discovery: who may become each identity.
--
-- WHY THIS TABLE. cloud_identity says what code runs as. cloud_assume_edge says
-- who is allowed to become it -- an AWS service, another IAM identity, a
-- Kubernetes service account via IRSA, a GitHub Actions workflow, or another
-- account. That is where the trust-policy read earns its keep: a role with a
-- broad IAM policy is only as safe as the list of things that can assume it.
--
-- WHY IT ALSO CARRIES THE KUBERNETES JOIN. The shared cross-cloud note is
-- explicit that this is the same mechanism: IRSA assumption and the AWS side of
-- "which pod can reach this role" are both a Federated principal on a trust
-- policy, differing only in which OIDC subject shows up. Modelling them as two
-- tables would split one relationship in half for no reason.
--
-- WHY subject_kind HAS FIVE VALUES AND THE TICKET TEXT NAMES FOUR. Ticket [2]'s
-- scope says "AWS service, IRSA Kubernetes subject, GitHub CI subject, or
-- another account". The shared schema note is the more precise source of truth
-- and splits "another account" in two: a Principal.AWS naming a SPECIFIC role
-- or user ARN is `identity` (a known principal, possibly in this account or
-- another), while a bare account id, an account root ARN, or "*" is
-- `external_account` (anyone in that account, or anyone at all). Collapsing
-- them would make "arn:aws:iam::999:role/known-role" and "*" read identically,
-- which is exactly the distinction a reviewer of this table needs.
--
-- WHY mechanism HAS TWO VALUES, NOT FOUR. It describes HOW the assumption
-- happens, not WHO is assuming. AWS has exactly two: a plain trust-policy
-- principal using sts:AssumeRole (`sts_assume_role` -- covers the cloud_service,
-- identity and external_account subject kinds), and a Federated principal using
-- sts:AssumeRoleWithWebIdentity (`oidc_federation` -- covers BOTH
-- k8s_service_account and ci_pipeline, which are the same AWS mechanism and are
-- told apart by subject_kind and issuer, not by mechanism).
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction -- so there is deliberately no BEGIN/COMMIT here.

CREATE TABLE IF NOT EXISTS public.cloud_assume_edge (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The identity being assumed.
    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,

    subject_kind text NOT NULL,

    -- The provider's own string, stored verbatim, never normalised. For a
    -- cloud_service this is a service principal ("lambda.amazonaws.com"); for
    -- an identity, the principal ARN; for external_account, the account id,
    -- root ARN or "*"; for k8s_service_account and ci_pipeline, the OIDC
    -- subject claim.
    subject text NOT NULL,

    -- OIDC issuer host, no scheme (matches the ARN's oidc-provider/<host>
    -- suffix). NULL for sts_assume_role edges, which have no issuer.
    -- Disambiguates two EKS clusters presenting the same namespace and service
    -- account name in their subject claim.
    issuer text,

    mechanism text NOT NULL,

    -- Set ONLY for k8s_service_account. Format: system:serviceaccount:<ns>:<sa>
    -- -- the exact string the Kubernetes connector already records for the same
    -- pod, so the join needs no translation on either side.
    k8s_ref text,

    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Reconciliation, identical in shape to cloud_identity and cloud_secret.
    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_assume_edge_subject_kind_chk CHECK (
        subject_kind IN ('cloud_service', 'identity', 'k8s_service_account',
                          'ci_pipeline', 'external_account')
    ),
    CONSTRAINT cloud_assume_edge_mechanism_chk CHECK (
        mechanism IN ('sts_assume_role', 'oidc_federation')
    ),
    CONSTRAINT cloud_assume_edge_subject_chk CHECK (subject <> ''),
    -- A k8s_service_account edge without its subject-account-format ref is a
    -- broken join: the whole reason this subject kind exists is so the
    -- Kubernetes connector can match on k8s_ref byte-for-byte.
    CONSTRAINT cloud_assume_edge_k8s_ref_chk CHECK (
        subject_kind <> 'k8s_service_account' OR k8s_ref IS NOT NULL
    ),
    CONSTRAINT cloud_assume_edge_generation_chk CHECK (last_seen_generation >= 0)
);

-- One edge per (identity, subject) pair. A trust policy naming the same
-- principal twice, or a re-scan of an unchanged policy, updates this row
-- rather than duplicating it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_assume_edge_subject
    ON public.cloud_assume_edge (identity_id, subject_kind, subject);

-- The scan's own reconciliation query.
CREATE INDEX IF NOT EXISTS idx_cloud_assume_edge_connector_generation
    ON public.cloud_assume_edge (connector_id, last_seen_generation);

-- The EKS ticket's join query: find the AWS role for a given Kubernetes
-- namespace/service-account/cluster-issuer triple.
CREATE INDEX IF NOT EXISTS idx_cloud_assume_edge_k8s_ref
    ON public.cloud_assume_edge (k8s_ref, issuer) WHERE k8s_ref IS NOT NULL;

-- The console's list query: everything that may assume one identity.
CREATE INDEX IF NOT EXISTS idx_cloud_assume_edge_identity
    ON public.cloud_assume_edge (identity_id);
