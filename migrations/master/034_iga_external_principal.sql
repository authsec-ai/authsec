-- ============================================================================
-- 034: external principals, and cross-provider can_assume.
--
-- SPEC-iga-phase2-graph.md §2.12.
--
-- A GitHub Action assuming an AWS role is FULLY VISIBLE FROM THE AWS SCAN
-- ALONE: the trust policy names the issuer and the subject claim, and
-- cloud_assume_edge already carries SubjectKind, Subject, Issuer and Mechanism.
-- So the rule is: every edge is recorded by the side that DECLARES it, and the
-- far endpoint may be unresolved.
--
-- WHY A NODE AND NOT A STRING ON THE EDGE. When the far provider connects
-- later, resolution UPGRADES THE EXISTING NODE and the edge keeps its identity
-- and its whole history. A string endpoint would force delete-and-recreate,
-- destroying "this access has existed since March" -- precisely the fact a
-- reviewer needs and the one hardest to recover.
--
-- LAST IN THE SEQUENCE, deliberately: the graph is correct without it -- a
-- trust policy naming an unconnected provider simply produces no edge -- so
-- shipping it after the core path is proven keeps P2-0's slice narrow.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_external_principal (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    issuer        text NOT NULL,   -- token.actions.githubusercontent.com
    subject_claim text NOT NULL,   -- repo:org/repo:ref:refs/heads/main
    mechanism     text NOT NULL,   -- oidc | saml | aws_account | service_principal
    source_key    text NOT NULL,

    -- Filled when the far provider connects AND the claim resolves to exactly
    -- one object. Nullable forever otherwise, which is an HONEST state, not a
    -- gap to be filled with a guess.
    --
    -- TYPED, for the same reason iga_object_support is: a text kind beside a
    -- bare uuid would let a principal in workspace A "resolve" to workspace
    -- B's identity, or to an id that no longer exists. A trust policy names an
    -- identity or a workload -- nothing else can be assumed -- so two typed
    -- columns cover the domain.
    resolved_identity_account_id uuid,
    resolved_workload_id         uuid,
    resolution_basis     text NOT NULL DEFAULT '',   -- derived | asserted
    resolution_rule      text NOT NULL DEFAULT '',
    -- Who asserted it, when basis = 'asserted'. A resolution a human made must
    -- be explicable and reversible.
    resolved_by          text NOT NULL DEFAULT '',
    -- Whether the resolution currently APPLIES, separate from whether it
    -- EXISTS. A human's decision is preserved when its target is retired, but
    -- it stops being in force until someone reconfirms it -- and it never
    -- returns to active automatically.
    resolution_state     text NOT NULL DEFAULT 'active',

    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_external_principal_pkey PRIMARY KEY (id),
    CONSTRAINT iga_external_principal_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_external_principal_workspace_id_key UNIQUE (workspace_id, id),

    -- RESOLUTION IS A CLAIM, NOT A FACT. repo:org/repo:* matches every branch
    -- and tag in that repository, so an exact unambiguous match is 'derived'
    -- with its rule recorded, anything wildcarded stays unresolved and is SHOWN
    -- as unresolved, and a human confirming it is 'asserted' with the deciding
    -- authority stored.
    CONSTRAINT iga_ep_resolved_identity_fkey
        FOREIGN KEY (workspace_id, resolved_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id)
        ON DELETE SET NULL (resolved_identity_account_id),
    CONSTRAINT iga_ep_resolved_workload_fkey
        FOREIGN KEY (workspace_id, resolved_workload_id)
        REFERENCES public.iga_workload (workspace_id, id)
        ON DELETE SET NULL (resolved_workload_id),

    -- At most one target, and a basis exactly when there is a target.
    CONSTRAINT iga_external_principal_resolution_chk CHECK (
        (resolved_identity_account_id IS NOT NULL)::int
      + (resolved_workload_id         IS NOT NULL)::int <= 1
        AND ((resolved_identity_account_id IS NULL AND resolved_workload_id IS NULL)
             = (resolution_basis = ''))),
    CONSTRAINT iga_external_principal_basis_chk CHECK (
        resolution_basis IN ('', 'derived', 'asserted')),
    CONSTRAINT iga_external_principal_asserted_chk CHECK (
        resolution_basis <> 'asserted' OR resolved_by <> ''),
    CONSTRAINT iga_external_principal_state_chk CHECK (
        resolution_state IN ('active', 'suspended', 'pending_reconfirmation')),
    CONSTRAINT iga_external_principal_derived_chk CHECK (
        resolution_basis <> 'derived' OR resolution_rule <> ''),
    CONSTRAINT iga_external_principal_source_key_chk CHECK (source_key <> '')
);

-- Deleting a resolved target cannot leave "resolved" with no target: SET NULL
-- would violate the resolution CHECK. So a target is never hard-deleted while
-- resolved -- nodes are RETIRED, not deleted (§2.7). Retirement does not clear
-- the resolution: it SUSPENDS it, keeping the FK pointed at the retired row so
-- the decision stays explicable. The FK is the backstop, not the mechanism.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_external_principal_key
    ON public.iga_external_principal (workspace_id, source_key);

COMMENT ON TABLE public.iga_external_principal IS
    'The far end of a cross-provider trust, recorded by the side that declares '
    'it. Unresolved is a legitimate permanent state: we record what the trust '
    'policy said, never that the named principal exists.';

-- widen iga_relationship -----------------------------------------------------
-- The fourth typed SOURCE. Typed and FK''d like every other endpoint -- an
-- unresolved far end is still a real endpoint, not a string.
ALTER TABLE public.iga_relationship
    ADD COLUMN IF NOT EXISTS source_external_principal_id uuid;

ALTER TABLE public.iga_relationship
    ADD CONSTRAINT iga_rel_src_external_fkey
        FOREIGN KEY (workspace_id, source_external_principal_id)
        REFERENCES public.iga_external_principal (workspace_id, id) ON DELETE CASCADE;

-- Exactly-one-source, now over four columns. Dropped and re-added rather than
-- edited: a CHECK cannot be altered in place.
ALTER TABLE public.iga_relationship
    DROP CONSTRAINT iga_relationship_source_chk,
    ADD CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id   IS NOT NULL)::int
      + (source_workload_id           IS NOT NULL)::int
      + (source_agent_instance_id     IS NOT NULL)::int
      + (source_external_principal_id IS NOT NULL)::int = 1);

-- The legal-pair CHECK, with can_assume widened. The ELSE false arm stays
-- exactly as load-bearing as it was: this widening is the deliberate review
-- point the arm exists to force.
ALTER TABLE public.iga_relationship
    DROP CONSTRAINT iga_relationship_pair_chk,
    ADD CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as' THEN
                source_workload_id IS NOT NULL
                AND target_identity_account_id IS NOT NULL
            WHEN 'can_assume' THEN
                -- Either one of OUR identities, or an external principal a
                -- trust policy names. Both are legitimate assumption sources.
                (source_identity_account_id IS NOT NULL
                 OR source_external_principal_id IS NOT NULL)
                AND target_identity_account_id IS NOT NULL
            WHEN 'realizes' THEN
                source_agent_instance_id IS NOT NULL
                AND target_workload_id IS NOT NULL
            ELSE false
        END);

-- The source index has to know about the fourth column, or an external-
-- principal edge is invisible to it.
DROP INDEX IF EXISTS public.idx_iga_relationship_source;
CREATE INDEX IF NOT EXISTS idx_iga_relationship_source
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(source_identity_account_id, source_workload_id,
                 source_agent_instance_id, source_external_principal_id));

-- verify ---------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM information_schema.tables
      WHERE table_name = 'iga_external_principal')                      AS table_created,
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'iga_relationship'
        AND column_name = 'source_external_principal_id')               AS fourth_source,
    (SELECT pg_get_constraintdef(oid) LIKE '%source_external_principal_id%'
       FROM pg_constraint WHERE conname = 'iga_relationship_source_chk') AS source_chk_widened,
    (SELECT pg_get_constraintdef(oid) LIKE '%source_external_principal_id%'
       FROM pg_constraint WHERE conname = 'iga_relationship_pair_chk')   AS pair_chk_widened;
