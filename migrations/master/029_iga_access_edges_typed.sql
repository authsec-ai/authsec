-- ============================================================================
-- 029: iga_access_edges gets a typed subject, a required entitlement, a
-- lifecycle, and stored partition membership.
--
-- SPEC-iga-phase2-graph.md §2.2, §2.7, §4.10.
--
-- A3, RESTATED. The entitlement and resource ends of this table were already
-- composite-FK'd to (workspace_id, id). The SUBJECT end was subject_kind text
-- + subject_id uuid with NO FOREIGN KEY OF ANY KIND (004:694) -- so a subject
-- could name a row in another workspace, or a row that does not exist, and
-- nothing would notice. This migration closes it the way 022:74 already proved
-- works: nullable typed FK columns plus an exactly-one CHECK. Adding a further
-- subject type later costs one migration that adds a column and widens two
-- constraints.
--
-- entitlement_id BECOMES NOT NULL. An access edge that grants nothing is not a
-- fact about access.
--
-- THERE IS NO subject_workload_id, deliberately. A workload does not hold an
-- entitlement; it executes AS an identity that does. That path is
-- iga_relationship(executes_as) then iga_access_edges, and keeping it two hops
-- is the point -- an inbound permission never implies an outbound one.
--
-- Nothing foreign-keys iga_access_edges (the only references in the migrations
-- are two of its own indexes), and it has exactly one writer and one reader,
-- so it can be rewritten in place.
-- ============================================================================

-- new columns ----------------------------------------------------------------
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS subject_identity_account_id uuid,
    ADD COLUMN IF NOT EXISTS subject_agent_id            uuid,
    ADD COLUMN IF NOT EXISTS subject_agent_instance_id   uuid,

    ADD COLUMN IF NOT EXISTS basis             text NOT NULL DEFAULT 'declared',
    ADD COLUMN IF NOT EXISTS derivation_rule   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS state             text NOT NULL DEFAULT 'current',
    ADD COLUMN IF NOT EXISTS valid_from        timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_to          timestamptz,
    ADD COLUMN IF NOT EXISTS last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_confirmed_by uuid,
    ADD COLUMN IF NOT EXISTS ended_reason      text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key        text NOT NULL DEFAULT '',

    -- PARTITION MEMBERSHIP (§4.10). Reconciliation selects the rows it is
    -- responsible for by these two columns and nothing else. An edge written
    -- without them is invisible to reconciliation and NEVER ENDS, EVER.
    --
    -- Membership is stored rather than inferred because every join-based
    -- alternative was wrong: filtering on (workspace_id, relationship_type)
    -- ends another ACCOUNT's edges; adding estate_scope_id still crosses
    -- regions and connectors; and an endpoint union silently omits any
    -- endpoint type it forgets to enumerate.
    --
    -- Edges keep a SINGLE membership, unlike nodes (§2.10B): an access edge's
    -- subject is an identity in one account, so it has exactly one supporting
    -- source and a support table would be ceremony.
    ADD COLUMN IF NOT EXISTS partition_key text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS connector_id  uuid;

-- backfill -------------------------------------------------------------------
-- The only writer ever set subject_kind = 'identity_account'
-- (services/iga_service.go:918), so this is the whole conversion.
UPDATE public.iga_access_edges
   SET subject_identity_account_id = subject_id
 WHERE subject_kind = 'identity_account'
   AND subject_identity_account_id IS NULL;

-- Rows that cannot satisfy the new shape are rebuildable projection rows with
-- no review decisions attached and nothing foreign-keying to them, so deleting
-- them is safe -- but the counts must be REPORTED, not swallowed. A large
-- number here means the GitHub path was writing something this migration did
-- not anticipate, and that is worth knowing before the projector runs.
DO $$
DECLARE n bigint;
BEGIN
    DELETE FROM public.iga_access_edges e
     WHERE e.subject_identity_account_id IS NULL
        OR e.entitlement_id IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM public.iga_identity_accounts a
             WHERE a.workspace_id = e.workspace_id
               AND a.id = e.subject_identity_account_id);
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE 'iga_access_edges: deleted % rows that cannot be typed', n;
END $$;

-- constraints ----------------------------------------------------------------
ALTER TABLE public.iga_access_edges
    ALTER COLUMN entitlement_id SET NOT NULL;

ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_subject_identity_fkey
        FOREIGN KEY (workspace_id, subject_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_subject_agent_fkey
        FOREIGN KEY (workspace_id, subject_agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_subject_instance_fkey
        FOREIGN KEY (workspace_id, subject_agent_instance_id)
        REFERENCES public.iga_agent_instances (workspace_id, id) ON DELETE CASCADE,

    -- §2.9: workspace-qualified, against the UNIQUE 026 added. A bare FK here
    -- would admit another workspace's scan run as this edge's provenance --
    -- the same defect class this table is being rewritten to close.
    ADD CONSTRAINT iga_access_edges_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_by),

    ADD CONSTRAINT iga_access_edges_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id)
        ON DELETE SET NULL (connector_id),

    ADD CONSTRAINT iga_access_edges_subject_chk2 CHECK (
        (subject_identity_account_id IS NOT NULL)::int
      + (subject_agent_id            IS NOT NULL)::int
      + (subject_agent_instance_id   IS NOT NULL)::int = 1),

    ADD CONSTRAINT iga_access_edges_basis_chk CHECK (
        basis IN ('declared', 'observed', 'derived', 'asserted')),
    -- A derived claim must name the rule that derived it, or it is an
    -- assertion wearing a better word.
    ADD CONSTRAINT iga_access_edges_derivation_chk CHECK (
        basis <> 'derived' OR derivation_rule <> ''),
    ADD CONSTRAINT iga_access_edges_state_chk CHECK (
        state IN ('current', 'stale', 'ended')),
    ADD CONSTRAINT iga_access_edges_ended_chk CHECK (
        (state = 'ended') = (valid_to IS NOT NULL)),
    ADD CONSTRAINT iga_access_edges_ended_reason_chk CHECK (
        (state = 'ended') = (ended_reason <> ''));

-- drop the polymorphic pair --------------------------------------------------
-- The index goes first: it names subject_kind, so the DROP COLUMN would fail.
-- iga_access_edges_subject_chk is the subject_kind ENUM check from 004, which
-- becomes meaningless the moment the column it constrains is gone.
--
-- iga_access_edges_honesty_chk from 004 MUST SURVIVE this. It constrains
-- effective_conclusion against calculation_state and touches none of these
-- columns, so ADD/DROP COLUMN leaves it intact -- the verify block below
-- asserts that rather than trusting it.
DROP INDEX IF EXISTS public.idx_iga_access_edges_subject;

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_subject_chk,
    DROP COLUMN IF EXISTS subject_kind,
    DROP COLUMN IF EXISTS subject_id;

-- indexes --------------------------------------------------------------------
-- Partial on state <> 'ended' so history accumulates while only ONE edge per
-- grant is live. Ended rows are never deleted: a review decision made last
-- quarter must stay explicable against the access that existed then.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_access_edges_live
    ON public.iga_access_edges (workspace_id, source_key)
    WHERE source_key <> '' AND state <> 'ended';

CREATE INDEX IF NOT EXISTS idx_iga_access_edges_subject_identity
    ON public.iga_access_edges (workspace_id, subject_identity_account_id, direction)
    WHERE subject_identity_account_id IS NOT NULL;

-- The predicate reconciliation actually selects on (§4.10 scope()).
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_partition
    ON public.iga_access_edges (workspace_id, connector_id, partition_key)
    WHERE state <> 'ended';

COMMENT ON COLUMN public.iga_access_edges.partition_key IS
    'Partition.Key() -- the same value iga_projection_state is keyed on, so '
    '"what this run reconciles" and "what this run recorded a watermark for" '
    'are the same set by construction rather than two predicates that have to '
    'be kept in agreement. An edge with an empty partition_key is invisible to '
    'reconciliation and will never end.';

COMMENT ON COLUMN public.iga_access_edges.state IS
    'current = a recent authoritative read confirmed it. stale = we could not '
    'look; still believed, with its last confirmation time shown. ended = an '
    'authoritative read of the owning scope and class did not see it. '
    'Collapsing stale into ended lets a permissions outage read as a cleanup.';

-- verify ---------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'iga_access_edges'
        AND column_name IN ('subject_kind', 'subject_id'))        AS polymorphic_cols_remaining,
    (SELECT count(*) FROM pg_constraint
      WHERE conname = 'iga_access_edges_honesty_chk')             AS honesty_chk_survived,
    (SELECT count(*) FROM pg_constraint
      WHERE conname = 'iga_access_edges_subject_chk2')            AS typed_subject_chk,
    (SELECT a.attnotnull FROM pg_attribute a
      WHERE a.attrelid = 'public.iga_access_edges'::regclass
        AND a.attname = 'entitlement_id')                         AS entitlement_not_null;
