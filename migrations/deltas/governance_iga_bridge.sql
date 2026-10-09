-- ============================================================================
-- Forward delta: bridge the k8s runtime inventory to the correlated IGA estate.
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_iga_bridge.sql
--
-- Depends on the iga_* schema (iga_agents) and on discovered_agents.
--
-- WHY THIS EXISTS
-- Two agent models now coexist in this service, built independently and both
-- legitimate:
--
--   discovered_agents  the k8s RUNTIME channel. One row per workload actually
--                      observed running, keyed by a stable fingerprint, carrying
--                      runtime lifecycle and the claim/quarantine decisions.
--   iga_agents         the CORRELATED estate. One row per logical agent across
--                      every channel, carrying classification, ownership and
--                      rollup state.
--
-- They answer different questions ("what is running in this cluster right now?"
-- versus "what agents does this organisation have?"), so neither subsumes the
-- other. What was missing was the join.
--
-- WHY A TABLE AND NOT A COLUMN
-- A link is a claim about identity that can be wrong, so it needs its own state,
-- its own evidence, and its own decision record. As columns on discovered_agents
-- it would also be corruptible: an FK with ON DELETE SET NULL would null the id
-- while leaving state='accepted', and the CHECK enforcing that pairing would then
-- make deleting an iga_agents row fail outright. A table with ON DELETE CASCADE
-- on both sides cannot reach an invalid state.
--
-- WHY IT ONLY EVER PROPOSES
-- There is NO shared identifier between the two models. iga_agents is canonical
-- with no fingerprint; iga_identity_accounts is canonical with no client
-- reference; native keys live in iga_source_objects behind iga_correlations. The
-- only field both sides share is a display name, which is weak evidence.
--
-- So this deliberately mirrors iga_correlations_weak_chk: a weak join may be
-- proposed automatically but can only become 'accepted' with a recorded human
-- decision. Auto-accepting a name match would invent a correlation, which is
-- exactly the failure that constraint exists to prevent.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.discovered_agent_iga_links (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    discovered_agent_id uuid NOT NULL,
    iga_agent_id        uuid NOT NULL,

    -- The evidence. Recorded so a reviewer can see WHY this was proposed rather
    -- than being asked to trust it: an unexplained proposal is one a reviewer can
    -- only rubber-stamp.
    join_key text NOT NULL DEFAULT '',
    strength text NOT NULL DEFAULT 'weak',

    state      text NOT NULL DEFAULT 'proposed',
    decided_by uuid,
    decided_at timestamptz,

    -- Optimistic concurrency, matching the iga_* decision routes: a decision
    -- carrying a stale version is rejected rather than silently winning.
    version bigint NOT NULL DEFAULT 1,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT discovered_agent_iga_links_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agent_iga_links_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- CASCADE on both sides: if either entity goes, the claim that they are the
    -- same thing is meaningless. This is what makes an invalid state
    -- unrepresentable rather than merely unlikely.
    CONSTRAINT discovered_agent_iga_links_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_iga_links_iga_fkey FOREIGN KEY (workspace_id, iga_agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,

    CONSTRAINT discovered_agent_iga_links_strength_chk CHECK (strength IN ('strong', 'weak')),
    CONSTRAINT discovered_agent_iga_links_state_chk CHECK (
        state IN ('proposed', 'accepted', 'rejected')),
    -- Mirrors iga_correlations_weak_chk. A weak join that claims accepted status
    -- without a decision is a bug, not a shortcut.
    CONSTRAINT discovered_agent_iga_links_weak_chk CHECK (
        state <> 'accepted' OR strength = 'strong' OR decided_by IS NOT NULL),
    -- A decision must say when it happened, or it cannot be reasoned about later.
    CONSTRAINT discovered_agent_iga_links_decided_chk CHECK (
        state = 'proposed' OR decided_at IS NOT NULL),

    -- One link per discovered agent: a k8s workload is one logical agent, or none.
    -- Re-proposing therefore updates in place rather than accumulating rows, and
    -- the repository refuses to overwrite a link that has already been DECIDED --
    -- so a rejected link stays rejected instead of being re-proposed on every
    -- sighting.
    CONSTRAINT discovered_agent_iga_links_agent_key UNIQUE (workspace_id, discovered_agent_id)
);

-- The reverse join: "which running workloads are believed to be this agent?"
CREATE INDEX IF NOT EXISTS idx_discovered_agent_iga_links_iga
    ON public.discovered_agent_iga_links(workspace_id, iga_agent_id);

-- A reviewer's queue: proposals still awaiting a decision.
CREATE INDEX IF NOT EXISTS idx_discovered_agent_iga_links_proposed
    ON public.discovered_agent_iga_links(workspace_id) WHERE state = 'proposed';

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.discovered_agent_iga_links') AS bridge_table,
       (SELECT count(*) FROM pg_constraint
         WHERE conrelid = 'public.discovered_agent_iga_links'::regclass
           AND contype = 'c') AS check_constraints;
