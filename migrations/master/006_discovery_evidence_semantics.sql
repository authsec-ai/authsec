-- 006_discovery_evidence_semantics.sql
--
-- AS-108. Separate "we saw evidence of this agent" from "we saw this agent
-- RUN", so a parsed file can enter the existing inventory without the product
-- asserting something it does not know.
--
-- WHY THIS MIGRATION EXISTS
--
-- discovered_agents was built for the Kubernetes admission collector, where the
-- contract is "a sighting means it is running": last_seen_at reads as "this
-- process existed at this time", and staleness reads as "not seen recently,
-- therefore possibly stopped".
--
-- A GitHub workflow file is a DECLARATION. It might run tonight. It might be
-- dead code from eighteen months ago. It might sit in a repository nobody has
-- merged to since 2024. Writing it into a table that means "running", stamped
-- with a last-seen of two minutes ago, makes the product state something it
-- cannot support -- and on screen "nightly-audit | 2 min ago" reads as a live
-- process to every human who sees it. It is a file.
--
-- Two columns fix that honestly:
--   evidence_mode            -- HOW we know: observed | declared | inferred
--   last_observed_running_at -- WHEN it last ran, and NULL when we never saw it
--
-- The NULL is not missing data. For a declared row it is the correct and
-- permanent answer, and any UI element implying liveness must read that column
-- and never last_seen_at.
--
-- Forward-only, idempotent, and the backfill is part of the migration rather
-- than a follow-up script someone forgets.

BEGIN;

-- ---------------------------------------------------------------------------
-- evidence_mode: how we know this agent exists.
-- ---------------------------------------------------------------------------
-- Defaulted to 'observed' because every row that exists TODAY came from the
-- Kubernetes admission webhook, which genuinely observed a running workload.
-- Backfilling those to anything else would understate what we actually saw.
ALTER TABLE public.discovered_agents
    ADD COLUMN IF NOT EXISTS evidence_mode text NOT NULL DEFAULT 'observed';

-- ---------------------------------------------------------------------------
-- last_observed_running_at: when we last saw it RUN. NULL means never.
-- ---------------------------------------------------------------------------
-- Deliberately nullable with no default. A default would manufacture a runtime
-- observation for rows that never had one, which is the exact lie this
-- migration exists to prevent.
ALTER TABLE public.discovered_agents
    ADD COLUMN IF NOT EXISTS last_observed_running_at timestamptz;

-- ---------------------------------------------------------------------------
-- Backfill, in the same migration.
-- ---------------------------------------------------------------------------
-- Existing rows: everything already in the table is a runtime sighting from a
-- collector, so its evidence mode is 'observed' and its runtime timestamp is
-- the last time we saw it. repo_scan rows are the exception -- they are
-- declarations, and the earlier code path stamped them 'automated' before this
-- was understood, so they are corrected here too.
UPDATE public.discovered_agents
   SET evidence_mode            = 'observed',
       last_observed_running_at = COALESCE(last_observed_running_at, last_seen_at)
 WHERE source <> 'repo_scan'
   AND last_observed_running_at IS NULL;

UPDATE public.discovered_agents
   SET evidence_mode            = 'declared',
       last_observed_running_at = NULL,
       -- A declaration establishes only that someone wrote the agent down, not
       -- how (or whether) it reached an environment.
       deployment_origin        = 'unknown'
 WHERE source = 'repo_scan';

-- ---------------------------------------------------------------------------
-- Constraints
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'discovered_agents_evidence_mode_check'
    ) THEN
        ALTER TABLE public.discovered_agents
            ADD CONSTRAINT discovered_agents_evidence_mode_check
            CHECK (evidence_mode IN ('observed', 'declared', 'inferred'));
    END IF;
END $$;

-- The invariant that keeps the product honest, enforced in the DATABASE rather
-- than left to every future call site: a DECLARED row can never carry a runtime
-- observation, because nothing about reading a file establishes that it ran.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'discovered_agents_declared_never_running_check'
    ) THEN
        ALTER TABLE public.discovered_agents
            ADD CONSTRAINT discovered_agents_declared_never_running_check
            CHECK (evidence_mode <> 'declared' OR last_observed_running_at IS NULL);
    END IF;
END $$;

-- The second half of the same invariant, and the one a service-layer guard
-- cannot cover on its own.
--
-- The scanner emits 'unknown' correctly, but three other routes could still
-- land or leave 'automated' on a declared row: a caller passing it explicitly,
-- the ON CONFLICT refresh on a rescan while the row is still unregistered, and
-- an operator PATCH through UpdateAgent. Each would reproduce the original
-- defect -- a file presented as an automated deployment -- from a different
-- direction. A CHECK closes all three at once, permanently.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'discovered_agents_declared_never_automated_check'
    ) THEN
        ALTER TABLE public.discovered_agents
            ADD CONSTRAINT discovered_agents_declared_never_automated_check
            CHECK (evidence_mode <> 'declared' OR deployment_origin <> 'automated');
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
-- Staleness branches on evidence mode -- a workflow file untouched for six
-- months is STABLE, a pod unseen for six months is GONE -- so every staleness
-- query filters on mode before it filters on time.
CREATE INDEX IF NOT EXISTS idx_discovered_agents_evidence_mode
    ON public.discovered_agents(workspace_id, evidence_mode, last_seen_at);

-- The runtime column, for "what is actually running right now" reads. Partial,
-- because declared rows are permanently NULL here and indexing them is waste.
CREATE INDEX IF NOT EXISTS idx_discovered_agents_observed_running
    ON public.discovered_agents(workspace_id, last_observed_running_at)
 WHERE last_observed_running_at IS NOT NULL;

COMMIT;
