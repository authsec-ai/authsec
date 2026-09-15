-- ============================================================================
-- Forward delta: the enforcement plan (phase 4 of ENFORCEMENT-ARCHITECTURE.md §7).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_enforcement_plan.sql
--
-- Depends on discovery_agent_registration_lifecycle.sql and
-- governance_agent_policies.sql.
--
-- WHAT THIS IS
-- The document the in-cluster agent polls, and the record of what it reported back.
--
-- The control plane originates no connection into a customer cluster (EN-0), so a
-- quarantine decision reaches the cluster exactly one way: the agent asks, on its
-- existing actuation interval, and is handed a whole plan. The plan is an explicit
-- list of fingerprints (EN-3) -- never a predicate -- so a detection bug can widen
-- the list but can never widen what the agent evaluates.
--
-- WHY THE PLAN IS PERSISTED AT ALL
-- It could be computed on demand and thrown away. Storing it makes "what was this
-- cluster enforcing at 03:00 on Tuesday" answerable from a row instead of
-- reconstructed from the state that has since changed -- which is the question asked
-- after a workload was blocked and nobody can say why.
--
-- THIS DELTA IS INERT ON ITS OWN. It creates a table and four columns. The agent
-- that reads the plan ships in mode=observe (EN-10): it counts what it WOULD have
-- denied and allows everything.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- enforcement_plans ---------------------------------------------------------
-- One row per PUBLISHED version, per connector. A poll that finds the plan
-- unchanged does not mint a row: version is bumped by content, not by traffic, or
-- a 30-second poll would produce 2,880 identical rows a day and make the version
-- number meaningless as a change signal.
CREATE TABLE IF NOT EXISTS public.enforcement_plans (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    -- WHICH CLUSTER. The plan is per-connector, so one cluster's plan can never
    -- contain another's fingerprints -- the property that makes a leaked actuation
    -- token bounded to the cluster it was minted for.
    discovery_source_id uuid NOT NULL,

    -- Monotonic per connector. The agent reports the version it is enforcing, and
    -- the difference between this and that IS the enforcement gap.
    version bigint NOT NULL,

    -- The document that was served. Stored rather than regenerated because the
    -- point of keeping it is to answer what was served, which a regeneration from
    -- today's state cannot do. jsonb rather than json so it stays QUERYABLE --
    -- "which clusters were ever told to contain this fingerprint" is one scan --
    -- at the cost of normalised key order, which no reader depends on.
    plan jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Content hash over the deny list, so an unchanged plan is recognised without
    -- comparing jsonb documents. Cheap equality on every poll.
    content_hash text NOT NULL DEFAULT '',

    generated_at timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT enforcement_plans_pkey PRIMARY KEY (id),
    CONSTRAINT enforcement_plans_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT enforcement_plans_source_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE CASCADE,
    -- Monotonicity is enforced here, not in application code. Two agent replicas
    -- polling at the same instant both compute version N+1; one insert wins and the
    -- loser re-reads. Without this the two would publish divergent plans under one
    -- version number.
    CONSTRAINT enforcement_plans_version_key UNIQUE (discovery_source_id, version),
    CONSTRAINT enforcement_plans_version_chk CHECK (version > 0)
);

CREATE INDEX IF NOT EXISTS idx_enforcement_plans_latest
    ON public.enforcement_plans(discovery_source_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_enforcement_plans_workspace
    ON public.enforcement_plans(workspace_id, generated_at DESC);

-- discovery_sources: what the cluster reports back -------------------------
-- These are OBSERVATIONS, not configuration. enforcement_mode is what the agent
-- says it is running, read off its own flag -- not a setting the console pushes,
-- because there is no channel to push one (EN-0) and a stored intent that the
-- cluster has not adopted would read as though it had.
ALTER TABLE public.discovery_sources
    -- '' means the agent has never reported; it predates enforcement, or the
    -- actuation role is off. Distinct from 'observe', which is a live agent
    -- explicitly enforcing nothing.
    ADD COLUMN IF NOT EXISTS enforcement_mode text NOT NULL DEFAULT '',
    -- The version the cluster is ACTUALLY enforcing. NULL until it reports one.
    ADD COLUMN IF NOT EXISTS enforced_plan_version bigint,
    ADD COLUMN IF NOT EXISTS enforced_plan_at timestamptz,
    -- Cumulative since the agent process started, so it resets on restart. Read as
    -- a rate and a liveness signal, never as an all-time total.
    ADD COLUMN IF NOT EXISTS enforcement_denials_total bigint NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'discovery_sources_enf_mode_chk'
    ) THEN
        ALTER TABLE public.discovery_sources
            ADD CONSTRAINT discovery_sources_enf_mode_chk CHECK (
                enforcement_mode IN ('', 'observe', 'evict', 'deny'));
    END IF;
END $$;

-- The console's "which clusters are behind?" query: every connector whose reported
-- version trails the plan it was last served. Partial, because a cluster that has
-- never reported is a different problem with a different answer.
CREATE INDEX IF NOT EXISTS idx_discovery_sources_enforcing
    ON public.discovery_sources(workspace_id, enforced_plan_at DESC)
    WHERE enforcement_mode <> '';
