-- ============================================================================
-- Forward delta: connector self-registration + agent runtime lifecycle.
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f discovery_agent_registration_lifecycle.sql
--
-- Fixes two gaps in agent discovery:
--
--   1. SELF-REGISTRATION. A single control plane serves discovery agents in many
--      clusters, but nothing represented "the agent installed in cluster X".
--      Cluster identity existed only inside each sighting's metadata jsonb, so
--      there was no way to list connected clusters, see their agent versions, or
--      tell a live agent from one that stopped reporting a week ago.
--      discovery_sources is extended to be that record: the agent upserts itself
--      on startup and heartbeats, and gets its source id back so every sighting
--      it reports carries a real discovery_source_id FK.
--
--   2. RUNTIME LIFECYCLE. Sightings only ever said "this exists". A deleted
--      workload left a row that looked identical to a running one forever.
--      discovered_agents gains an OBSERVED runtime_status, deliberately separate
--      from the governance `status` column, plus discovered_agent_events as the
--      durable "who deleted it, when, and how we know" trail.
--
-- The two status axes are orthogonal and must stay that way:
--   status         -- what a HUMAN decided (unregistered/registered/quarantined/
--                     ignored). Forward-only. Untouched by this delta.
--   runtime_status -- what we OBSERVED (running/stopped/gone/unknown). Machine-
--                     written, moves both ways.
-- An agent that was claimed and then deleted must stay `registered` (the audit
-- trail is the whole point) while its runtime_status becomes `gone`.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- 1. discovery_sources -- the self-registered connector instance ------------
--
-- instance_id is the stable upsert key the agent asserts. For the Kubernetes
-- connector it is derived from cluster.name, which is ALREADY part of every
-- agent fingerprint -- so if an operator renames the cluster, the connector row
-- re-mints exactly when the agent rows do. Keying on display_name instead would
-- break the moment an admin renamed the connector in the console.
ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS instance_id       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cluster_name      text NOT NULL DEFAULT '',
    -- Corroborating fact, not a key: the kube-system namespace UID, which is
    -- immutable per cluster. Lets the control plane detect two DIFFERENT clusters
    -- accidentally installed with the same cluster.name (same instance_id, new
    -- uid). Empty when the agent lacks the RBAC to read it, which is the default.
    ADD COLUMN IF NOT EXISTS cluster_uid       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS agent_version     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz,
    -- Distinguishes a row an agent created for itself from one an admin
    -- configured in the console. A self-registered row is machine-owned: the
    -- next heartbeat overwrites its runtime fields.
    ADD COLUMN IF NOT EXISTS self_registered   boolean NOT NULL DEFAULT false,
    -- Last reported runtime snapshot: pod/node identity, resolved config, and
    -- counters. Observability only -- nothing reads it to make a decision, so it
    -- stays schemaless on purpose.
    ADD COLUMN IF NOT EXISTS runtime           jsonb NOT NULL DEFAULT '{}'::jsonb;

-- The self-registration upsert target. PARTIAL so it constrains only
-- self-registered rows: admin-created connectors keep instance_id='' and any
-- number of them may coexist, which a plain UNIQUE would forbid.
CREATE UNIQUE INDEX IF NOT EXISTS discovery_sources_instance_key
    ON public.discovery_sources(workspace_id, kind, instance_id)
    WHERE instance_id <> '';

-- Answers "which clusters are reporting right now?" without a full scan.
CREATE INDEX IF NOT EXISTS idx_discovery_sources_heartbeat
    ON public.discovery_sources(workspace_id, last_heartbeat_at DESC);

-- 2. discovered_agents -- observed runtime state ----------------------------
ALTER TABLE public.discovered_agents
    -- 'unknown' is the honest default for every row that predates this delta:
    -- we have never observed their lifecycle, and backfilling 'running' would
    -- assert something we do not know.
    ADD COLUMN IF NOT EXISTS runtime_status        text NOT NULL DEFAULT 'unknown',
    -- Why runtime_status holds its current value, in the agent's words
    -- ("deleted by alice@corp via Deployment DELETE", "absent from a complete
    -- resync sweep"). Displayed verbatim; a reviewer should never have to guess.
    ADD COLUMN IF NOT EXISTS runtime_reason        text NOT NULL DEFAULT '',
    -- Observation time of the event that last set runtime_status -- NOT the time
    -- we received it. This is the monotonic guard: a sighting delayed in a retry
    -- queue must not resurrect an agent that was deleted after it was enqueued,
    -- so a transition is applied only when its observed_at is at least as recent
    -- as the stored value.
    ADD COLUMN IF NOT EXISTS runtime_observed_at   timestamptz,
    ADD COLUMN IF NOT EXISTS terminated_at         timestamptz,
    -- The authenticated principal the API server attributed the DELETE to. This
    -- is the answer to "who destroyed this agent" and it is only ever available
    -- from admission -- a resync can prove absence but never attribute it.
    ADD COLUMN IF NOT EXISTS terminated_by         text NOT NULL DEFAULT '';

DO $$
BEGIN
    ALTER TABLE public.discovered_agents
        ADD CONSTRAINT discovered_agents_runtime_status_chk CHECK (
            runtime_status IN ('running', 'stopped', 'gone', 'unknown'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- The "show me agents that vanished" and "show me live agents" reports.
CREATE INDEX IF NOT EXISTS idx_discovered_agents_runtime
    ON public.discovered_agents(workspace_id, runtime_status);

-- 3. discovered_agent_events -- the lifecycle trail -------------------------
--
-- Append-only. The inventory row carries only the CURRENT runtime state; this is
-- the history behind it, which is what makes "when and how was this agent
-- destroyed" answerable after the fact rather than merely "it is gone now".
--
-- Kept separate from audit_events because these are MACHINE observations of
-- third-party workloads, not administrator actions on AuthSec objects. They are
-- higher-volume, they carry no acting AuthSec user, and they are safe to prune
-- on a shorter retention -- all of which would be wrong for the admin audit log.
CREATE TABLE IF NOT EXISTS public.discovered_agent_events (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    -- Nullable: an event can legitimately arrive for a fingerprint we have never
    -- seen a sighting for (an agent created and deleted between two resyncs, or
    -- deleted while the reporting queue was backed up). Dropping it would lose
    -- the only evidence that agent ever existed.
    discovered_agent_id uuid,
    discovery_source_id uuid,
    source              text NOT NULL,
    fingerprint         text NOT NULL,
    event              text NOT NULL,
    -- The runtime_status this event asserted, or '' for a purely informational
    -- event such as a controller-owned pod being rescheduled.
    runtime_status      text NOT NULL DEFAULT '',
    reason              text NOT NULL DEFAULT '',
    actor               text NOT NULL DEFAULT '',
    -- 'admission' | 'resync' | 'control_plane'. An admission event carries a
    -- trustworthy actor; a resync event never can.
    channel             text NOT NULL DEFAULT '',
    cluster_name        text NOT NULL DEFAULT '',
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at         timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovered_agent_events_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agent_events_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_events_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agent_events_source_id_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agent_events_event_chk CHECK (
        event IN ('observed', 'deleted', 'pod_terminated', 'absent', 'reappeared')),
    CONSTRAINT discovered_agent_events_runtime_chk CHECK (
        runtime_status IN ('', 'running', 'stopped', 'gone', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_discovered_agent_events_agent
    ON public.discovered_agent_events(discovered_agent_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_discovered_agent_events_ws_fp
    ON public.discovered_agent_events(workspace_id, source, fingerprint, observed_at DESC);

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.discovered_agent_events') AS events_table,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'discovery_sources'
           AND column_name IN ('instance_id', 'cluster_name', 'cluster_uid',
                               'agent_version', 'last_heartbeat_at',
                               'self_registered', 'runtime')) AS source_cols,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'discovered_agents'
           AND column_name IN ('runtime_status', 'runtime_reason',
                               'runtime_observed_at', 'terminated_at',
                               'terminated_by')) AS agent_cols;
