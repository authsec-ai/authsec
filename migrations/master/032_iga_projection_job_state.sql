-- ============================================================================
-- 032: the projection job, the per-partition watermark, and agent origin.
--
-- SPEC-iga-phase2-graph.md §2.8, §4.10.
--
-- WHY PROJECTION IS ITS OWN DURABLE WORK ITEM. It cannot run under the scan
-- lease: Publish() sets lease_owner = "" and lease_expires_at = nil
-- (repository/cloud_scan_run_repository.go:152), and fenced() requires
-- lease_owner = ?, so ANY fenced call after publication returns ErrLeaseLost
-- and affects zero rows. "Project after publication under the same lease" is
-- not implementable. Moving the call earlier instead would make a projection
-- failure fail the scan, which is worse.
--
-- So it mirrors cloud_scan_run's proven pattern -- Enqueue/Claim/Renew/
-- Complete/Fail, lease_owner + lease_version, fenced updates that CONSULT NO
-- CLOCK. Do not invent a second ownership notion; copy the one that works.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_projection_job (
    id               uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL,
    scan_run_id      uuid NOT NULL,
    connector_id     uuid NOT NULL,
    generation       integer NOT NULL,
    status           text NOT NULL DEFAULT 'queued',
    lease_owner      text NOT NULL DEFAULT '',
    lease_expires_at timestamptz,
    -- The fence token. A worker records the value it claimed and every write
    -- demands the row still carries it, so a worker that paused past its
    -- expiry is refused without anyone trusting a clock.
    lease_version    bigint NOT NULL DEFAULT 0,
    attempts         integer NOT NULL DEFAULT 0,
    last_error       text NOT NULL DEFAULT '',
    requested_at     timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,

    CONSTRAINT iga_projection_job_pkey PRIMARY KEY (id),
    CONSTRAINT iga_projection_job_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_projection_job_run_fkey FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE CASCADE,
    -- §2.9: workspace-qualified, never a bare FK to cloud_connector(id).
    CONSTRAINT iga_projection_job_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,

    CONSTRAINT iga_projection_job_status_chk CHECK (
        status IN ('queued', 'running', 'complete', 'failed', 'abandoned')),
    -- A job for a run that never started has nothing to project.
    CONSTRAINT iga_projection_job_generation_chk CHECK (generation > 0),
    -- Enqueue is in the SAME transaction as Publish(), so a published run
    -- always has exactly one job and a crash between the two is impossible
    -- rather than recovered.
    CONSTRAINT iga_projection_job_run_key UNIQUE (scan_run_id)
);

CREATE INDEX IF NOT EXISTS idx_iga_projection_job_claimable
    ON public.iga_projection_job (status, lease_expires_at, requested_at)
    WHERE status IN ('queued', 'running');

COMMENT ON TABLE public.iga_projection_job IS
    'A wedged projection BLOCKS SCANNING for its connector, by design -- '
    'cloud_scan_run.Claim gains a NOT EXISTS predicate on queued/running jobs. '
    'That is why attempts has a ceiling and failed/abandoned are terminal: a '
    'job must always reach a terminal state, or it becomes an outage. Alert on '
    'queued/running jobs older than one lease.';

-- per-partition watermark ----------------------------------------------------
CREATE TABLE IF NOT EXISTS public.iga_projection_state (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    estate_scope_id   uuid NOT NULL,
    connector_id      uuid NOT NULL,
    object_class      text NOT NULL DEFAULT '',
    relationship_type text NOT NULL DEFAULT '',

    -- The partition's FULL identity (Partition.Key()): scope, connector,
    -- class, relationship type, target and required surfaces.
    --
    -- Keying on (scope, class, relationship_type) alone merges partitions that
    -- must stay separate -- roles with users, every region's Lambda with every
    -- other's -- and one partition's watermark then overwrites another's,
    -- which licenses closing relationships nothing in this run looked at.
    partition_key     text NOT NULL,
    last_run_id       uuid NOT NULL,
    last_generation   bigint NOT NULL,
    coverage_state    text NOT NULL,
    -- false until the Reconciler commits. A pass interrupted between
    -- projection and reconciliation is visible as exactly that, and the next
    -- job re-reconciles the partition rather than assuming it settled.
    reconciled        boolean NOT NULL DEFAULT false,
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_projection_state_pkey PRIMARY KEY (id),
    CONSTRAINT iga_projection_state_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_projection_state_scope_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_projection_state_run_fkey FOREIGN KEY (workspace_id, last_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE CASCADE,
    -- (workspace_id, connector_id), never connector_id alone: a bare FK lets a
    -- row in workspace A reference workspace B's integration, which is the
    -- §2.9 defect this phase exists to close. 026 adds the UNIQUE this needs.
    CONSTRAINT iga_projection_state_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,

    CONSTRAINT iga_projection_state_generation_chk CHECK (last_generation >= 0),
    CONSTRAINT iga_projection_state_key
        UNIQUE (workspace_id, connector_id, partition_key)
);

COMMENT ON COLUMN public.iga_projection_state.partition_key IS
    'The SAME value stamped on iga_relationship.partition_key and '
    'iga_access_edges.partition_key, so "what this run reconciles" and "what '
    'this run recorded a watermark for" are the same set by construction.';

-- agent origin and the instance link -----------------------------------------
-- The exit gate''s "a registered agent is distinguished from native
-- discovery": they get different review treatment and must never silently
-- merge. A discovered object a human later registers KEEPS ITS ID and flips
-- origin, with the decision recorded -- the projector must never overwrite
-- origin once it reads 'registered'.
ALTER TABLE public.iga_agents
    ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'discovered';

ALTER TABLE public.iga_agents
    ADD CONSTRAINT iga_agents_origin_chk CHECK (origin IN ('registered', 'discovered'));

-- iga_agent_instances already has first_seen_at/last_seen_at and
-- native_workload_id from 004:563 -- it needs the key, the origin and the
-- typed link, not a rebuild.
ALTER TABLE public.iga_agent_instances
    ADD COLUMN IF NOT EXISTS workload_id    uuid,
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS origin         text NOT NULL DEFAULT 'discovered',
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_agent_instances
    ADD CONSTRAINT iga_agent_instances_workload_fkey
        FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id)
        ON DELETE SET NULL (workload_id),
    ADD CONSTRAINT iga_agent_instances_origin_chk CHECK (
        origin IN ('registered', 'discovered'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agent_instances_source_key
    ON public.iga_agent_instances (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- verify ---------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('iga_projection_job', 'iga_projection_state')) AS tables_created,
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'iga_agents' AND column_name = 'origin')          AS agents_origin,
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'iga_agent_instances'
        AND column_name IN ('workload_id', 'source_key', 'origin'))        AS instance_cols;
