-- 007_discovery_scan_runs.sql
--
-- Gives a GitHub discovery scan a durable record, and makes that record the
-- work queue.
--
-- WHY. The scan ran inside the HTTP request that asked for it. Two consequences,
-- both of which get worse exactly as an estate gets bigger:
--
--   1. An org-wide scan holds one connection open for its whole duration. A
--      hundred repositories times a tree listing plus blob fetches is minutes,
--      and every proxy between the console and the backend is entitled to cut
--      that off. The scan then dies half-done with nobody holding the result.
--   2. The result existed ONLY in that response body. Nothing was written down.
--      Refresh the page and "3 agents found, 1 repository unreadable" was gone
--      for good — so an admin could not answer "what did the last scan see?",
--      which is the whole point of running one.
--
-- WHAT. One row per scan, written before any work starts and updated as the
-- work proceeds. The row is simultaneously:
--
--   * the QUEUE      — status='queued' with a lease, claimed FOR UPDATE SKIP
--                      LOCKED so two backend replicas cannot run the same scan
--   * the PROGRESS   — counters updated per repository, so the console can show
--                      movement instead of a spinner
--   * the REPORT     — the final counters, warnings and completeness verdict,
--                      kept after the scan ends and after the admin navigates
--                      away
--   * the CHECKPOINT — `cursor` holds the units already finished, so a scan
--                      interrupted by a deploy resumes instead of restarting
--
-- One table rather than a separate jobs table plus a separate runs table: the
-- thing being queued and the thing being reported are the same thing, and
-- splitting them would mean keeping two rows in step for no gain.
--
-- Deliberately NOT reusing iga_scan_runs. That table participates in the IGA
-- generation model — a generation becomes authoritative on successful
-- completion and drives tombstone sweeps over iga_source_objects. The discovery
-- channel has no generation and no tombstones; it reports sightings into
-- discovered_agents, whose lifecycle is governed by claim/quarantine. Forcing
-- one table to carry both meanings would either corrupt the generation
-- semantics or need a discriminator on every query.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction — so there is deliberately no BEGIN/COMMIT here (see the note
-- in 006 for what happens when a migration opens a second one).

CREATE TABLE IF NOT EXISTS public.discovery_scan_runs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    -- ON DELETE CASCADE: a scan report for a source that no longer exists has
    -- no reader. The FINDINGS outlive the source (discovered_agents keeps them);
    -- the report of how they were gathered does not.
    source_id    uuid NOT NULL
        REFERENCES public.discovery_sources(id) ON DELETE CASCADE,

    -- queued -> running -> succeeded | failed | cancelled
    status text NOT NULL DEFAULT 'queued',

    -- The PLAN, snapshotted at enqueue time. A scan must report the plan it
    -- actually ran under: if an admin widens the selection while a scan is in
    -- flight, the finished report still describes what was really inspected.
    selection_mode text NOT NULL DEFAULT '',
    branch_mode    text NOT NULL DEFAULT 'default',
    max_branches   integer NOT NULL DEFAULT 0,

    -- Counters. repos_failed and repos_excluded stay separate for the reason
    -- that runs through this whole feature: "we could not look" and "we chose
    -- not to look" are different answers and neither one means "clean".
    repos_selected   integer NOT NULL DEFAULT 0,
    repos_scanned    integer NOT NULL DEFAULT 0,
    repos_failed     integer NOT NULL DEFAULT 0,
    repos_excluded   integer NOT NULL DEFAULT 0,
    repos_truncated  integer NOT NULL DEFAULT 0,
    branches_scanned integer NOT NULL DEFAULT 0,
    -- Branches beyond max_branches. Non-zero must force complete=false: we know
    -- there were more refs and we did not read them.
    branches_skipped integer NOT NULL DEFAULT 0,
    files_fetched    integer NOT NULL DEFAULT 0,
    sightings_new    integer NOT NULL DEFAULT 0,
    sightings_bumped integer NOT NULL DEFAULT 0,

    -- complete_for_selected_scope. Only true when every selected unit was fully
    -- read. Never averaged, never inferred from "no errors logged".
    complete boolean NOT NULL DEFAULT false,

    -- Monotonic "we know we missed something": set the first time any unit is
    -- unreadable, any tree is truncated, or the branch cap bites, and never
    -- cleared.
    --
    -- It exists because `complete` cannot be written while a run is in flight —
    -- the CHECK below reserves it for a finished run, so that a queued or failed
    -- row can never read as an authoritative all-clear. Without a separate flag,
    -- a scan interrupted and resumed would have no way to carry "attempt one hit
    -- a 403" across the restart, and would finish claiming complete coverage it
    -- never had. Completeness is therefore DERIVED at the end: succeeded AND NOT
    -- degraded.
    degraded boolean NOT NULL DEFAULT false,

    excluded_repositories jsonb NOT NULL DEFAULT '[]'::jsonb,
    warnings              jsonb NOT NULL DEFAULT '[]'::jsonb,
    error                 text  NOT NULL DEFAULT '',

    -- Resume cursor: {"done": ["acme/payments@main", ...]}. A unit already in
    -- here is skipped on a retry, so an interrupted scan continues rather than
    -- re-paying for the repositories it already read.
    cursor jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Lease. leased_until in the past means the worker holding it died; another
    -- worker may take the run over. attempts bounds that so a run that crashes
    -- the worker every time is marked failed instead of looping forever.
    attempts     integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    leased_by    text NOT NULL DEFAULT '',
    leased_until timestamptz,
    heartbeat_at timestamptz,

    requested_by text NOT NULL DEFAULT '',
    queued_at    timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT discovery_scan_runs_status_chk CHECK (
        status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
    ),
    CONSTRAINT discovery_scan_runs_branch_mode_chk CHECK (
        branch_mode IN ('default', 'all')
    ),
    -- A finished run must say when it finished, and an unfinished one must not
    -- claim to have. Without this a crashed worker can leave a row that reads
    -- as succeeded-but-still-running.
    CONSTRAINT discovery_scan_runs_finished_chk CHECK (
        (status IN ('succeeded', 'failed', 'cancelled')) = (finished_at IS NOT NULL)
    ),
    -- Completeness is only meaningful for a run that finished successfully.
    -- A queued or failed run asserting complete=true would be read by the
    -- console as an authoritative all-clear it never earned.
    CONSTRAINT discovery_scan_runs_complete_chk CHECK (
        NOT complete OR status = 'succeeded'
    )
);

-- One active scan per source. An admin double-clicking Scan, or a webhook
-- firing while a manual scan runs, must not put two workers on the same
-- repositories: they would race on the same fingerprints and bill twice for
-- identical work. The partial predicate lets history accumulate freely.
CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_scan_runs_active
    ON public.discovery_scan_runs (source_id)
    WHERE status IN ('queued', 'running');

-- The worker's claim query: oldest queued (or expired-lease) run first.
CREATE INDEX IF NOT EXISTS idx_discovery_scan_runs_claim
    ON public.discovery_scan_runs (status, leased_until, queued_at);

-- The console's history query: newest first for one source.
CREATE INDEX IF NOT EXISTS idx_discovery_scan_runs_source
    ON public.discovery_scan_runs (workspace_id, source_id, queued_at DESC);
