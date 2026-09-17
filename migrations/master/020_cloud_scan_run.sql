-- ============================================================================
-- 020: give an AWS scan a durable identity, an owner, and a fence.
--
-- Until now a scan was an HTTP request that returned 202 and left a `go func()`
-- running. Three things follow from that, and all three are customer-visible:
--
--   1. A backend restart loses the run. Nothing records that a scan was in
--      flight, so nothing resumes it and nothing reports it stopped. The
--      connector sits at status 'running' forever.
--   2. Two scan requests race. Both walk the same account, both write rows
--      stamped with their own generation, and whichever finishes last
--      reconciles -- deleting the other's rows because they carry a different
--      generation.
--   3. A slow worker that has been given up on can still publish. Its results
--      are older than the run that replaced it, and publishing them makes the
--      inventory go backwards.
--
-- cloud_scan_checkpoint (017) already records how FAR a run got. What it cannot
-- say is WHO is running it and whether they are still entitled to. That is what
-- this table adds: a lease with a version, so a worker that lost its lease is
-- refused at publication rather than trusted because it arrived.
--
-- WHY A LEASE AND NOT A LOCK. A lock held by a dead process is either held
-- forever or released by something that has to guess when the holder died. A
-- lease expires on its own and the holder renews it while it works, so a
-- crashed worker's run becomes claimable without anyone deciding it is dead.
--
-- WHY A VERSION ON TOP OF THE EXPIRY. Expiry alone is a clock comparison, and
-- two clocks disagree. The version is the fence: a worker records the version
-- it claimed, and publication demands that the row still carry it. A worker
-- that paused past its expiry finds the version moved on and is refused --
-- regardless of whose clock was right.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_scan_run (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The generation this run stamps its rows with. Assigned when the run is
    -- claimed, not when it is queued: a run that never starts must not burn a
    -- generation, because reconciliation reads generations as evidence of a
    -- completed pass.
    generation integer NOT NULL DEFAULT 0,

    -- queued    -- waiting for a worker
    -- running   -- a worker holds the lease
    -- published -- finished and reconciled; the only authoritative end state
    -- failed    -- finished without publishing, reason in last_error
    -- abandoned -- lease expired and another run superseded it
    status text NOT NULL DEFAULT 'queued',

    trigger text NOT NULL DEFAULT 'manual',

    -- Lease. Empty owner means nobody holds it.
    lease_owner text NOT NULL DEFAULT '',
    lease_expires_at timestamptz,
    -- Bumped on every claim. This is the fence token; see the header.
    lease_version bigint NOT NULL DEFAULT 0,

    attempts integer NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT '',

    requested_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_scan_run_status_chk CHECK (
        status IN ('queued', 'running', 'published', 'failed', 'abandoned')),

    -- A published run must say when, and only a published run may.
    -- Reconciliation reads published_at as proof the pass finished.
    CONSTRAINT cloud_scan_run_published_chk CHECK (
        (status = 'published') = (published_at IS NOT NULL)),

    -- A running run must name its holder and its expiry, or it cannot be
    -- fenced and cannot be reclaimed.
    CONSTRAINT cloud_scan_run_lease_chk CHECK (
        status <> 'running'
        OR (lease_owner <> '' AND lease_expires_at IS NOT NULL)),

    -- A run that reached a worker has a generation; a queued one does not yet.
    CONSTRAINT cloud_scan_run_generation_chk CHECK (
        status IN ('queued', 'abandoned') OR generation > 0),

    CONSTRAINT cloud_scan_run_attempts_chk CHECK (attempts >= 0)
);

-- AT MOST ONE LIVE RUN PER CONNECTOR.
--
-- This is the overlapping-scan protection, and it is a database constraint
-- rather than a check in the handler because the handler runs in more than one
-- process. Two concurrent POSTs both see "no run in flight" and both insert;
-- only a unique index can refuse the second.
--
-- Partial, so finished runs accumulate as history without blocking the next.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_scan_run_live
    ON public.cloud_scan_run (connector_id)
    WHERE status IN ('queued', 'running');

-- The worker's claim query: the oldest queued run, or a running one whose lease
-- has expired.
CREATE INDEX IF NOT EXISTS idx_cloud_scan_run_claimable
    ON public.cloud_scan_run (status, lease_expires_at, requested_at)
    WHERE status IN ('queued', 'running');

-- "What happened to this connector's scans?" -- newest first.
CREATE INDEX IF NOT EXISTS idx_cloud_scan_run_history
    ON public.cloud_scan_run (workspace_id, connector_id, requested_at DESC);

COMMENT ON TABLE public.cloud_scan_run IS
    'One AWS scan attempt, with the lease that makes it resumable and fenced. '
    'Publication requires the holder to still own the lease version it claimed.';
COMMENT ON COLUMN public.cloud_scan_run.lease_version IS
    'Fence token. A worker records this at claim time and publication demands '
    'the row still carries it, so a worker that paused past its expiry is '
    'refused without relying on clock agreement.';
COMMENT ON COLUMN public.cloud_scan_run.generation IS
    'Assigned at claim, not at enqueue: a run that never starts must not burn a '
    'generation, because reconciliation reads generations as evidence of a pass.';

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.cloud_scan_run') AS scan_run_table,
       (SELECT count(*) FROM pg_constraint
         WHERE conrelid = 'public.cloud_scan_run'::regclass AND contype = 'c') AS checks;
