-- ============================================================================
-- 027: every provenance reference is workspace-qualified.
--
-- SPEC-iga-phase2-graph.md §2.9. A single-column
--     FOREIGN KEY (scan_run_id) REFERENCES cloud_scan_run (id)
-- admits ANOTHER workspace's scan run. That is the same class of defect as the
-- untyped subject on iga_access_edges (A3), and it is easy to reintroduce two
-- lines below the fix -- 024 did exactly that while closing D4.
--
-- THE RULE THIS MIGRATION ESTABLISHES, for every migration after it:
--   no single-column foreign key to a workspace-scoped table. Every reference
--   is (workspace_id, id) against a UNIQUE (workspace_id, id).
--
-- Why this must land before the projector: 030-034 write their references in
-- composite form against targets that do not exist yet. cloud_connector has
-- only a PRIMARY KEY (id) and the unique INDEX uq_cloud_connector_scope
-- (010) -- neither is a usable composite FK target -- so without the UNIQUE
-- added below, every REFERENCES cloud_connector (workspace_id, id) in
-- 030-034 fails to apply. Verified against the schema, not assumed.
--
-- SCOPE NOTE. §2.9's table names three references to convert, all to
-- cloud_scan_run. Two more single-column FKs to the workspace-scoped
-- cloud_connector exist and are the same defect:
--     cloud_observation.connector_id   (022:37)
--     cloud_scan_run.connector_id      (020)
-- They are converted here too. Leaving a known instance of the exact defect
-- this migration exists to close, in the one migration that adds the target
-- making it fixable, would guarantee a 035 that does nothing else.
-- ============================================================================

-- pre-flight -----------------------------------------------------------------
-- Rows that already violate this cannot be converted, and a cross-tenant
-- reference is a FINDING, not a migration inconvenience. Fail loudly and name
-- the count rather than letting ALTER TABLE report a constraint violation with
-- no indication of how much data is wrong.
DO $$
DECLARE
    n_run          bigint;
    n_confirmed    bigint;
    n_obs_conn     bigint;
    n_scan_conn    bigint;
BEGIN
    SELECT count(*) INTO n_run
      FROM public.cloud_observation o
      JOIN public.cloud_scan_run r ON r.id = o.scan_run_id
     WHERE r.workspace_id <> o.workspace_id;

    SELECT count(*) INTO n_confirmed
      FROM public.cloud_observation o
      JOIN public.cloud_scan_run r ON r.id = o.last_confirmed_run_id
     WHERE r.workspace_id <> o.workspace_id;

    SELECT count(*) INTO n_obs_conn
      FROM public.cloud_observation o
      JOIN public.cloud_connector c ON c.id = o.connector_id
     WHERE c.workspace_id <> o.workspace_id;

    SELECT count(*) INTO n_scan_conn
      FROM public.cloud_scan_run r
      JOIN public.cloud_connector c ON c.id = r.connector_id
     WHERE c.workspace_id <> r.workspace_id;

    IF (n_run + n_confirmed + n_obs_conn + n_scan_conn) > 0 THEN
        RAISE EXCEPTION
            'cross-workspace provenance rows found: scan_run_id=%, '
            'last_confirmed_run_id=%, observation.connector_id=%, '
            'scan_run.connector_id=%. These are real cross-tenant references '
            'and must be investigated before 027 can apply.',
            n_run, n_confirmed, n_obs_conn, n_scan_conn;
    END IF;
END $$;

-- composite FK targets -------------------------------------------------------
-- Each is the target some reference below (or in 030-034) needs. None of the
-- three tables has one today; all three are workspace-scoped.
ALTER TABLE public.cloud_connector
    ADD CONSTRAINT cloud_connector_workspace_id_key UNIQUE (workspace_id, id);

ALTER TABLE public.cloud_scan_run
    ADD CONSTRAINT cloud_scan_run_workspace_id_key UNIQUE (workspace_id, id);

ALTER TABLE public.cloud_observation
    ADD CONSTRAINT cloud_observation_workspace_id_key UNIQUE (workspace_id, id);

-- convert the references -----------------------------------------------------
-- Constraint names below were read off \d cloud_observation in a rehearsal
-- database built by applying 001-025, not guessed from PostgreSQL's naming
-- rules. A wrong name fails the migration.
ALTER TABLE public.cloud_observation
    DROP CONSTRAINT cloud_observation_scan_run_id_fkey,
    ADD CONSTRAINT cloud_observation_run_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT,

    -- ON DELETE SET NULL (last_confirmed_run_id) nulls ONLY that column and
    -- keeps workspace_id, which is the reason the column-list form of SET NULL
    -- exists. Without it, deleting a scan run would null the workspace of every
    -- observation it last confirmed. Requires PostgreSQL 15+; this repo runs 16.
    DROP CONSTRAINT cloud_observation_last_confirmed_run_id_fkey,
    ADD CONSTRAINT cloud_observation_last_confirmed_fkey
        FOREIGN KEY (workspace_id, last_confirmed_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_run_id),

    DROP CONSTRAINT cloud_observation_connector_id_fkey,
    ADD CONSTRAINT cloud_observation_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE;

ALTER TABLE public.cloud_scan_run
    DROP CONSTRAINT cloud_scan_run_connector_id_fkey,
    ADD CONSTRAINT cloud_scan_run_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE;

COMMENT ON CONSTRAINT cloud_observation_run_fkey ON public.cloud_observation IS
    'Workspace-qualified (§2.9). The single-column form this replaced admitted '
    'another workspace''s scan run as the provenance of this observation.';

COMMENT ON CONSTRAINT cloud_observation_last_confirmed_fkey ON public.cloud_observation IS
    'Workspace-qualified (§2.9). SET NULL names its column so a deleted scan '
    'run clears the confirmation without clearing the row''s workspace.';

-- verify ---------------------------------------------------------------------
-- Every FK on these two tables that points at a workspace-scoped table must
-- now name two columns. A row here with conkey length 1 is a miss.
SELECT c.conrelid::regclass::text AS tbl,
       c.conname,
       array_length(c.conkey, 1) AS cols,
       pg_get_constraintdef(c.oid) AS def
  FROM pg_constraint c
 WHERE c.contype = 'f'
   AND c.conrelid IN ('public.cloud_observation'::regclass,
                      'public.cloud_scan_run'::regclass)
   AND c.confrelid IN ('public.cloud_scan_run'::regclass,
                       'public.cloud_connector'::regclass)
 ORDER BY 1, 2;

-- ============================================================================
-- iga_pipeline_lease -- the pipeline barrier (§2.10A).
--
-- Placed in 027 because §2.10A's own DDL comment labels it 027 and the ERD
-- lists it as 027; §3's numbered sections never gave it a slot. It belongs
-- before the projector either way, since the projector cannot be correct
-- without it.
--
-- WHY A ROW AND NOT A LOCK. A published run's inventory must not change while
-- its projection reads it, and three writers can change it:
--
--   * another connector's scan -- uq_cloud_resource_native is
--     (workspace_id, native_id) with NO connector (013:86) and UpsertResource
--     reassigns connector_id, so two connectors never contend for the same
--     per-connector lock yet both write the row;
--   * a superseded worker still running -- it holds no lock to lose;
--   * the next scan of the same connector -- the only one a per-connector rule
--     catches.
--
-- pg_advisory_xact_lock is released when its transaction commits, and
-- publication and projection are NECESSARILY different transactions --
-- projection is a durable job claimed later. The window between them is
-- exactly where the overwrite happens, so a session lock cannot express this.
-- A committed row can.
--
-- COST, STATED PLAINLY: scanning is serialized per WORKSPACE, not per
-- connector. A customer with five AWS accounts scans them one at a time. That
-- is a real throughput ceiling and it is the price of the guarantee -- the
-- shared-resource writer crosses connectors, so nothing narrower is sound.
-- Revisit only by removing the sharing (per-connector resource rows) or by
-- projecting from immutable inputs, never by narrowing the barrier.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_pipeline_lease (
    workspace_id uuid NOT NULL,
    -- idle -> collecting -> projecting -> idle
    state        text NOT NULL DEFAULT 'idle',
    holder       text NOT NULL DEFAULT '',   -- worker identity
    scan_run_id  uuid,
    expires_at   timestamptz,
    -- Fence token. Every transition demands the version it read, so a worker
    -- that slept past its expiry is refused because the version moved on --
    -- never because a clock was consulted.
    version      bigint NOT NULL DEFAULT 0,
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_pipeline_lease_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT iga_pipeline_lease_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_pipeline_lease_state_chk CHECK (
        state IN ('idle', 'collecting', 'projecting')),
    -- Busy exactly when someone holds it. Prevents the half-state where a
    -- worker died between clearing its name and clearing the state.
    CONSTRAINT iga_pipeline_lease_busy_chk CHECK (
        (state = 'idle') = (holder = '' AND scan_run_id IS NULL))
);

COMMENT ON TABLE public.iga_pipeline_lease IS
    'One row per WORKSPACE. state=projecting is what a later scan claim '
    'collides with, and because it is a committed row rather than a session '
    'lock it survives the gap between the publish transaction and the '
    'projection transaction. Recovery is an expiry sweep, so a dead worker '
    'cannot wedge a workspace permanently.';

SELECT count(*) AS iga_pipeline_lease_created
  FROM information_schema.tables
 WHERE table_schema = 'public' AND table_name = 'iga_pipeline_lease';
