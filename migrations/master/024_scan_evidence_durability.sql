-- ============================================================================
-- 024: four defects in how a scan's coverage and evidence survive past the
-- scan that produced them. Nothing built on cloud_observation or on "was this
-- scan complete" is trustworthy until these are fixed.
--
-- D1 · COVERAGE WAS NOT PER-RUN.
-- cloud_connector.coverage (010) is one jsonb column, overwritten by every
-- scan. A reader who asks "was THIS run's inventory trustworthy" after a later
-- scan has already published gets that later run's answer instead -- possibly
-- a worse one. cloud_scan_run already exists as the per-run anchor (020); this
-- migration gives it a coverage column of its own, so a specific run's report
-- stays readable regardless of what any later run wrote to the connector.
--
-- D2 · Complete() must be consumed, not re-derived.
-- ScanCoverage.Complete() (models/cloud_discovery.go) already composes
-- correctly with the permission scanner's ParseFailures/StatementsSkipped
-- gate -- but only because FinalizeCoverage folds that gate into a Surfaces
-- entry before Complete() ever runs. That composition has to happen exactly
-- once, on the one persisted report a reader consumes; this migration's
-- coverage column is that report, stamped at publish time in Go code (see
-- FinalizeCoverage / AWSScanWorker.execute), not recomputed later from parts.
--
-- D3 · Evidence was deleted by inventory churn.
-- cloud_observation's subject columns (022) were ON DELETE CASCADE to
-- cloud_identity/cloud_permission/cloud_resource/cloud_workload. Reconciliation
-- deletes stale inventory by generation (cloud_permission_repository.go,
-- cloud_identity_repository.go, ...), so a permission that disappeared this
-- scan took its own evidence down with it via the cascade -- the opposite of
-- what scan_run_id's ON DELETE RESTRICT (022) was written to guarantee.
--
-- Changing the subject FKs to RESTRICT does not fix this: reconciliation would
-- then fail outright on every row that ever had evidence recorded against it,
-- which is every row a real scan ever wrote. That is a deadlock, not a fix.
-- SET NULL lets reconciliation keep working and stops the delete from
-- propagating, but by itself it throws away the one thing that made the
-- evidence legible -- which subject it was about. subject_native_id is
-- captured at write time (the ARN or provider id, never a bare uuid) precisely
-- so an observation still says what it was evidence FOR after its subject row
-- is gone. The subject check is relaxed from "exactly one" to "at most one"
-- to allow that orphaned state to exist at all.
--
-- D4 · Content dedupe erased run confirmation.
-- uq_cloud_observation_dedupe (022) is correct for storage -- an unchanged
-- re-read must not grow the table -- and wrong for reconciliation, which needs
-- "was this fact's surface among what THIS run read" and had no way to ask it:
-- a dedup'd re-read wrote nothing, so nothing on the row said run B ever saw
-- it. last_confirmed_run_id/at answer that without duplicating storage: the
-- writer's ON CONFLICT now updates them instead of doing nothing (see
-- ObservationWriter.Record), so a repeated fact keeps one row and gains a
-- fresh confirmation instead of going silent.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- D1 + D2: per-run coverage on cloud_scan_run.
-- ---------------------------------------------------------------------------
ALTER TABLE public.cloud_scan_run
    ADD COLUMN IF NOT EXISTS coverage jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN public.cloud_scan_run.coverage IS
    'This run''s own final ScanCoverage report, stamped once at publish time. '
    'Authoritative for THIS run regardless of what a later run writes to '
    'cloud_connector.coverage -- read this column, not the connector''s, when '
    'the question is "was this specific run complete".';

-- ---------------------------------------------------------------------------
-- D3: evidence must outlive the inventory row it was about.
-- ---------------------------------------------------------------------------

-- Drop and recreate the four subject FKs as SET NULL. Named constraints match
-- what PostgreSQL auto-generates for a column-level REFERENCES clause in 022.
ALTER TABLE public.cloud_observation
    DROP CONSTRAINT IF EXISTS cloud_observation_identity_id_fkey,
    DROP CONSTRAINT IF EXISTS cloud_observation_permission_id_fkey,
    DROP CONSTRAINT IF EXISTS cloud_observation_resource_id_fkey,
    DROP CONSTRAINT IF EXISTS cloud_observation_workload_id_fkey;

ALTER TABLE public.cloud_observation
    ADD CONSTRAINT cloud_observation_identity_id_fkey
        FOREIGN KEY (identity_id) REFERENCES public.cloud_identity(id) ON DELETE SET NULL,
    ADD CONSTRAINT cloud_observation_permission_id_fkey
        FOREIGN KEY (permission_id) REFERENCES public.cloud_permission(id) ON DELETE SET NULL,
    ADD CONSTRAINT cloud_observation_resource_id_fkey
        FOREIGN KEY (resource_id) REFERENCES public.cloud_resource(id) ON DELETE SET NULL,
    ADD CONSTRAINT cloud_observation_workload_id_fkey
        FOREIGN KEY (workload_id) REFERENCES public.cloud_workload(id) ON DELETE SET NULL;

-- subject_native_id: captured at write time, independent of the live FK.
-- Backfilled '(unknown)' for any pre-existing row so the column can be
-- NOT NULL from here on; a real scan always has a native id to record.
ALTER TABLE public.cloud_observation
    ADD COLUMN IF NOT EXISTS subject_native_id text NOT NULL DEFAULT '(unknown)';
ALTER TABLE public.cloud_observation
    ALTER COLUMN subject_native_id DROP DEFAULT;

COMMENT ON COLUMN public.cloud_observation.subject_native_id IS
    'The AWS-native id (ARN, role name, ...) of the subject, captured when the '
    'observation was written. Exists so a row still says what it was evidence '
    'for after its subject_id is SET NULL by reconciliation deleting the row '
    'it pointed at -- otherwise SET NULL preserves a row with nothing legible '
    'left on it.';

-- Relax "exactly one subject" to "at most one": an observation whose subject
-- was reconciled away legitimately has zero live subject columns now, and
-- that must not become a constraint violation on the next unrelated write to
-- the row (there is none -- the row is otherwise immutable -- but the check
-- runs on every UPDATE, not only INSERT).
ALTER TABLE public.cloud_observation
    DROP CONSTRAINT IF EXISTS cloud_observation_subject_chk;
ALTER TABLE public.cloud_observation
    ADD CONSTRAINT cloud_observation_subject_chk CHECK (
        (identity_id IS NOT NULL)::int
      + (permission_id IS NOT NULL)::int
      + (resource_id IS NOT NULL)::int
      + (workload_id IS NOT NULL)::int <= 1
    );

-- ---------------------------------------------------------------------------
-- D4: confirmation without growing the table on an unchanged re-read.
-- ---------------------------------------------------------------------------

-- uq_cloud_observation_dedupe (022) stays exactly as it is: a unique index on
-- an expression. Postgres cannot convert an expression index into a named
-- UNIQUE constraint ("cannot create a unique constraint using such an
-- index"), so ON CONFLICT here targets it the ordinary way -- by repeating
-- the same column/expression list, not by constraint name. See
-- ObservationWriter.Record for how GORM is made to emit that expression
-- un-quoted.
ALTER TABLE public.cloud_observation
    ADD COLUMN IF NOT EXISTS last_confirmed_run_id uuid
        REFERENCES public.cloud_scan_run(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS last_confirmed_at timestamptz,
    ADD COLUMN IF NOT EXISTS confirmation_count integer NOT NULL DEFAULT 1;

-- Backfill: every existing row was confirmed, at least once, by the run that
-- wrote it -- that is what scan_run_id already records.
UPDATE public.cloud_observation
   SET last_confirmed_run_id = scan_run_id,
       last_confirmed_at     = ingested_at
 WHERE last_confirmed_run_id IS NULL;

ALTER TABLE public.cloud_observation
    ALTER COLUMN confirmation_count SET DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_cloud_observation_last_confirmed_run
    ON public.cloud_observation (last_confirmed_run_id);

COMMENT ON COLUMN public.cloud_observation.last_confirmed_run_id IS
    'The most recent run that re-read this exact fact (same subject, api and '
    'content hash). Updated on the dedupe path instead of leaving it silent, '
    'so reconciliation can ask "did this run confirm this" without the table '
    'growing on an unchanged account.';
COMMENT ON COLUMN public.cloud_observation.confirmation_count IS
    'How many runs, including the one that first wrote this row, have seen '
    'this exact fact. A floor on how long it has been true, not a full history '
    '-- the history is scan_run_id plus every later confirming run, which this '
    'table does not enumerate.';

-- verify -------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'cloud_scan_run' AND column_name = 'coverage') AS scan_run_coverage,
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'cloud_observation' AND column_name = 'subject_native_id') AS subject_native_id,
    (SELECT count(*) FROM information_schema.columns
      WHERE table_name = 'cloud_observation' AND column_name = 'last_confirmed_run_id') AS last_confirmed_run_id;
