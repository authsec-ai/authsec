-- 018_source_object_scope.sql
--
-- Records WHICH SCOPE each source object was discovered in, so a scope that was
-- never read cannot be emptied by a different scope's success.
--
-- WHY. sweepAbsent built its completeness set keyed by object CLASS alone:
--
--     complete[c.ObjectClass] = true
--
-- so if any one scope reported complete for a class, the class counted as
-- complete. TombstoneAbsent then swept integration-wide. The reproduction is
-- exact: repository A returns three agent profiles and repository B returns
-- 403 denied; B's object is tombstoned anyway, using A's success as the licence.
--
-- The mass-disappearance guard does not catch it, because one quarter of the
-- inventory disappearing stays under the threshold. The inventory silently
-- shrinks, which is the specific failure the coverage design exists to prevent:
-- "we could not look" must never become "it is gone".
--
-- Fixing this needs a scope on the object, because the sweep otherwise has no
-- way to ask which objects belonged to the scope it actually read.
--
-- NULLABLE, AND NULL MEANS UNSWEEPABLE. Rows written before this migration have
-- no recorded scope. We cannot reconstruct it — the evidence was never stored —
-- so they are never eligible for tombstoning. They will become sweepable the
-- first time a scan re-observes them and records a scope. That is the honest
-- direction to fail: a stale row that lingers is visible and correctable, a row
-- deleted on a guess is neither.

ALTER TABLE public.iga_source_objects
    ADD COLUMN IF NOT EXISTS integration_scope_id uuid;

-- No foreign key on purpose. A scope row can be deleted when an admin narrows a
-- selection, and that must not cascade into deleting the evidence collected
-- while it was selected, nor block the deletion. The id is retained as a
-- historical fact about where the object came from.
COMMENT ON COLUMN public.iga_source_objects.integration_scope_id IS
    'Scope this object was observed in. NULL means the scope was not recorded '
    '(pre-018 rows) and the object is therefore never eligible for tombstoning.';

-- The sweep asks: within this integration, this scope and this class, what did
-- the current generation not see? This index is that question.
CREATE INDEX IF NOT EXISTS idx_iga_source_objects_scope_sweep
    ON public.iga_source_objects (
        workspace_id, integration_id, integration_scope_id, object_type,
        lifecycle, scan_generation
    );
