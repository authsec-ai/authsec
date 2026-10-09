-- ============================================================================
-- 037: contract (a later release)
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================
-- NOT APPLIED BY THE RUNNER. The runner reads migrations/master only.
-- Ships in a LATER release, after the rollback window of the release that
-- shipped 030 closes and the GitHub writer and readers stop referencing
-- subject_kind / subject_id. Move it into migrations/master then, and not
-- before: applying it makes rolling back to 0e75ad7 impossible.
--

ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_subject_agree_chk,
    DROP CONSTRAINT IF EXISTS iga_access_edges_subject_chk,
    DROP COLUMN IF EXISTS subject_kind,
    DROP COLUMN IF EXISTS subject_id;
DROP INDEX IF EXISTS public.idx_iga_access_edges_subject;
