-- 008_discovery_scan_files_failed.sql
--
-- Adds files_failed to discovery_scan_runs.
--
-- WHY. A real organisation-wide scan reported "0 Failed" next to a hundred and
-- thirty warnings naming files it could not read. Both numbers were true and
-- together they were a lie: repos_failed counts REPOSITORIES that could not be
-- opened, and every one of those failures was at FILE level, so nothing
-- incremented. A console showing "0 failed" beside a wall of errors teaches an
-- operator to distrust the number or to ignore the errors, and either way the
-- gap in coverage stops being legible.
--
-- complete_for_selected_scope was correctly false throughout, so the run never
-- claimed an all-clear. This is about the counters agreeing with the warnings.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction.

ALTER TABLE public.discovery_scan_runs
    ADD COLUMN IF NOT EXISTS files_failed integer NOT NULL DEFAULT 0;
