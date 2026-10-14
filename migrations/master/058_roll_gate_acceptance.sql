-- 058_roll_gate_acceptance.sql -- a canary gate's acceptance is bound to its
-- rollout AND that rollout's version, once per (rollout, gate, window).
--
-- Expand only: one UNIQUE constraint, one foreign key and one partial unique
-- index are added; no existing object is altered or dropped. Idempotent:
-- guarded DO blocks and IF NOT EXISTS, safe to run again. 001_bootstrap.sql
-- carries the same objects (the 051 section).
--
-- WHY (review of a43a5bf, P3 "gate_not_available acceptances";
-- SPEC-iga-phase3-policy.md section 8.6 "the approver may accept named
-- not_available gates when expanding; the acceptance and reason are
-- recorded"). 051 bound a gate_not_available acceptance to its rollout by
-- (workspace_id, rollout_id) only: nothing tied its version_id to the
-- rollout's version, nothing stopped the same gate being accepted twice for
-- the same window, and the rollout matched acceptances by gate name. Now:
--
--   1. iga_gov_rollout gains UNIQUE (workspace_id, id, version_id) -- a
--      rollout has one version already (UNIQUE (version_id)); this is the key
--      the foreign key below needs.
--   2. iga_gov_acceptance (workspace_id, rollout_id, version_id) references
--      iga_gov_rollout (workspace_id, id, version_id): an acceptance of a
--      rollout's gate names that rollout's own version. MATCH SIMPLE, so the
--      evidence_gap / unanalysed_form rows (rollout_id NULL) are untouched.
--      No ON DELETE action, like 051's (workspace_id, rollout_id) key.
--   3. uq_iga_gov_acceptance_gate: one gate_not_available row per (rollout,
--      gate, window_start, window_end). The service matches acceptances by
--      rollout, version, gate and the whole window.
--
-- Rows written before 058 by the 051 code always carried the rollout's own
-- version and at most one row per gate and window; the pre-checks below
-- refuse to run (naming the count) rather than leave a constraint unapplied
-- if that ever was not so.

DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM iga_gov_acceptance a
      JOIN iga_gov_rollout r ON r.workspace_id = a.workspace_id AND r.id = a.rollout_id
     WHERE a.version_id <> r.version_id;
    IF n <> 0 THEN
        RAISE EXCEPTION '058: % acceptance(s) name another version than their rollout''s', n;
    END IF;
    SELECT count(*) INTO n FROM (
        SELECT 1 FROM iga_gov_acceptance WHERE kind = 'gate_not_available'
         GROUP BY rollout_id, item_key, window_start, window_end HAVING count(*) > 1) d;
    IF n <> 0 THEN
        RAISE EXCEPTION '058: % gate_not_available acceptance(s) are duplicated within a rollout window', n;
    END IF;
END $$;

-- 1. The rollout's (workspace, id, version) key -------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.iga_gov_rollout'::regclass
                      AND conname = 'iga_gov_rollout_workspace_id_id_version_id_key') THEN
        ALTER TABLE iga_gov_rollout
          ADD CONSTRAINT iga_gov_rollout_workspace_id_id_version_id_key UNIQUE (workspace_id, id, version_id);
    END IF;
END $$;

-- 2. An acceptance names its rollout's version --------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.iga_gov_acceptance'::regclass
                      AND conname = 'iga_gov_acceptance_rollout_version_fkey') THEN
        ALTER TABLE iga_gov_acceptance
          ADD CONSTRAINT iga_gov_acceptance_rollout_version_fkey FOREIGN KEY (workspace_id, rollout_id, version_id)
          REFERENCES iga_gov_rollout (workspace_id, id, version_id);
    END IF;
END $$;

-- 3. One acceptance per (rollout, gate, window) -------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_acceptance_gate
  ON iga_gov_acceptance (rollout_id, item_key, window_start, window_end) WHERE kind = 'gate_not_available';

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_rollout'::regclass
       AND conname = 'iga_gov_rollout_workspace_id_id_version_id_key' AND contype = 'u';
    IF n <> 1 THEN
        RAISE EXCEPTION '058: iga_gov_rollout (workspace_id, id, version_id) key is missing';
    END IF;
    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_acceptance'::regclass
       AND conname = 'iga_gov_acceptance_rollout_version_fkey' AND contype = 'f' AND convalidated;
    IF n <> 1 THEN
        RAISE EXCEPTION '058: iga_gov_acceptance_rollout_version_fkey is missing or not validated';
    END IF;
    SELECT count(*) INTO n FROM pg_indexes
     WHERE schemaname = 'public' AND tablename = 'iga_gov_acceptance' AND indexname = 'uq_iga_gov_acceptance_gate';
    IF n <> 1 THEN
        RAISE EXCEPTION '058: index uq_iga_gov_acceptance_gate is missing';
    END IF;
END $$;
