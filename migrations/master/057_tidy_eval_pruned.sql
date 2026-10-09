-- 057_tidy_eval_pruned.sql — record which revisions' findings were pruned.
--
-- expand only. Idempotent: safe to run again.
--
-- WHY
-- §2.5: a finding read at revision N is 410 revision_not_retained once N's
-- evidence and results have been pruned. The read used to INFER "pruned" from
-- the current evidence_retention_revs setting (N not among the newest
-- retention complete revisions and not pinned by a version). Raising the
-- setting after a prune therefore made a pruned revision look retained again,
-- and the read answered 200 with NO results -- an empty finding list that
-- reads as "nothing was wrong at N". Pruning is now recorded explicitly, in
-- the same transaction that deletes the rows, and the read answers 410 from
-- this record alone.
--
--   iga_gov_evaluation_pruned(workspace_id, rev, pruned_at): one row per
--   pruned evaluation; insert-once (PK), removed only with its evaluation or
--   its workspace (FK ON DELETE CASCADE, so a workspace purge needs nothing
--   new).
--
-- Backfill: every revision the pre-057 rule had pruned by now -- a complete
-- evaluation that is neither among its workspace's newest
-- evidence_retention_revs (default 30) complete evaluations nor named by a
-- policy version's evidence_rev. That is exactly the set PruneTx deleted rows
-- of on its last run under the current setting. (A revision pruned under an
-- EARLIER, lower setting that has since been raised cannot be told apart
-- from one that never had results; such revisions keep the old behaviour.)

CREATE TABLE IF NOT EXISTS iga_gov_evaluation_pruned (
  workspace_id uuid        NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  rev          bigint      NOT NULL,
  pruned_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, rev),
  FOREIGN KEY (workspace_id, rev) REFERENCES iga_gov_evaluation (workspace_id, rev) ON DELETE CASCADE
);

INSERT INTO iga_gov_evaluation_pruned (workspace_id, rev)
SELECT e.workspace_id, e.rev
  FROM iga_gov_evaluation e
  LEFT JOIN iga_gov_settings s ON s.workspace_id = e.workspace_id
 WHERE e.status = 'complete'
   AND e.rev NOT IN (SELECT n.rev FROM iga_gov_evaluation n
                      WHERE n.workspace_id = e.workspace_id AND n.status = 'complete'
                      ORDER BY n.rev DESC LIMIT COALESCE(s.evidence_retention_revs, 30))
   AND e.rev NOT IN (SELECT v.evidence_rev FROM iga_gov_policy_version v WHERE v.workspace_id = e.workspace_id)
ON CONFLICT (workspace_id, rev) DO NOTHING;

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    n integer;
BEGIN
    IF to_regclass('public.iga_gov_evaluation_pruned') IS NULL THEN
        RAISE EXCEPTION '057: table iga_gov_evaluation_pruned is missing';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conrelid = 'public.iga_gov_evaluation_pruned'::regclass AND contype = 'f'
       AND confrelid = 'public.iga_gov_evaluation'::regclass AND confdeltype = 'c';
    IF n <> 1 THEN
        RAISE EXCEPTION '057: iga_gov_evaluation_pruned has no cascading key to iga_gov_evaluation';
    END IF;

    SELECT count(*) INTO n FROM iga_gov_evaluation_pruned p
      JOIN iga_gov_evaluation e ON e.workspace_id = p.workspace_id AND e.rev = p.rev
     WHERE e.status <> 'complete';
    IF n <> 0 THEN
        RAISE EXCEPTION '057: % pruned marker(s) on an evaluation that is not complete', n;
    END IF;
END $$;
