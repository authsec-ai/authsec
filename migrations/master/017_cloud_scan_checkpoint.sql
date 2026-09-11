-- 017_cloud_scan_checkpoint.sql
--
-- How far a scan got, so a scan that dies part-way resumes instead of starting
-- over.
--
-- WHY THIS IS NEEDED NOW AND WAS NOT BEFORE. Identity discovery alone is two
-- calls per role. Adding per-identity policies makes it roughly seven, and
-- adding activity makes it a submit-plus-poll report job per identity on top.
-- On five hundred roles that is thousands of calls, and the probability that
-- nothing interrupts a run that long is not one. Without a checkpoint every
-- interruption throws away the whole run's work and the next attempt is exactly
-- as likely to be interrupted, so a large account can fail to ever complete a
-- scan.
--
-- WHY NOT iga_scan_checkpoints. That table is the same idea for the GitHub
-- pipeline, and it has a NOT NULL foreign key to iga_scan_runs. The AWS
-- connector does not create iga_scan_runs rows -- it tracks a scan in
-- cloud_connector.scan_generation and .coverage -- so reusing it would mean
-- making AWS write into the canonical iga_* pipeline, which is an open
-- architecture question and not something a resume feature should decide.
--
-- WHY THE KEY INCLUDES generation. A checkpoint belongs to one scan attempt.
-- The generation is that attempt's identity, and it is already how every other
-- cloud_* table decides what is current, so a stale checkpoint from an older
-- generation is inert rather than actively wrong -- it simply never matches.
--
-- WHY A CURSOR AND NOT A SET OF COMPLETED ITEMS. Storing which of five hundred
-- identities were finished would mean five hundred rows or one enormous array.
-- Instead each resumable phase walks its items in a deterministic order --
-- sorted by ARN, not the order AWS happened to return -- and records the last
-- one it finished. Resuming skips everything at or before that value. Sorting
-- is what makes this sound: AWS makes no promise that two calls return items in
-- the same order, and a cursor over an unstable order would silently skip work.
--
-- WHAT MAKES SKIPPING SAFE. Every skipped item's rows were already written and
-- stamped with THIS generation by the interrupted attempt, so reconciliation --
-- which only removes rows older than the current generation, and only when the
-- scan completed -- cannot mistake them for gone. That property is why resume
-- can be a cursor rather than a re-verification.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction. This file must not open one of its own.

CREATE TABLE IF NOT EXISTS public.cloud_scan_checkpoint (
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The scan attempt this checkpoint belongs to.
    generation integer NOT NULL,

    -- Which resumable phase. Free text because the phase list grows with the
    -- surfaces: 'identity_policies', 'activity', 'workloads:<region>'. A phase
    -- nobody recognises is ignored, which is the right failure mode for a
    -- resume hint.
    phase text NOT NULL,

    -- The last item this phase finished, in the phase's own sort order. An
    -- identity ARN for the per-identity phases, a region for the regional ones.
    -- Empty means the phase started and finished nothing.
    cursor text NOT NULL DEFAULT '',

    -- How many items the phase has finished, for the scan report. Advisory:
    -- the cursor is what resume actually uses.
    done_count integer NOT NULL DEFAULT 0,

    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_scan_checkpoint_pkey
        PRIMARY KEY (workspace_id, connector_id, generation, phase),
    CONSTRAINT cloud_scan_checkpoint_phase_chk CHECK (phase <> ''),
    CONSTRAINT cloud_scan_checkpoint_generation_chk CHECK (generation >= 0),
    CONSTRAINT cloud_scan_checkpoint_done_count_chk CHECK (done_count >= 0)
);

-- "Is there an unfinished scan for this connector, and at which generation" --
-- the question asked once at the start of every scan.
CREATE INDEX IF NOT EXISTS idx_cloud_scan_checkpoint_connector
    ON public.cloud_scan_checkpoint (connector_id, generation);
