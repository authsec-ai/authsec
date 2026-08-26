-- ============================================================================
-- Forward delta: releasing a quarantine.
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_unquarantine.sql
--
-- Depends on governance_actuation.sql and discovery_agent_registration_lifecycle.sql.
--
-- WHY THIS EXISTS
-- Quarantine was one-way. Every piece of the release path was present except the
-- entry point: the agent implements the `unquarantine` instruction,
-- models.InstructionUnquarantine is defined, and EnforceQuarantine() takes a
-- `release bool`. But the only call site passed release=false, and no route reached
-- it. Once an agent was quarantined the deny NetworkPolicy stayed until somebody ran
-- `kubectl delete networkpolicy` by hand.
--
-- Two things needed schema support to fix it properly.
-- ============================================================================

-- 1. Release bookkeeping on the agent ---------------------------------------
--
-- The release must NOT clear quarantined_at / quarantined_by / quarantine_reason:
-- those are the record that this agent WAS quarantined, and why. Erasing them on
-- release would destroy exactly the history a reviewer needs.
--
-- But keeping them while status returns to 'registered' is ambiguous on its own --
-- a row would look quarantined and not-quarantined at once. These two columns
-- disambiguate it: quarantine_released_at set means the quarantine is history.
ALTER TABLE public.discovered_agents
    ADD COLUMN IF NOT EXISTS quarantine_released_at timestamptz,
    ADD COLUMN IF NOT EXISTS quarantine_released_by uuid;

-- 2. A superseded instruction state ----------------------------------------
--
-- Needed because of a second bug found while fixing the first.
--
-- EnforceQuarantine keyed BOTH kinds on "quarantine:<fingerprint>", and Enqueue
-- resolves a conflict on that key with DoNothing. So: quarantine an agent, then
-- release it before the cluster agent next polls, and the release collapsed onto the
-- still-pending quarantine and was SILENTLY DROPPED. The stale quarantine then
-- applied, and the console showed a released agent that was still blocked.
--
-- The intent behind the shared key was right -- a quarantine and its release must
-- never sit open at once, contradicting each other -- but DoNothing resolves that
-- contradiction in favour of the OLDER decision. The newest decision has to win.
--
-- So the key is now per-kind, and an open instruction of the opposite kind is
-- explicitly superseded. 'superseded' rather than deleting the row: an operator
-- looking at why enforcement did or did not happen needs to see that a decision was
-- overtaken, not find a gap where a row used to be.
ALTER TABLE public.provisioning_instructions
    DROP CONSTRAINT IF EXISTS provisioning_instructions_status_chk;
ALTER TABLE public.provisioning_instructions
    ADD CONSTRAINT provisioning_instructions_status_chk
    CHECK (status IN ('pending', 'leased', 'applied', 'failed', 'superseded'));

-- The partial unique index over OPEN instructions is deliberately NOT touched here.
-- governance_actuation.sql already defines it as
--   ... WHERE status IN ('pending', 'leased')
-- which is exactly right: 'superseded' is not open, so a superseded row never blocks
-- a later enqueue for the same key. Dropping and recreating a unique index on a live
-- table to reach a definition it already has would open a window for a duplicate
-- open instruction to slip in, for no gain. The verify block below asserts it instead.

-- verify -------------------------------------------------------------------
SELECT (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'discovered_agents'
           AND column_name IN ('quarantine_released_at','quarantine_released_by')) AS release_cols,
       (SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conname = 'provisioning_instructions_status_chk') AS status_chk,
       -- Must report a predicate over exactly pending+leased.
       (SELECT pg_get_expr(indpred, indrelid) FROM pg_index
         WHERE indexrelid = 'provisioning_instructions_open_key'::regclass) AS open_idx_predicate;
