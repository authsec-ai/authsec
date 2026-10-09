-- ============================================================================
-- 023: give EXISTING databases the enforcement columns that only new ones have.
--
-- The enforcement work added seven columns to discovery_sources by editing
-- 001_bootstrap.sql and adding no numbered migration. A database created from
-- that bootstrap has them. A database created earlier -- production -- never
-- did, and never would, because nothing replays bootstrap against a live
-- database.
--
-- Found by restoring the production schema into a scratch database and running
-- the suite against it: 34 tests failed there against 7 on a fresh bootstrap,
-- every one of them on
--
--     column "enforcement_mode" of relation "discovery_sources" does not exist
--
-- Deploying the current binary without this would have put code that reads and
-- writes those columns in front of a table that does not have them. Not a
-- startup failure -- the pods would come up healthy and the enforcement paths
-- would fail at the moment a customer used them, which is the worse shape.
--
-- WHY THIS KEEPS HAPPENING. Adding a column to bootstrap is the obvious move
-- and it is silently wrong: bootstrap is the schema for a database that does
-- not exist yet. Every column an existing database needs has to arrive as a
-- numbered migration, and bootstrap mirrors it so the two paths agree. The
-- check at the end of this file is one way to notice; comparing a restored
-- production schema against a fresh bootstrap before every release is better.
--
-- IF-NOT-EXISTS throughout, so this is a no-op on the databases that already
-- have the columns.
-- ============================================================================

ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_mode text NOT NULL DEFAULT '';

ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforced_plan_version bigint;

ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforced_plan_at timestamptz;

ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_denials_total bigint NOT NULL DEFAULT 0;

-- The three actions a plan may authorise. Default false: an existing source
-- must not acquire the ability to evict or delete anything by being migrated.
ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_evict boolean NOT NULL DEFAULT false;

ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_delete boolean NOT NULL DEFAULT false;

ALTER TABLE public.discovery_sources
    ADD COLUMN IF NOT EXISTS enforcement_force_evict boolean NOT NULL DEFAULT false;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.discovery_sources'::regclass
           AND conname = 'discovery_sources_enf_mode_chk'
    ) THEN
        ALTER TABLE public.discovery_sources
            ADD CONSTRAINT discovery_sources_enf_mode_chk
            CHECK (enforcement_mode IN ('', 'observe', 'evict', 'deny'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_discovery_sources_enforcing
    ON public.discovery_sources(workspace_id, enforced_plan_at DESC)
    WHERE enforcement_mode <> '';

COMMENT ON COLUMN public.discovery_sources.enforcement_mode IS
    '"" | observe | evict | deny. Empty means enforcement was never configured '
    'for this source, which is not the same as configured-and-off.';

-- verify -------------------------------------------------------------------
SELECT count(*) AS enforcement_columns
  FROM information_schema.columns
 WHERE table_schema = 'public' AND table_name = 'discovery_sources'
   AND column_name IN ('enforcement_mode','enforced_plan_version','enforced_plan_at',
                       'enforcement_denials_total','enforcement_evict',
                       'enforcement_delete','enforcement_force_evict');
