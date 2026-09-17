-- ============================================================================
-- 019: record what constrains a permission, not just what it grants.
--
-- Discovery was storing the generous half of every policy statement and
-- discarding the half that narrows it. A statement's Condition was dropped at
-- parse time, a statement written with NotAction disappeared entirely, a
-- NotResource was widened to "*", and a role's permissions boundary -- already
-- present in the GetRole response -- was never read.
--
-- Each of those makes a permission read as BROADER than it is, which is the
-- dangerous direction for a governance product: a reviewer is shown access the
-- principal does not have, approves around it, and the record says we checked.
--
-- Nothing here evaluates anything. AWS remains the authority on whether a
-- request is allowed; these columns record what the documents say so the
-- console can stop claiming unconditional access it never verified.
-- ============================================================================

-- NotAction: "every action except these". A statement carrying it used to be
-- skipped, taking any Deny it expressed with it.
ALTER TABLE public.cloud_permission
    ADD COLUMN IF NOT EXISTS not_actions text[];

-- NotResource: "every resource except these". Previously collapsed into a
-- resource_id=NULL row indistinguishable from a genuine account-wide grant.
ALTER TABLE public.cloud_permission
    ADD COLUMN IF NOT EXISTS not_resources text[];

-- The Condition block verbatim. jsonb, not text, so a later evaluator can index
-- and query condition keys without reparsing every row.
ALTER TABLE public.cloud_permission
    ADD COLUMN IF NOT EXISTS condition jsonb;

-- How far this row may be trusted as a statement of access.
--
-- The default is 'unknown', NOT 'unconstrained'. Every row that exists when this
-- migration runs was collected by a scanner that discarded conditions and
-- negations, so we genuinely do not know whether it was constrained. Defaulting
-- to 'unconstrained' would stamp "we checked and it is unrestricted" onto rows
-- nobody checked -- the same over-claim these columns exist to prevent, just
-- moved into a backfill.
--
-- Rows leave 'unknown' when a scan that parses constraints rewrites them.
ALTER TABLE public.cloud_permission
    ADD COLUMN IF NOT EXISTS constraint_state text NOT NULL DEFAULT 'unknown';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_permission_constraint_state_chk'
    ) THEN
        ALTER TABLE public.cloud_permission
            ADD CONSTRAINT cloud_permission_constraint_state_chk
            CHECK (constraint_state IN
                ('unknown','unconstrained','conditional','negated','bounded'));
    END IF;
END $$;

-- A row carrying a Condition is never 'unconstrained'. The check is here rather
-- than in application code because the whole point is that no future writer can
-- quietly record a conditional grant as a plain one.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_permission_condition_state_chk'
    ) THEN
        ALTER TABLE public.cloud_permission
            ADD CONSTRAINT cloud_permission_condition_state_chk
            CHECK (condition IS NULL OR constraint_state <> 'unconstrained');
    END IF;
END $$;

-- Same for a negated statement: NotAction or NotResource means the extent
-- depends on what else exists in the account, so it cannot read as plain.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_permission_negation_state_chk'
    ) THEN
        ALTER TABLE public.cloud_permission
            ADD CONSTRAINT cloud_permission_negation_state_chk
            CHECK (
                (COALESCE(array_length(not_actions, 1), 0) = 0
                 AND COALESCE(array_length(not_resources, 1), 0) = 0)
                OR constraint_state <> 'unconstrained'
            );
    END IF;
END $$;

-- Two existing constraints block the fixes above and must move with them.
--
-- 1. actions was required non-empty. A statement written with NotAction has NO
--    Action element, so the old check made recording it impossible -- which is
--    part of why such statements were silently dropped. The rule becomes: a
--    statement must say which actions it is about, through one element or the
--    other.
ALTER TABLE public.cloud_permission
    DROP CONSTRAINT IF EXISTS cloud_permission_actions_chk;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_permission_actions_present_chk'
    ) THEN
        ALTER TABLE public.cloud_permission
            ADD CONSTRAINT cloud_permission_actions_present_chk
            CHECK (
                COALESCE(array_length(actions, 1), 0) > 0
                OR COALESCE(array_length(not_actions, 1), 0) > 0
            );
    END IF;
END $$;

-- 2. derivation allowed only 'granted' and 'effective'. A permissions boundary
--    is neither: it is a ceiling. It needs its own value so no query counts a
--    boundary statement as access the identity was given.
ALTER TABLE public.cloud_permission
    DROP CONSTRAINT IF EXISTS cloud_permission_derivation_chk;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_permission_derivation_v2_chk'
    ) THEN
        ALTER TABLE public.cloud_permission
            ADD CONSTRAINT cloud_permission_derivation_v2_chk
            CHECK (derivation IN ('granted', 'effective', 'boundary'));
    END IF;
END $$;

COMMENT ON COLUMN public.cloud_permission.not_actions IS
    'NotAction element: every action EXCEPT these. Never empty-means-none - a '
    'row with not_actions and no actions is a very broad statement.';
COMMENT ON COLUMN public.cloud_permission.not_resources IS
    'NotResource element, verbatim. Must never be widened to ''*''.';
COMMENT ON COLUMN public.cloud_permission.condition IS
    'Condition block as AWS returned it. Stored, never evaluated.';
COMMENT ON COLUMN public.cloud_permission.constraint_state IS
    'unknown | unconstrained | conditional | negated | bounded. Only '
    '''unconstrained'' may be rendered as plain access; ''unknown'' means the row '
    'predates constraint collection and has not been rescanned.';

-- Finding every grant that is capped or conditional is the query a reviewer
-- runs; without this it is a sequential scan of the whole permission table.
CREATE INDEX IF NOT EXISTS idx_cloud_permission_constrained
    ON public.cloud_permission (workspace_id, identity_id)
    WHERE constraint_state <> 'unconstrained';

-- Any row already present predates constraint collection. Say so explicitly
-- rather than relying on the column default, so the intent survives a reader
-- who only greps for UPDATE.
UPDATE public.cloud_permission
   SET constraint_state = 'unknown'
 WHERE constraint_state = 'unconstrained';

-- verify -------------------------------------------------------------------
SELECT count(*) AS new_columns
  FROM information_schema.columns
 WHERE table_schema = 'public' AND table_name = 'cloud_permission'
   AND column_name IN ('not_actions','not_resources','condition','constraint_state');
