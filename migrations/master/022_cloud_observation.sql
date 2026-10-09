-- ============================================================================
-- 022: evidence for what the cloud collectors wrote.
--
-- Every cloud_identity, cloud_permission, cloud_resource and cloud_workload row
-- is an assertion about a customer's account, and until now none of them could
-- say where it came from. "This role may assume that one" was a row with a
-- generation stamp and nothing else -- no record of which API returned it, when
-- AWS considered it true, or under what coverage the read happened. A reviewer
-- asked to act on it had to trust it.
--
-- WHY NOT iga_observations. That table exists and is the same idea, but its
-- provenance anchor is a foreign key to iga_scan_runs -- the GitHub pipeline's
-- run table. The AWS connector does not create iga_scan_runs rows, and
-- 017's header says plainly that making it do so would be forcing AWS into the
-- canonical iga_* pipeline, which is an architecture decision a collector
-- feature must not take on its own. cloud_scan_run (020) is the cloud path's
-- own anchor, and it now exists, so the evidence can hang off it.
--
-- WHY TYPED SUBJECT COLUMNS AND NOT (subject_kind, subject_id). A text
-- discriminator beside a bare uuid is not a foreign key: nothing stops it
-- naming a row in another workspace, or a row that does not exist. That exact
-- shape is the open cross-tenant defect in the iga_* tables. Four nullable
-- foreign keys with a check that exactly one is set costs four columns and buys
-- referential integrity the database enforces.
--
-- WHY THE HASH IS OF REDACTED CONTENT. The hash exists so an unchanged re-read
-- produces no new row. Hashing the raw AWS response would fix a deterministic
-- derivative of material we refused to store -- a Lambda environment variable
-- value, say -- so the order is: response, delete sensitive fields, canonical
-- form, hash. The writer enforces it; this comment records why.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_observation (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The run that produced this fact. RESTRICT, not CASCADE: evidence must not
    -- disappear because someone pruned a scan. Retention is a deliberate policy
    -- with an auditable outcome, never a side effect of housekeeping.
    scan_run_id uuid NOT NULL
        REFERENCES public.cloud_scan_run(id) ON DELETE RESTRICT,
    generation integer NOT NULL,

    -- Exactly one subject. See the header on why these are typed columns.
    identity_id uuid REFERENCES public.cloud_identity(id) ON DELETE CASCADE,
    permission_id uuid REFERENCES public.cloud_permission(id) ON DELETE CASCADE,
    resource_id uuid REFERENCES public.cloud_resource(id) ON DELETE CASCADE,
    workload_id uuid REFERENCES public.cloud_workload(id) ON DELETE CASCADE,

    -- The AWS call this came from, e.g. "iam:GetRole", "lambda:ListFunctions".
    -- Named as the API, not as our surface, so a reader can go and make the
    -- same call.
    source_api text NOT NULL,

    -- The surface this read belonged to and what its coverage said AT THE TIME.
    -- A fact collected during a partial scan stays readable as such a year
    -- later; without it, yesterday's degraded read is indistinguishable from
    -- today's clean one.
    surface text NOT NULL DEFAULT '',
    surface_state text NOT NULL DEFAULT '',

    -- When the PROVIDER's data was true, versus when we stored it. Conflating
    -- them makes a delayed scan look like a change in the account.
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),

    -- What AWS said, after redaction. Never a raw response.
    sanitized_facts jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Hash of sanitized_facts, so an unchanged re-read writes nothing.
    content_hash text NOT NULL,

    CONSTRAINT cloud_observation_subject_chk CHECK (
        (identity_id IS NOT NULL)::int
      + (permission_id IS NOT NULL)::int
      + (resource_id IS NOT NULL)::int
      + (workload_id IS NOT NULL)::int = 1
    ),
    CONSTRAINT cloud_observation_source_api_chk CHECK (source_api <> ''),
    CONSTRAINT cloud_observation_hash_chk CHECK (content_hash <> ''),
    CONSTRAINT cloud_observation_generation_chk CHECK (generation > 0)
);

-- Re-reading unchanged data must not grow the table.
--
-- Keyed on the subject columns rather than a single subject id because that is
-- what exists; COALESCE gives one comparable value without reintroducing a
-- polymorphic column.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_observation_dedupe
    ON public.cloud_observation (
        workspace_id,
        COALESCE(identity_id, permission_id, resource_id, workload_id),
        source_api,
        content_hash
    );

-- "Why do you believe this?" -- newest evidence for one row, which is the
-- question the evidence drawer asks.
CREATE INDEX IF NOT EXISTS idx_cloud_observation_identity
    ON public.cloud_observation (workspace_id, identity_id, observed_at DESC)
    WHERE identity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cloud_observation_permission
    ON public.cloud_observation (workspace_id, permission_id, observed_at DESC)
    WHERE permission_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cloud_observation_workload
    ON public.cloud_observation (workspace_id, workload_id, observed_at DESC)
    WHERE workload_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cloud_observation_resource
    ON public.cloud_observation (workspace_id, resource_id, observed_at DESC)
    WHERE resource_id IS NOT NULL;

-- "What did this run see?" -- for a scan report.
CREATE INDEX IF NOT EXISTS idx_cloud_observation_run
    ON public.cloud_observation (workspace_id, scan_run_id);

COMMENT ON TABLE public.cloud_observation IS
    'Why a cloud_* row exists: which AWS call returned it, when the provider '
    'considered it true, and what coverage the read had. Anchored on '
    'cloud_scan_run, not iga_scan_runs -- the AWS path has its own run table.';
COMMENT ON COLUMN public.cloud_observation.content_hash IS
    'Hash of sanitized_facts, computed AFTER redaction. Hashing the raw '
    'response would retain a deterministic derivative of material we refused '
    'to store.';
COMMENT ON COLUMN public.cloud_observation.surface_state IS
    'The surface coverage state when this was collected, so a fact read during '
    'a partial scan stays readable as such later.';

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.cloud_observation') AS observation_table,
       (SELECT count(*) FROM pg_constraint
         WHERE conrelid = 'public.cloud_observation'::regclass AND contype = 'c') AS checks;
