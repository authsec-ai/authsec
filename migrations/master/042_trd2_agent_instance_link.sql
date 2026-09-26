-- 042_trd2_agent_instance_link.sql — TRD 2 confirmed agent instances (M4).
--
-- A logical agent may have many deployed instances. One workload may host
-- several confirmed agent containers when the evidence distinguishes them.
-- Uniqueness is (workspace, workload, observation arm), never a global name.
--
-- observation_id is the collector arm (iga_observations). cloud_observation_id
-- is the AWS arm (cloud_observation). At most one arm is set. Both stay null
-- on a legacy instance that has no workload. An authoritative workload link
-- requires exactly one arm: that is what the unique indexes distinguish.
--
-- Weak and candidate links never set workload_id. The authority CHECK admits
-- a workload only with basis human_registration plus the actor, the owner
-- and the classification version the decision was made against. The join
-- table discovered_agent_workloads can store only weak or candidate strength,
-- so it cannot express authority. Go repeats the basis rule before any write.
--
-- 042 does not read or write 041 or 045. It applies on a database at 040.
--
-- Lock and runtime. The runner wraps this file in one transaction, so nothing
-- here uses CREATE INDEX CONCURRENTLY.
--
--   Statement                              Lock                         Notes
--   ADD UNIQUE (discovered_agents)         ACCESS EXCLUSIVE             (id) is already the primary key, so the new pair cannot conflict
--   ADD COLUMN (nullable)                  ACCESS EXCLUSIVE, brief      no table rewrite (PG 11+)
--   ADD CHECK / FK NOT VALID               ACCESS EXCLUSIVE /           no full-table scan; existing rows keep every new column null
--                                          SHARE ROW EXCLUSIVE
--   CREATE UNIQUE INDEX (partial)          SHARE                        new columns are null, so the index is empty
--   CREATE INDEX collector_batches         SHARE                        snapshot_id already exists (040); not an ON CONFLICT target
--   CREATE TABLE discovered_agent_workloads ACCESS EXCLUSIVE, brief      new empty table; its FKs are valid immediately
--   VALIDATE CONSTRAINT                    not in this file             scripts/validate-042-agent-instance-link.sql
--
-- ON DELETE CASCADE on the new instance keys: SET NULL of workload_id alone
-- would leave the authority columns set and fail the CHECK, and RESTRICT
-- would block the workspace cascade that already deletes iga_workload.
-- The instance is the deployment on that workload; it goes with the workload.
--
-- Re-runnable. No transaction wrapper (the runner applies each file with psql -1).
-- Down: forward-only.

-- discovered_agents has PRIMARY KEY (id) only. The join's composite FK needs
-- UNIQUE (workspace_id, id). Skip when any unique or primary key already
-- covers exactly those two columns.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = 'public'
           AND t.relname = 'discovered_agents'
           AND c.contype IN ('u', 'p')
           AND (
                SELECT array_agg(a.attname::text ORDER BY k.ord)
                  FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
                  JOIN pg_attribute a
                    ON a.attrelid = c.conrelid AND a.attnum = k.attnum
           ) = ARRAY['workspace_id', 'id']
    ) THEN
        ALTER TABLE public.discovered_agents
            ADD CONSTRAINT discovered_agents_workspace_id_key UNIQUE (workspace_id, id);
    END IF;
END $$;

-- Nullable. Existing rows stay all-null and fail none of the checks below.
ALTER TABLE public.iga_agent_instances
    ADD COLUMN IF NOT EXISTS workload_id uuid,
    ADD COLUMN IF NOT EXISTS observation_id uuid,
    ADD COLUMN IF NOT EXISTS cloud_observation_id uuid,
    ADD COLUMN IF NOT EXISTS workload_link_basis text,
    ADD COLUMN IF NOT EXISTS linked_by uuid,
    ADD COLUMN IF NOT EXISTS owner_user_id uuid,
    ADD COLUMN IF NOT EXISTS link_purpose text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS classification_version bigint;

COMMENT ON COLUMN public.iga_agent_instances.workload_id IS
    'Canonical iga_workload this instance is registered on. Null on a legacy instance. Set only by a human registration.';
COMMENT ON COLUMN public.iga_agent_instances.observation_id IS
    'Collector evidence arm (iga_observations). Mutually exclusive with cloud_observation_id.';
COMMENT ON COLUMN public.iga_agent_instances.cloud_observation_id IS
    'Cloud evidence arm (cloud_observation). AWS workload evidence lives here, not in iga_observations. Mutually exclusive with observation_id.';
COMMENT ON COLUMN public.iga_agent_instances.workload_link_basis IS
    'human_registration when workload_id is set. No other basis may name a workload: a weak or candidate name match is not authority.';
COMMENT ON COLUMN public.iga_agent_instances.linked_by IS
    'The verified human who registered the instance. users is not an iga_* table; the value is recorded, not a foreign key, matching iga_workload_classification.decided_by_user_id.';
COMMENT ON COLUMN public.iga_agent_instances.owner_user_id IS
    'The accountable human named by the registration. Same bare-uuid treatment as linked_by.';
COMMENT ON COLUMN public.iga_agent_instances.classification_version IS
    'iga_workload.classification_version the registration was made against. Registration does not bump it.';

-- Authority is all-or-nothing, and a workload requires exactly one evidence
-- arm. NOT VALID: existing rows are all-null and are not scanned here.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_agent_instances_workload_authority_chk') THEN
        ALTER TABLE public.iga_agent_instances
            ADD CONSTRAINT iga_agent_instances_workload_authority_chk CHECK (
                (
                    workload_id IS NULL
                    AND workload_link_basis IS NULL
                    AND linked_by IS NULL
                    AND owner_user_id IS NULL
                    AND classification_version IS NULL
                )
                OR
                (
                    workload_id IS NOT NULL
                    AND workload_link_basis = 'human_registration'
                    AND linked_by IS NOT NULL
                    AND owner_user_id IS NOT NULL
                    AND classification_version IS NOT NULL
                    AND (observation_id IS NOT NULL)::int
                        + (cloud_observation_id IS NOT NULL)::int = 1
                )
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_agent_instances_observation_arm_chk') THEN
        ALTER TABLE public.iga_agent_instances
            ADD CONSTRAINT iga_agent_instances_observation_arm_chk CHECK (
                (observation_id IS NOT NULL)::int
                    + (cloud_observation_id IS NOT NULL)::int <= 1
            ) NOT VALID;
    END IF;
END $$;

-- Composite foreign keys, NOT VALID. VALIDATE is
-- scripts/validate-042-agent-instance-link.sql, outside this transaction.
DO $$
DECLARE
    fk record;
BEGIN
    FOR fk IN
        SELECT * FROM (VALUES
            ('iga_agent_instances_workload_fkey', 'workload_id', 'iga_workload'),
            ('iga_agent_instances_observation_fkey', 'observation_id', 'iga_observations'),
            ('iga_agent_instances_cloud_observation_fkey', 'cloud_observation_id', 'cloud_observation')
        ) AS t(conname, col, parent)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = fk.conname) THEN
            EXECUTE format(
                'ALTER TABLE public.iga_agent_instances ADD CONSTRAINT %I FOREIGN KEY (workspace_id, %I) REFERENCES public.%I (workspace_id, id) ON DELETE CASCADE NOT VALID',
                fk.conname, fk.col, fk.parent);
        END IF;
    END LOOP;
END $$;

-- One instance per (workload, evidence). A second agent citing the same
-- evidence is a conflict, not a silent reattach. A name is not part of the key.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agent_instances_workload_observation
    ON public.iga_agent_instances (workspace_id, workload_id, observation_id)
    WHERE workload_id IS NOT NULL AND observation_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agent_instances_workload_cloud_observation
    ON public.iga_agent_instances (workspace_id, workload_id, cloud_observation_id)
    WHERE workload_id IS NOT NULL AND cloud_observation_id IS NOT NULL;

-- Candidate triage. Strength cannot be strong: this table never authorizes
-- an instance. evidence columns are the observation arms; the registration
-- decision itself is the iga_agent_instances row, not a second authority here.
CREATE TABLE IF NOT EXISTS public.discovered_agent_workloads (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    discovered_agent_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    observation_id uuid,
    cloud_observation_id uuid,
    link_strength text NOT NULL DEFAULT 'candidate',
    link_state text NOT NULL DEFAULT 'proposed',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovered_agent_workloads_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agent_workloads_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT discovered_agent_workloads_pair_key
        UNIQUE (workspace_id, discovered_agent_id, workload_id),
    CONSTRAINT discovered_agent_workloads_workspace_fkey
        FOREIGN KEY (workspace_id) REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_workloads_agent_fkey
        FOREIGN KEY (workspace_id, discovered_agent_id)
        REFERENCES public.discovered_agents (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_workloads_workload_fkey
        FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_workloads_observation_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.iga_observations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_workloads_cloud_observation_fkey
        FOREIGN KEY (workspace_id, cloud_observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT discovered_agent_workloads_strength_chk CHECK (
        link_strength IN ('weak', 'candidate')),
    CONSTRAINT discovered_agent_workloads_state_chk CHECK (
        link_state IN ('proposed', 'accepted', 'rejected')),
    CONSTRAINT discovered_agent_workloads_arm_chk CHECK (
        (observation_id IS NOT NULL)::int
            + (cloud_observation_id IS NOT NULL)::int <= 1)
);

COMMENT ON TABLE public.discovered_agent_workloads IS
    'Candidate or weak link from a legacy discovered_agents row to a canonical workload. link_strength cannot be strong: accepting a name match does not set iga_agent_instances.workload_id.';

-- Operator read of stuck snapshots joins batches to a logical snapshot_id.
-- 040 stores that id as a copied watermark. It is not a foreign key: uniqueness
-- is (workspace_id, collector_id, snapshot_id). This index is not an upsert target.
CREATE INDEX IF NOT EXISTS idx_collector_batches_snapshot
    ON public.collector_batches (workspace_id, collector_id, snapshot_id)
    WHERE snapshot_id IS NOT NULL;
