-- 040_trd2_typed_provenance.sql — TRD 2 typed alternative provenance (M2).
--
-- The canonical graph stays provider-neutral. Cloud rows keep connector_id,
-- cloud_scan_run and cloud_observation. Collector rows use integration_id,
-- iga_scan_runs and iga_observations. Composite foreign keys are
-- (workspace_id, id). 038 and 039 CHECK constraints are not dropped.
--
-- credential_id is the reserved third support arm for credential projection.
-- It is not added here; that projection is not enabled.
--
-- Relationship, access-edge and policy-assignment rows may name neither arm.
-- That grandfathers GitHub edges whose connector_id is null. The database does
-- not force a new collector row to carry integration_id. Go does: a confirming
-- collector run without integration_id is rejected in the repository, and the
-- collector writer always sets the integration arm. Both arms are refused.
--
-- Lock and runtime. The runner wraps this file in one transaction, so nothing
-- here uses CREATE INDEX CONCURRENTLY (that cannot run inside a transaction).
-- The new unique indexes are on columns this file adds; existing rows have
-- them NULL, so each build is a catalog write plus an empty partial index.
--
--   Statement                         Lock                         Notes
--   ADD COLUMN (nullable)             ACCESS EXCLUSIVE, brief      no table rewrite (PG 11+)
--   ADD COLUMN ordering_sequence      ACCESS EXCLUSIVE, brief      constant default, no rewrite
--   DROP NOT NULL                     ACCESS EXCLUSIVE, catalog    no rewrite
--   ADD CHECK / FK NOT VALID          ACCESS EXCLUSIVE /           no full-table scan
--                                     SHARE ROW EXCLUSIVE
--   CREATE UNIQUE INDEX               SHARE                        empty new columns; not CONCURRENTLY
--   VALIDATE CONSTRAINT               not in this file             scripts/validate-040-typed-provenance.sql
--
-- VALIDATE runs outside the deploy transaction and takes only
-- SHARE UPDATE EXCLUSIVE. Existing rows already satisfy the new checks:
-- the cloud columns were NOT NULL and the new columns start NULL.
-- Adding a check as VALID and validating a NOT VALID constraint in the same
-- transaction would still scan under ACCESS EXCLUSIVE, so this file does neither.
--
-- Re-runnable. No transaction wrapper (the runner applies each file with psql -1).
-- Down: forward-only. Rollback is the feature flag off; the new columns stay null.

-- Parents the new keys reference. 001 and 038 already UNIQUE (workspace_id, id).
-- 039 may add the same uniqueness under another name. Skip when any unique or
-- primary key already covers exactly those two columns.
DO $$
DECLARE
    parent text;
BEGIN
    FOREACH parent IN ARRAY ARRAY['iga_integrations', 'iga_scan_runs', 'iga_observations']
    LOOP
        IF NOT EXISTS (
            SELECT 1
              FROM pg_constraint c
              JOIN pg_class t ON t.oid = c.conrelid
              JOIN pg_namespace n ON n.oid = t.relnamespace
             WHERE n.nspname = 'public'
               AND t.relname = parent
               AND c.contype IN ('u', 'p')
               AND (
                    SELECT array_agg(a.attname::text ORDER BY k.ord)
                      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
                      JOIN pg_attribute a
                        ON a.attrelid = c.conrelid AND a.attnum = k.attnum
               ) = ARRAY['workspace_id', 'id']
        ) THEN
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I UNIQUE (workspace_id, id)',
                parent, parent || '_workspace_id_key');
        END IF;
    END LOOP;
END $$;

-- Alternative arm columns. Nullable: the checks below are the rule.
ALTER TABLE public.iga_object_support
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS confirming_iga_scan_run_id uuid;
ALTER TABLE public.iga_relationship
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS confirming_iga_scan_run_id uuid;
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS confirming_iga_scan_run_id uuid;
ALTER TABLE public.iga_policy_assignment
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS confirming_iga_scan_run_id uuid;
ALTER TABLE public.iga_access_edge_evidence
    ADD COLUMN IF NOT EXISTS iga_observation_id uuid;
ALTER TABLE public.iga_relationship_evidence
    ADD COLUMN IF NOT EXISTS iga_observation_id uuid;
ALTER TABLE public.iga_assignment_evidence
    ADD COLUMN IF NOT EXISTS iga_observation_id uuid;
ALTER TABLE public.iga_projection_job
    ADD COLUMN IF NOT EXISTS iga_scan_run_id uuid;
ALTER TABLE public.iga_projection_state
    ADD COLUMN IF NOT EXISTS integration_id uuid,
    ADD COLUMN IF NOT EXISTS last_iga_scan_run_id uuid;
ALTER TABLE public.iga_publication
    ADD COLUMN IF NOT EXISTS iga_scan_run_id uuid,
    ADD COLUMN IF NOT EXISTS source_manifest_v2 jsonb;
ALTER TABLE public.iga_pipeline_lease
    ADD COLUMN IF NOT EXISTS iga_scan_run_id uuid;

-- Which snapshot a batch belongs to. Null means a runtime batch. Set by
-- ingest when 040 is present. superseded_at records a batch the generation
-- fence rejected; projection_state stays 'queued' because 038's check does
-- not allow 'superseded'.
ALTER TABLE public.collector_batches
    ADD COLUMN IF NOT EXISTS snapshot_id uuid,
    ADD COLUMN IF NOT EXISTS superseded_at timestamptz;

-- Watermark for (integration, scope, class). last_generation is the highest
-- snapshot generation projected. ordering_snapshot is the snapshot_id that
-- set it. ordering_sequence is recorded and is not a tie-break: a different
-- snapshot of the same generation is projected, not superseded. Runtime
-- batches do not move any of these values.
ALTER TABLE public.iga_projection_state
    ADD COLUMN IF NOT EXISTS ordering_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS ordering_epoch uuid,
    ADD COLUMN IF NOT EXISTS ordering_snapshot uuid;

COMMENT ON COLUMN public.collector_batches.snapshot_id IS
    'Logical collector_snapshots.snapshot_id this batch belongs to. NULL is a runtime batch.';
COMMENT ON COLUMN public.collector_batches.superseded_at IS
    'Set when a newer snapshot generation for the same integration, scope and class already projected. The batch is not published. GET /receipts reports state superseded; these columns stay accepted and queued because 038 forbids projection_state superseded.';
COMMENT ON COLUMN public.iga_projection_state.ordering_sequence IS
    'Highest collector batch sequence recorded for the snapshot that set last_generation. Not a fence: another snapshot of the same generation is not superseded.';
COMMENT ON COLUMN public.iga_projection_state.ordering_epoch IS
    'Epoch of the snapshot that set last_generation. A copied watermark, not a foreign key: collector_snapshots.epoch is not unique.';
COMMENT ON COLUMN public.iga_projection_state.ordering_snapshot IS
    'collector_snapshots.snapshot_id that set last_generation. A copied watermark, not a foreign key: snapshot_id is unique only with workspace_id and collector_id. The same value on a later pass is a replay, not a newer snapshot.';

COMMENT ON COLUMN public.iga_object_support.integration_id IS
    'Collector owning source. credential_id is reserved for credential projection and is not created until that projection is enabled.';

-- The cloud arm keeps its meaning. It is nullable only so the collector arm
-- can be the one that is set. Existing rows keep the values they have.
ALTER TABLE public.iga_object_support ALTER COLUMN connector_id DROP NOT NULL;
ALTER TABLE public.iga_access_edge_evidence ALTER COLUMN observation_id DROP NOT NULL;
ALTER TABLE public.iga_relationship_evidence ALTER COLUMN observation_id DROP NOT NULL;
ALTER TABLE public.iga_assignment_evidence ALTER COLUMN observation_id DROP NOT NULL;
ALTER TABLE public.iga_projection_job
    ALTER COLUMN scan_run_id DROP NOT NULL,
    ALTER COLUMN connector_id DROP NOT NULL;
ALTER TABLE public.iga_projection_state
    ALTER COLUMN connector_id DROP NOT NULL,
    ALTER COLUMN last_run_id DROP NOT NULL;
ALTER TABLE public.iga_publication ALTER COLUMN scan_run_id DROP NOT NULL;

-- Exactly one arm where every existing row already has the cloud arm.
-- Relationship, access edge and policy assignment grandfather a row that
-- names neither arm (GitHub edges have a null connector_id). Both arms are
-- refused everywhere.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_object_support_arm_xor') THEN
        ALTER TABLE public.iga_object_support
            ADD CONSTRAINT iga_object_support_arm_xor CHECK (
                (connector_id IS NOT NULL)::int + (integration_id IS NOT NULL)::int = 1
                AND (last_confirmed_run_id IS NOT NULL)::int
                    + (confirming_iga_scan_run_id IS NOT NULL)::int <= 1
                AND (confirming_iga_scan_run_id IS NULL OR integration_id IS NOT NULL)
                AND (last_confirmed_run_id IS NULL OR connector_id IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_relationship_arm_xor') THEN
        ALTER TABLE public.iga_relationship
            ADD CONSTRAINT iga_relationship_arm_xor CHECK (
                (connector_id IS NOT NULL)::int + (integration_id IS NOT NULL)::int <= 1
                AND (last_confirmed_by IS NOT NULL)::int
                    + (confirming_iga_scan_run_id IS NOT NULL)::int <= 1
                AND (confirming_iga_scan_run_id IS NULL OR integration_id IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_access_edges_arm_xor') THEN
        ALTER TABLE public.iga_access_edges
            ADD CONSTRAINT iga_access_edges_arm_xor CHECK (
                (connector_id IS NOT NULL)::int + (integration_id IS NOT NULL)::int <= 1
                AND (last_confirmed_by IS NOT NULL)::int
                    + (confirming_iga_scan_run_id IS NOT NULL)::int <= 1
                AND (confirming_iga_scan_run_id IS NULL OR integration_id IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_policy_assignment_arm_xor') THEN
        ALTER TABLE public.iga_policy_assignment
            ADD CONSTRAINT iga_policy_assignment_arm_xor CHECK (
                (connector_id IS NOT NULL)::int + (integration_id IS NOT NULL)::int <= 1
                AND (last_confirmed_by IS NOT NULL)::int
                    + (confirming_iga_scan_run_id IS NOT NULL)::int <= 1
                AND (confirming_iga_scan_run_id IS NULL OR integration_id IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_access_edge_evidence_arm_xor') THEN
        ALTER TABLE public.iga_access_edge_evidence
            ADD CONSTRAINT iga_access_edge_evidence_arm_xor CHECK (
                (observation_id IS NOT NULL)::int + (iga_observation_id IS NOT NULL)::int = 1) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_relationship_evidence_arm_xor') THEN
        ALTER TABLE public.iga_relationship_evidence
            ADD CONSTRAINT iga_relationship_evidence_arm_xor CHECK (
                (observation_id IS NOT NULL)::int + (iga_observation_id IS NOT NULL)::int = 1) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_assignment_evidence_arm_xor') THEN
        ALTER TABLE public.iga_assignment_evidence
            ADD CONSTRAINT iga_assignment_evidence_arm_xor CHECK (
                (observation_id IS NOT NULL)::int + (iga_observation_id IS NOT NULL)::int = 1) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_projection_job_arm_xor') THEN
        ALTER TABLE public.iga_projection_job
            ADD CONSTRAINT iga_projection_job_arm_xor CHECK (
                (scan_run_id IS NOT NULL)::int + (iga_scan_run_id IS NOT NULL)::int = 1
                AND (scan_run_id IS NOT NULL) = (connector_id IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_projection_state_arm_xor') THEN
        ALTER TABLE public.iga_projection_state
            ADD CONSTRAINT iga_projection_state_arm_xor CHECK (
                (connector_id IS NOT NULL)::int + (integration_id IS NOT NULL)::int = 1
                AND (last_run_id IS NOT NULL)::int + (last_iga_scan_run_id IS NOT NULL)::int = 1
                AND (connector_id IS NOT NULL) = (last_run_id IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_publication_arm_xor') THEN
        ALTER TABLE public.iga_publication
            ADD CONSTRAINT iga_publication_arm_xor CHECK (
                (scan_run_id IS NOT NULL)::int + (iga_scan_run_id IS NOT NULL)::int = 1) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_pipeline_lease_arm_xor') THEN
        ALTER TABLE public.iga_pipeline_lease
            ADD CONSTRAINT iga_pipeline_lease_arm_xor CHECK (
                (scan_run_id IS NOT NULL)::int + (iga_scan_run_id IS NOT NULL)::int <= 1) NOT VALID;
    END IF;
END $$;

-- Idle means no run of either type. 027's check did not know the collector arm.
-- Replace it once. A later apply leaves the row alone so a validated check is
-- not dropped back to NOT VALID. VALIDATE is the separate script.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'iga_pipeline_lease_busy_chk'
           AND pg_get_constraintdef(oid) LIKE '%iga_scan_run_id%'
    ) THEN
        NULL;
    ELSE
        IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iga_pipeline_lease_busy_chk') THEN
            ALTER TABLE public.iga_pipeline_lease DROP CONSTRAINT iga_pipeline_lease_busy_chk;
        END IF;
        ALTER TABLE public.iga_pipeline_lease
            ADD CONSTRAINT iga_pipeline_lease_busy_chk CHECK (
                (state = 'idle') = (holder = '' AND scan_run_id IS NULL AND iga_scan_run_id IS NULL)) NOT VALID;
    END IF;
END $$;

-- Composite foreign keys, NOT VALID. VALIDATE is scripts/validate-040-typed-provenance.sql,
-- outside this transaction. A second apply skips the add.
DO $$
DECLARE
    fk record;
BEGIN
    FOR fk IN
        SELECT * FROM (VALUES
            ('iga_object_support_integration_fkey', 'iga_object_support', 'integration_id', 'iga_integrations'),
            ('iga_object_support_confirming_iga_run_fkey', 'iga_object_support', 'confirming_iga_scan_run_id', 'iga_scan_runs'),
            ('iga_relationship_integration_fkey', 'iga_relationship', 'integration_id', 'iga_integrations'),
            ('iga_relationship_confirming_iga_run_fkey', 'iga_relationship', 'confirming_iga_scan_run_id', 'iga_scan_runs'),
            ('iga_access_edges_integration_fkey', 'iga_access_edges', 'integration_id', 'iga_integrations'),
            ('iga_access_edges_confirming_iga_run_fkey', 'iga_access_edges', 'confirming_iga_scan_run_id', 'iga_scan_runs'),
            ('iga_policy_assignment_integration_fkey', 'iga_policy_assignment', 'integration_id', 'iga_integrations'),
            ('iga_policy_assignment_confirming_iga_run_fkey', 'iga_policy_assignment', 'confirming_iga_scan_run_id', 'iga_scan_runs'),
            ('iga_access_edge_evidence_iga_observation_fkey', 'iga_access_edge_evidence', 'iga_observation_id', 'iga_observations'),
            ('iga_relationship_evidence_iga_observation_fkey', 'iga_relationship_evidence', 'iga_observation_id', 'iga_observations'),
            ('iga_assignment_evidence_iga_observation_fkey', 'iga_assignment_evidence', 'iga_observation_id', 'iga_observations'),
            ('iga_projection_job_iga_run_fkey', 'iga_projection_job', 'iga_scan_run_id', 'iga_scan_runs'),
            ('iga_projection_state_integration_fkey', 'iga_projection_state', 'integration_id', 'iga_integrations'),
            ('iga_projection_state_iga_run_fkey', 'iga_projection_state', 'last_iga_scan_run_id', 'iga_scan_runs'),
            ('iga_publication_iga_run_fkey', 'iga_publication', 'iga_scan_run_id', 'iga_scan_runs'),
            ('iga_pipeline_lease_iga_run_fkey', 'iga_pipeline_lease', 'iga_scan_run_id', 'iga_scan_runs')
        ) AS t(conname, tbl, col, parent)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = fk.conname) THEN
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (workspace_id, %I) REFERENCES public.%I (workspace_id, id) NOT VALID',
                fk.tbl, fk.conname, fk.col, fk.parent);
        END IF;
    END LOOP;
END $$;

-- Collector conflict targets. Built in this transaction, not CONCURRENTLY:
-- the runner's transaction forbids CONCURRENTLY, and every indexed column is
-- new, so the partial indexes contain no existing rows.

-- The cloud unique indexes are not widened.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_identity_integration
    ON public.iga_object_support (workspace_id, identity_account_id, integration_id, partition_key)
    WHERE identity_account_id IS NOT NULL AND integration_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_workload_integration
    ON public.iga_object_support (workspace_id, workload_id, integration_id, partition_key)
    WHERE workload_id IS NOT NULL AND integration_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_resource_integration
    ON public.iga_object_support (workspace_id, resource_id, integration_id, partition_key)
    WHERE resource_id IS NOT NULL AND integration_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_entitlement_integration
    ON public.iga_object_support (workspace_id, entitlement_id, integration_id, partition_key)
    WHERE entitlement_id IS NOT NULL AND integration_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_policy_integration
    ON public.iga_object_support (workspace_id, policy_id, integration_id, partition_key)
    WHERE policy_id IS NOT NULL AND integration_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_aee_iga_observation
    ON public.iga_access_edge_evidence (workspace_id, access_edge_id, iga_observation_id, relation)
    WHERE iga_observation_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_re_iga_observation
    ON public.iga_relationship_evidence (workspace_id, relationship_id, iga_observation_id, relation)
    WHERE iga_observation_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_ae_iga_observation
    ON public.iga_assignment_evidence (workspace_id, assignment_id, iga_observation_id, relation)
    WHERE iga_observation_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_projection_job_iga_run
    ON public.iga_projection_job (workspace_id, iga_scan_run_id)
    WHERE iga_scan_run_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_projection_state_integration
    ON public.iga_projection_state (workspace_id, integration_id, partition_key)
    WHERE integration_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_publication_iga_run
    ON public.iga_publication (workspace_id, iga_scan_run_id)
    WHERE iga_scan_run_id IS NOT NULL;
