-- 045_ad_hardening_posture.sql — AD hardening and directory posture (WP-A9 part 1).
--
-- Depends on 039. Does not depend on 041 or 042: those files may be absent.
-- Does not edit 001–040.
--
-- Hardening carried over from the A9a review:
--   * composite (workspace_id, …) foreign keys beside 039's single-column ones
--   * CHECK ad_tracking_mode / tracking_mode IN ('usn'), so a dirsync write
--     cannot land even if the API check is bypassed
--
-- Posture (D03) is evidence only. No secrets, no findings, no alerts.
-- A partial row must not store privileged = false or admin_count_orphan = true:
-- those values assert "not privileged" / "no privileged path".
--
-- Lock and runtime. The runner wraps this file in one transaction, so nothing
-- here uses CREATE INDEX CONCURRENTLY or VALIDATE CONSTRAINT.
--
--   Statement                              Lock                         Notes
--   ADD UNIQUE (workspace_id, id)          ACCESS EXCLUSIVE             id is already unique; index build
--   ADD CHECK NOT VALID                    ACCESS EXCLUSIVE             no full-table scan
--   ADD FK NOT VALID                       SHARE ROW EXCLUSIVE          no full-table scan
--   CREATE TABLE ad_directory_posture      ACCESS EXCLUSIVE on new rel  empty table
--   VALIDATE + DROP of 039 single-column   not in this file             scripts/validate-045-ad-hardening.sql
--                                          FKs
--
-- VALIDATE takes SHARE UPDATE EXCLUSIVE and runs outside the deploy
-- transaction. The 039 single-column names (ad_inventory_scopes_config_fkey,
-- ad_inventory_runs_config_fkey, ad_directory_instances_config_fkey,
-- ad_inventory_cursors_scope_fkey) are not referenced by views, functions, or
-- application SQL. They are dropped in the validate script only after the
-- composite keys are validated.
--
-- Re-runnable. No transaction wrapper (the runner applies each file with psql -1).
-- Down: forward-only. The new keys and the posture table stay.

-- Parents the new keys reference. 039's primary keys are (id) only.
-- The unique names are sync_configurations_workspace_id_key,
-- ad_inventory_scopes_workspace_id_key and ad_inventory_runs_workspace_id_key.
-- Skip when any unique or primary key already covers exactly (workspace_id, id).
DO $$
DECLARE
    parent text;
BEGIN
    FOREACH parent IN ARRAY ARRAY[
        'sync_configurations',
        'ad_inventory_scopes',
        'ad_inventory_runs'
    ]
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

-- The API already rejects dirsync. These checks make the database refuse it
-- too. Existing rows are 'usn' (039's default). NOT VALID skips the scan;
-- scripts/validate-045-ad-hardening.sql validates them.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'sync_configurations_ad_tracking_mode_chk'
    ) THEN
        ALTER TABLE public.sync_configurations
            ADD CONSTRAINT sync_configurations_ad_tracking_mode_chk
            CHECK (ad_tracking_mode IN ('usn')) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ad_inventory_cursors_tracking_mode_chk'
    ) THEN
        ALTER TABLE public.ad_inventory_cursors
            ADD CONSTRAINT ad_inventory_cursors_tracking_mode_chk
            CHECK (tracking_mode IN ('usn')) NOT VALID;
    END IF;
END $$;

-- Composite keys beside 039's single-column ones. ON DELETE CASCADE matches
-- the keys they replace. NOT VALID: VALIDATE is the script, not this file.
DO $$
DECLARE
    fk record;
BEGIN
    FOR fk IN
        SELECT * FROM (VALUES
            ('ad_inventory_scopes_config_ws_fkey', 'ad_inventory_scopes', 'sync_config_id', 'sync_configurations'),
            ('ad_inventory_runs_config_ws_fkey', 'ad_inventory_runs', 'sync_config_id', 'sync_configurations'),
            ('ad_directory_instances_config_ws_fkey', 'ad_directory_instances', 'sync_config_id', 'sync_configurations'),
            ('ad_inventory_cursors_scope_ws_fkey', 'ad_inventory_cursors', 'scope_id', 'ad_inventory_scopes')
        ) AS t(conname, child, col, parent)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = fk.conname) THEN
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (workspace_id, %I) REFERENCES public.%I (workspace_id, id) ON DELETE CASCADE NOT VALID',
                fk.child, fk.conname, fk.col, fk.parent);
        END IF;
    END LOOP;
END $$;

-- One row per directory account observed in one inventory run.
-- privileged = false and admin_count_orphan = true are assertions. A partial
-- read must not make them: privileged stays NULL (or TRUE, when a path was
-- actually seen) and admin_count_orphan stays NULL or FALSE.
CREATE TABLE IF NOT EXISTS public.ad_directory_posture (
    id                       uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id             uuid NOT NULL,
    run_id                   uuid NOT NULL,
    object_guid              text NOT NULL,
    object_sid               text NOT NULL DEFAULT '',
    account_kind             text NOT NULL,
    distinguished_name       text NOT NULL DEFAULT '',
    sam_account_name         text NOT NULL DEFAULT '',
    coverage                 text NOT NULL,
    partial_reasons          jsonb NOT NULL DEFAULT '[]'::jsonb,
    unconstrained_delegation boolean NOT NULL DEFAULT false,
    constrained_delegation   boolean NOT NULL DEFAULT false,
    protocol_transition      boolean NOT NULL DEFAULT false,
    delegation_targets       jsonb NOT NULL DEFAULT '[]'::jsonb,
    rbcd_principals          jsonb NOT NULL DEFAULT '[]'::jsonb,
    rbcd_asserted            boolean NOT NULL DEFAULT false,
    privileged               boolean,
    privileged_direct        boolean NOT NULL DEFAULT false,
    privileged_nested        boolean NOT NULL DEFAULT false,
    privileged_path          jsonb NOT NULL DEFAULT '[]'::jsonb,
    admin_count              boolean NOT NULL DEFAULT false,
    admin_count_orphan       boolean,
    sensitive_not_delegated  boolean NOT NULL DEFAULT false,
    protected_users          boolean NOT NULL DEFAULT false,
    gmsa                     boolean NOT NULL DEFAULT false,
    smsa                     boolean NOT NULL DEFAULT false,
    depth_exceeded           boolean NOT NULL DEFAULT false,
    account_disabled         boolean NOT NULL DEFAULT false,
    created_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ad_directory_posture_pkey PRIMARY KEY (id),
    CONSTRAINT ad_directory_posture_run_object UNIQUE (workspace_id, run_id, object_guid),
    CONSTRAINT ad_directory_posture_coverage_chk CHECK (coverage IN ('complete', 'partial')),
    CONSTRAINT ad_directory_posture_privileged_chk CHECK (
        privileged IS DISTINCT FROM false OR coverage = 'complete'),
    CONSTRAINT ad_directory_posture_orphan_chk CHECK (
        admin_count_orphan IS NOT TRUE OR coverage = 'complete'),
    CONSTRAINT ad_directory_posture_depth_chk CHECK (
        depth_exceeded = false OR coverage = 'partial')
);

-- A database that applied an earlier draft of this unshipped file already
-- has the table. CREATE TABLE IF NOT EXISTS does not add the new column.
ALTER TABLE public.ad_directory_posture
    ADD COLUMN IF NOT EXISTS protected_users boolean NOT NULL DEFAULT false;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ad_directory_posture_run_fkey') THEN
        ALTER TABLE public.ad_directory_posture
            ADD CONSTRAINT ad_directory_posture_run_fkey
            FOREIGN KEY (workspace_id, run_id)
            REFERENCES public.ad_inventory_runs (workspace_id, id)
            ON DELETE CASCADE
            NOT VALID;
    END IF;
END $$;

COMMENT ON TABLE public.ad_directory_posture IS
    'D03 delegation and privileged-group evidence for one inventory run. No secrets and no findings. coverage=partial never stores privileged=false.';
COMMENT ON COLUMN public.ad_directory_posture.privileged IS
    'TRUE when a privileged path was observed. FALSE only when coverage is complete and no path exists. NULL when the read cannot support a negative.';
COMMENT ON COLUMN public.ad_directory_posture.admin_count_orphan IS
    'TRUE only when coverage is complete, adminCount is set, and no privileged path exists. NULL when that negative is not supported.';
COMMENT ON COLUMN public.ad_directory_posture.rbcd_principals IS
    'SIDs parsed from msDS-AllowedToActOnBehalfOfOtherIdentity. The security descriptor itself is not stored.';
COMMENT ON COLUMN public.ad_directory_posture.account_disabled IS
    'userAccountControl ACCOUNTDISABLE. Recorded as an ITDR input; this table does not raise a finding.';
COMMENT ON COLUMN public.ad_directory_posture.protected_users IS
    'TRUE when a Protected Users (domain RID 525) path was observed. Membership restricts NTLM, delegation, and caching; it is not a privilege. FALSE means that path was not observed. A partial read is not proof of absence.';
