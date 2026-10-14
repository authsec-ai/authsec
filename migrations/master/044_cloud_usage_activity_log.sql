-- 044_cloud_usage_activity_log.sql — Azure Activity Log is usage evidence.
--
-- expand only. Widens cloud_usage_source_chk to admit 'activity_log'.
--
-- WHY A FOURTH SOURCE
-- 043 admitted Entra sign-ins: an identity obtained a token for a resource.
-- The Azure Activity Log is a different and stronger claim about a different
-- plane: an identity PERFORMED a management operation (an authorization action
-- such as Microsoft.Compute/virtualMachines/write) in a subscription. It is
-- what lets an Azure RBAC grant be shown as exercised or unused -- a sign-in to
-- Azure Resource Manager says nothing about which role was used.
--
-- Azure discovery aggregates the log to one row per identity per resource
-- provider namespace ("Microsoft.Compute"), never the raw events, which is the
-- (identity, service, source) grain 016 chose. As with 043, a separate source
-- because a reader must be able to tell which evidence produced a row.
--
-- No data changes: every value the old CHECK admitted is still admitted.

ALTER TABLE public.cloud_usage
    DROP CONSTRAINT IF EXISTS cloud_usage_source_chk;

ALTER TABLE public.cloud_usage
    ADD CONSTRAINT cloud_usage_source_chk CHECK (
        source IN ('service_last_accessed', 'cloudtrail', 'entra_sign_in', 'activity_log')
    );

-- verify ----------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'cloud_usage_source_chk'
           AND pg_get_constraintdef(oid) LIKE '%activity_log%'
    ) THEN
        RAISE EXCEPTION '044: cloud_usage_source_chk does not admit activity_log';
    END IF;
END $$;
