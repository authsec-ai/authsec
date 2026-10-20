-- 142_cloud_usage_entra_sign_in.sql — Entra sign-ins are usage evidence.
--
-- expand only. Widens cloud_usage_source_chk to admit 'entra_sign_in'.
--
-- WHY A THIRD SOURCE
-- cloud_usage records that an identity actually exercised a service, and
-- `source` says which evidence produced the row because the sources support
-- different claims (016). Azure has neither of AWS's: there is no
-- service-last-accessed report, and the Activity Log records management
-- writes, not the token an application obtained to call an API.
--
-- What Azure does record is the sign-in: every time a service principal or a
-- managed identity obtains a token, Entra logs which identity, for which
-- resource (Microsoft Graph, Key Vault, Azure OpenAI ...), from where. Azure
-- identity discovery aggregates those sign-ins to one row per identity per
-- resource -- never the raw events -- which is the same (identity, service,
-- source) grain 016 chose. It is a different claim from either AWS source
-- ("obtained a token for this resource", not "called this action"), so it is
-- a different source rather than a reuse of 'cloudtrail'.
--
-- No data changes: every value the old CHECK admitted is still admitted.

-- Only ever widened: a constraint that already admits 'entra_sign_in' (the
-- bootstrap's, or one a later migration widened further) is left as it is,
-- so this never narrows it under rows a later source wrote.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'cloud_usage_source_chk'
           AND pg_get_constraintdef(oid) LIKE '%entra_sign_in%'
    ) THEN
        ALTER TABLE public.cloud_usage
            DROP CONSTRAINT IF EXISTS cloud_usage_source_chk;
        ALTER TABLE public.cloud_usage
            ADD CONSTRAINT cloud_usage_source_chk CHECK (
                source IN ('service_last_accessed', 'cloudtrail', 'entra_sign_in')
            );
    END IF;
END $$;

-- verify ----------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'cloud_usage_source_chk'
           AND pg_get_constraintdef(oid) LIKE '%entra_sign_in%'
    ) THEN
        RAISE EXCEPTION '142: cloud_usage_source_chk does not admit entra_sign_in';
    END IF;
END $$;
