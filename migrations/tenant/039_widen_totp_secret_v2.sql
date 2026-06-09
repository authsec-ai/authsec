-- 039_widen_totp_secret_v2.sql
--
-- Re-applies the TOTP secret widening from 037. Tenants created from the
-- template snapshot have 037 marked applied-without-running, so the column was
-- never actually widened on them (it stayed varchar(64)) and the encrypted,
-- base64 AES-256-GCM secret (~80 chars) overflows. 037 won't re-run there
-- because it's already tracked — so we ship the same change under a fresh,
-- untracked version that migrate-all will execute everywhere. Idempotent:
-- guards on table existence and the ALTER is a no-op where the column is
-- already varchar(255). The template now also defines varchar(255) directly.
DO $$
BEGIN
    IF to_regclass('public.tenant_totp_secrets') IS NOT NULL THEN
        ALTER TABLE public.tenant_totp_secrets ALTER COLUMN secret TYPE varchar(255);
    END IF;
    IF to_regclass('public.totp_secrets') IS NOT NULL THEN
        ALTER TABLE public.totp_secrets ALTER COLUMN secret TYPE varchar(255);
    END IF;
END $$;
