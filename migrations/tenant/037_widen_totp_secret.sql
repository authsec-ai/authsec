-- Widen TOTP secret columns in tenant databases so they can hold the
-- AES-256-GCM ciphertext (base64) of the TOTP secret instead of the raw base32
-- value. See services/tenant_totp_service.go (and totp_service.go) — secrets
-- are now encrypted at rest; the encrypted value is ~80 chars and overflows the
-- original varchar(64). Idempotent; guards on table existence because not every
-- tenant schema carries both tables.
DO $$
BEGIN
    IF to_regclass('public.tenant_totp_secrets') IS NOT NULL THEN
        ALTER TABLE public.tenant_totp_secrets ALTER COLUMN secret TYPE varchar(255);
    END IF;
    IF to_regclass('public.totp_secrets') IS NOT NULL THEN
        ALTER TABLE public.totp_secrets ALTER COLUMN secret TYPE varchar(255);
    END IF;
END $$;
