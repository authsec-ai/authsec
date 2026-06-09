-- Widen totp_secrets.secret so it can hold the AES-256-GCM ciphertext
-- (base64) of the TOTP secret instead of the raw base32 value.
--
-- Background: TOTP secrets in the /uflow service path were stored as plaintext
-- base32 (~32 chars) in a varchar(64) column. They are now encrypted at rest
-- via utils.EncryptString (see services/totp_service.go); the encrypted,
-- base64-encoded value is ~80 chars and overflows varchar(64). Widening to
-- varchar(255) leaves headroom. Idempotent.
DO $$
BEGIN
    IF to_regclass('public.totp_secrets') IS NOT NULL THEN
        ALTER TABLE public.totp_secrets ALTER COLUMN secret TYPE varchar(255);
    END IF;
END $$;
