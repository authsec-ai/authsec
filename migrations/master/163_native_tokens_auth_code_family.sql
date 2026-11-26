-- 163_native_tokens_auth_code_family.sql
--
-- Browser login (authorization_code / refresh_token at /oauth/token) now
-- returns an AuthSec-native access token, like M2M, ID-JAG and CIBA already do,
-- instead of passing Hydra's token through. Its native_tokens rows carry the new
-- token family 'auth_code'.
--
-- The row also links to the Hydra refresh token it was minted alongside:
-- source_grant_jti holds the refresh token's SHA-256 and source_grant_iss the
-- marker 'urn:authsec:hydra-refresh-token', so revoking or rotating the refresh
-- token revokes its access token. The existing idx_native_tokens_source_grant
-- serves that lookup.
--
-- Additive: the CHECK only widens, and a binary without this change never
-- writes 'auth_code'. Idempotent: the token_family CHECK (unnamed in older
-- bootstraps, so found by definition) is dropped and re-added under its
-- canonical name, which equals the name Postgres gives the inline CHECK in
-- 001_bootstrap.sql, so a fresh and an upgraded database match.

DO $$
DECLARE
    c text;
BEGIN
    FOR c IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'public.native_tokens'::regclass
           AND contype = 'c'
           AND pg_get_constraintdef(oid) LIKE '%token_family%'
    LOOP
        EXECUTE format('ALTER TABLE public.native_tokens DROP CONSTRAINT %I', c);
    END LOOP;
END $$;

ALTER TABLE public.native_tokens
    ADD CONSTRAINT native_tokens_token_family_check
    CHECK (token_family IN ('xaa', 'm2m', 'ciba', 'auth_code'));
