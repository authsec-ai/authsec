-- 038_add_second_factor_completed.sql
--
-- Adds the second_factor_completed gate to auth_request_context. The OAuth v2
-- login flow stamps user_id after primary auth (password / OIDC / SAML) but
-- does NOT accept the Hydra login until a WebAuthn 2FA ceremony (enroll on first
-- login, challenge thereafter) completes. This column records that the second
-- factor was satisfied for the request. Idempotent.

ALTER TABLE auth_request_context
    ADD COLUMN IF NOT EXISTS second_factor_completed boolean NOT NULL DEFAULT false;
