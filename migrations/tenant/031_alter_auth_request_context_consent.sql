-- Add consent_completed flag to auth_request_context. Used by the v2
-- login + consent flow (session 1+3 of the login-surface port):
--
--   - Set to true when the consent handler successfully calls Hydra
--     accept-consent.
--   - Read by /oauth/v2/token before consuming the context — token
--     exchange fails closed unless consent_completed=true.
--
-- Also adds login_challenge + consent_challenge so the consent handler
-- can find the in-flight context when Hydra sends a consent_challenge
-- back to our consent endpoint. login_challenge is bound at /login/page-data
-- and read at /consent.
--
-- Backfill: existing rows (from the smoke-test traffic before this
-- column existed) get consent_completed=false. Token exchanges against
-- those will fail closed, which is the safe default — those rows are
-- expired by now anyway.

ALTER TABLE auth_request_context
    ADD COLUMN IF NOT EXISTS consent_completed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS login_challenge TEXT,
    ADD COLUMN IF NOT EXISTS consent_challenge TEXT,
    ADD COLUMN IF NOT EXISTS user_id UUID,
    ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_auth_request_context_login_challenge
    ON auth_request_context(login_challenge) WHERE login_challenge IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_request_context_consent_challenge
    ON auth_request_context(consent_challenge) WHERE consent_challenge IS NOT NULL;
