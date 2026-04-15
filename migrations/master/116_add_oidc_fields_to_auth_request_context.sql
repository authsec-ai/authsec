-- Add OIDC parameters to auth_request_contexts for OpenID Connect Core 1.0 support.
-- nonce: binds id_token to authorization request (OIDC Core §3.1.2.1)
-- prompt: controls login/consent UI behavior (OIDC Core §3.1.2.1)
-- max_age: maximum authentication age in seconds (OIDC Core §3.1.2.1)
-- auth_time: timestamp of actual authentication event (OIDC Core §2)
ALTER TABLE auth_request_contexts
  ADD COLUMN IF NOT EXISTS nonce TEXT,
  ADD COLUMN IF NOT EXISTS prompt VARCHAR(64),
  ADD COLUMN IF NOT EXISTS max_age INTEGER,
  ADD COLUMN IF NOT EXISTS auth_time TIMESTAMP;
