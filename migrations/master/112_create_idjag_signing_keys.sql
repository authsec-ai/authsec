-- idjag_signing_keys: RSA keypair AuthSec uses to sign ID-JAGs when it acts as
-- the IdP for Cross-App Access. Lazily generated on first use and persisted so
-- restarts don't invalidate every outstanding ID-JAG.
--
-- Only one active row at a time (active=true). When rotation is needed, mint a
-- new row with active=true and flip the old one to active=false; the JWKS
-- handler publishes both (so verifiers with cached old keys still validate
-- their in-flight tokens) until the old one's `not_after` passes.

CREATE TABLE IF NOT EXISTS idjag_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kid TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL DEFAULT 'RS256',
    -- DER-encoded PKCS#1 (RSA private key). bytea so it round-trips cleanly.
    private_key_pem BYTEA NOT NULL,
    public_key_pem BYTEA NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    not_after TIMESTAMPTZ, -- null = no expiry; set to retire-but-publish window
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_idjag_signing_keys_active ON idjag_signing_keys (active);
