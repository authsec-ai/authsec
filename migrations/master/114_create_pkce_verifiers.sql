-- Migration 114: Create pkce_verifiers table for database-backed PKCE storage.
-- Replaces process-local sync.Map. Survives restarts and works in multi-instance deployments.

CREATE TABLE IF NOT EXISTS pkce_verifiers (
    key VARCHAR(512) PRIMARY KEY,
    verifier TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pkce_verifiers_expires_at ON pkce_verifiers(expires_at);
