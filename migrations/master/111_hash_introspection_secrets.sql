-- Migration 111: Add hashed introspection secret storage for resource servers.
-- New rows store only introspection_secret_hash. Legacy plaintext secrets remain readable
-- until opportunistically backfilled on first successful validation.

ALTER TABLE resource_servers ADD COLUMN IF NOT EXISTS introspection_secret_hash TEXT;
ALTER TABLE resource_servers ALTER COLUMN introspection_secret DROP NOT NULL;
ALTER TABLE resource_servers ALTER COLUMN introspection_secret SET DEFAULT '';
