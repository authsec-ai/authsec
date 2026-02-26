-- Migration: Add rp_id column to credentials and webauthn_credentials tables
-- This enables domain-specific WebAuthn credentials

-- Add rp_id column to credentials table
ALTER TABLE IF EXISTS credentials 
ADD COLUMN IF NOT EXISTS rp_id VARCHAR(255);

-- Add index for better query performance
CREATE INDEX IF NOT EXISTS idx_credentials_client_rp 
ON credentials(client_id, rp_id);

-- Add rp_id column to webauthn_credentials table
ALTER TABLE IF EXISTS webauthn_credentials 
ADD COLUMN IF NOT EXISTS rp_id VARCHAR(255);

-- Add index for better query performance
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_rp 
ON webauthn_credentials(user_id, rp_id);

-- Add comment to explain the column
COMMENT ON COLUMN credentials.rp_id IS 'Relying Party ID (domain) where this credential was registered';
COMMENT ON COLUMN webauthn_credentials.rp_id IS 'Relying Party ID (domain) where this credential was registered';
