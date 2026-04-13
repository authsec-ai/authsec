-- Migration 109: Add context_id (server-generated binding key) and consent_completed to auth_request_contexts
-- context_id replaces client-supplied state as the deterministic binding mechanism.
-- consent_completed separates consent from consumption (Token handler is the only consumer).

ALTER TABLE auth_request_contexts ADD COLUMN IF NOT EXISTS context_id VARCHAR(255);
ALTER TABLE auth_request_contexts ADD COLUMN IF NOT EXISTS consent_completed BOOLEAN DEFAULT false;

-- context_id must be unique for active rows
CREATE UNIQUE INDEX IF NOT EXISTS idx_arc_context_id ON auth_request_contexts(context_id) WHERE context_id IS NOT NULL;
