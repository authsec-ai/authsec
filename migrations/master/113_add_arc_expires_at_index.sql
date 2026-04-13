-- Migration 113: Add index on expires_at for efficient cleanup queries.
-- CleanupExpired() runs every 10 minutes: DELETE WHERE expires_at < NOW().

CREATE INDEX IF NOT EXISTS idx_arc_expires_at ON auth_request_contexts(expires_at);
