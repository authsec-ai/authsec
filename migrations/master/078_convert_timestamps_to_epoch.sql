-- Migration: Convert timestamp columns to BIGINT (Unix epoch seconds)
-- This eliminates timezone issues and makes comparisons reliable

-- ========================================
-- device_codes table
-- ========================================

-- Add new epoch columns
ALTER TABLE device_codes
    ADD COLUMN IF NOT EXISTS expires_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS last_polled_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS authorized_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS created_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS updated_at_epoch BIGINT;

-- Migrate existing data (convert TIMESTAMP to epoch)
UPDATE device_codes SET
    expires_at_epoch = EXTRACT(EPOCH FROM expires_at)::BIGINT,
    last_polled_at_epoch = EXTRACT(EPOCH FROM last_polled_at)::BIGINT,
    authorized_at_epoch = EXTRACT(EPOCH FROM authorized_at)::BIGINT,
    created_at_epoch = EXTRACT(EPOCH FROM created_at)::BIGINT,
    updated_at_epoch = EXTRACT(EPOCH FROM updated_at)::BIGINT
WHERE expires_at_epoch IS NULL;

-- Drop old timestamp columns
ALTER TABLE device_codes
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS last_polled_at,
    DROP COLUMN IF EXISTS authorized_at,
    DROP COLUMN IF EXISTS created_at,
    DROP COLUMN IF EXISTS updated_at;

-- Rename epoch columns to original names
ALTER TABLE device_codes
    RENAME COLUMN expires_at_epoch TO expires_at;
ALTER TABLE device_codes
    RENAME COLUMN last_polled_at_epoch TO last_polled_at;
ALTER TABLE device_codes
    RENAME COLUMN authorized_at_epoch TO authorized_at;
ALTER TABLE device_codes
    RENAME COLUMN created_at_epoch TO created_at;
ALTER TABLE device_codes
    RENAME COLUMN updated_at_epoch TO updated_at;

-- Add NOT NULL constraint and default for required columns
ALTER TABLE device_codes
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN created_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    ALTER COLUMN updated_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT;

-- Recreate index on expires_at
DROP INDEX IF EXISTS idx_device_codes_expires_at;
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);

-- ========================================
-- voice_sessions table
-- ========================================

ALTER TABLE voice_sessions
    ADD COLUMN IF NOT EXISTS expires_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS verified_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS created_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS updated_at_epoch BIGINT;

UPDATE voice_sessions SET
    expires_at_epoch = EXTRACT(EPOCH FROM expires_at)::BIGINT,
    verified_at_epoch = EXTRACT(EPOCH FROM verified_at)::BIGINT,
    created_at_epoch = EXTRACT(EPOCH FROM created_at)::BIGINT,
    updated_at_epoch = EXTRACT(EPOCH FROM updated_at)::BIGINT
WHERE expires_at_epoch IS NULL;

ALTER TABLE voice_sessions
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS verified_at,
    DROP COLUMN IF EXISTS created_at,
    DROP COLUMN IF EXISTS updated_at;

ALTER TABLE voice_sessions
    RENAME COLUMN expires_at_epoch TO expires_at;
ALTER TABLE voice_sessions
    RENAME COLUMN verified_at_epoch TO verified_at;
ALTER TABLE voice_sessions
    RENAME COLUMN created_at_epoch TO created_at;
ALTER TABLE voice_sessions
    RENAME COLUMN updated_at_epoch TO updated_at;

ALTER TABLE voice_sessions
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN created_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    ALTER COLUMN updated_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT;

DROP INDEX IF EXISTS idx_voice_sessions_expires_at;
CREATE INDEX idx_voice_sessions_expires_at ON voice_sessions(expires_at);

-- ========================================
-- voice_identity_links table
-- ========================================

ALTER TABLE voice_identity_links
    ADD COLUMN IF NOT EXISTS last_used_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS linked_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS created_at_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS updated_at_epoch BIGINT;

UPDATE voice_identity_links SET
    last_used_at_epoch = EXTRACT(EPOCH FROM last_used_at)::BIGINT,
    linked_at_epoch = EXTRACT(EPOCH FROM linked_at)::BIGINT,
    created_at_epoch = EXTRACT(EPOCH FROM created_at)::BIGINT,
    updated_at_epoch = EXTRACT(EPOCH FROM updated_at)::BIGINT
WHERE created_at_epoch IS NULL;

ALTER TABLE voice_identity_links
    DROP COLUMN IF EXISTS last_used_at,
    DROP COLUMN IF EXISTS linked_at,
    DROP COLUMN IF EXISTS created_at,
    DROP COLUMN IF EXISTS updated_at;

ALTER TABLE voice_identity_links
    RENAME COLUMN last_used_at_epoch TO last_used_at;
ALTER TABLE voice_identity_links
    RENAME COLUMN linked_at_epoch TO linked_at;
ALTER TABLE voice_identity_links
    RENAME COLUMN created_at_epoch TO created_at;
ALTER TABLE voice_identity_links
    RENAME COLUMN updated_at_epoch TO updated_at;

ALTER TABLE voice_identity_links
    ALTER COLUMN linked_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    ALTER COLUMN created_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    ALTER COLUMN updated_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT;

-- ========================================
-- voice_active_sessions table (if exists)
-- ========================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'voice_active_sessions') THEN
        ALTER TABLE voice_active_sessions
            ADD COLUMN IF NOT EXISTS login_at_epoch BIGINT,
            ADD COLUMN IF NOT EXISTS last_activity_at_epoch BIGINT,
            ADD COLUMN IF NOT EXISTS expires_at_epoch BIGINT,
            ADD COLUMN IF NOT EXISTS revoked_at_epoch BIGINT,
            ADD COLUMN IF NOT EXISTS created_at_epoch BIGINT,
            ADD COLUMN IF NOT EXISTS updated_at_epoch BIGINT;

        UPDATE voice_active_sessions SET
            login_at_epoch = EXTRACT(EPOCH FROM login_at)::BIGINT,
            last_activity_at_epoch = EXTRACT(EPOCH FROM last_activity_at)::BIGINT,
            expires_at_epoch = EXTRACT(EPOCH FROM expires_at)::BIGINT,
            revoked_at_epoch = EXTRACT(EPOCH FROM revoked_at)::BIGINT,
            created_at_epoch = EXTRACT(EPOCH FROM created_at)::BIGINT,
            updated_at_epoch = EXTRACT(EPOCH FROM updated_at)::BIGINT
        WHERE created_at_epoch IS NULL;

        ALTER TABLE voice_active_sessions
            DROP COLUMN IF EXISTS login_at,
            DROP COLUMN IF EXISTS last_activity_at,
            DROP COLUMN IF EXISTS expires_at,
            DROP COLUMN IF EXISTS revoked_at,
            DROP COLUMN IF EXISTS created_at,
            DROP COLUMN IF EXISTS updated_at;

        ALTER TABLE voice_active_sessions
            RENAME COLUMN login_at_epoch TO login_at;
        ALTER TABLE voice_active_sessions
            RENAME COLUMN last_activity_at_epoch TO last_activity_at;
        ALTER TABLE voice_active_sessions
            RENAME COLUMN expires_at_epoch TO expires_at;
        ALTER TABLE voice_active_sessions
            RENAME COLUMN revoked_at_epoch TO revoked_at;
        ALTER TABLE voice_active_sessions
            RENAME COLUMN created_at_epoch TO created_at;
        ALTER TABLE voice_active_sessions
            RENAME COLUMN updated_at_epoch TO updated_at;

        ALTER TABLE voice_active_sessions
            ALTER COLUMN expires_at SET NOT NULL,
            ALTER COLUMN login_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
            ALTER COLUMN last_activity_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
            ALTER COLUMN created_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
            ALTER COLUMN updated_at SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT;
    END IF;
END $$;

-- ========================================
-- Update triggers to use epoch
-- ========================================

CREATE OR REPLACE FUNCTION update_device_codes_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_voice_sessions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_voice_identity_links_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ========================================
-- Update cleanup functions to use epoch
-- ========================================

CREATE OR REPLACE FUNCTION cleanup_expired_device_codes()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
    current_epoch BIGINT;
BEGIN
    current_epoch := EXTRACT(EPOCH FROM NOW())::BIGINT;

    DELETE FROM device_codes
    WHERE expires_at < (current_epoch - 86400)  -- 24 hours ago
    AND status IN ('expired', 'consumed', 'denied');

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_expired_voice_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
    current_epoch BIGINT;
BEGIN
    current_epoch := EXTRACT(EPOCH FROM NOW())::BIGINT;

    DELETE FROM voice_sessions
    WHERE expires_at < (current_epoch - 3600)  -- 1 hour ago
    AND status IN ('expired', 'failed', 'verified');

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ========================================
-- Add comments
-- ========================================

COMMENT ON COLUMN device_codes.expires_at IS 'Unix epoch timestamp (seconds) when this device code expires';
COMMENT ON COLUMN device_codes.created_at IS 'Unix epoch timestamp (seconds) when created';
COMMENT ON COLUMN device_codes.updated_at IS 'Unix epoch timestamp (seconds) when last updated';

COMMENT ON COLUMN voice_sessions.expires_at IS 'Unix epoch timestamp (seconds) when this session expires';
COMMENT ON COLUMN voice_sessions.created_at IS 'Unix epoch timestamp (seconds) when created';

COMMENT ON COLUMN voice_identity_links.linked_at IS 'Unix epoch timestamp (seconds) when link was created';
COMMENT ON COLUMN voice_identity_links.last_used_at IS 'Unix epoch timestamp (seconds) when last used for authentication';
