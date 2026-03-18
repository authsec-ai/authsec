-- Normalize tenant oauth_sessions to the SDK Manager schema.
-- Older tenant databases used a legacy table keyed by `id` with UUID columns
-- and timestamp fields that do not match the sdkmgr OAuth session model.

ALTER TABLE oauth_sessions
    ADD COLUMN IF NOT EXISTS session_id VARCHAR(36),
    ADD COLUMN IF NOT EXISTS tenant_id  VARCHAR(255);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'oauth_sessions'
          AND column_name = 'id'
    ) THEN
        UPDATE oauth_sessions
        SET session_id = id::text
        WHERE session_id IS NULL
          AND id IS NOT NULL;
    END IF;
END $$;

ALTER TABLE oauth_sessions
    ALTER COLUMN session_id SET NOT NULL,
    ALTER COLUMN user_id DROP NOT NULL,
    ALTER COLUMN client_id DROP NOT NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'oauth_sessions'
          AND column_name = 'created_at'
          AND data_type = 'timestamp with time zone'
    ) THEN
        ALTER TABLE oauth_sessions
            ALTER COLUMN created_at DROP DEFAULT,
            ALTER COLUMN created_at TYPE BIGINT
            USING COALESCE(
                CASE WHEN created_at IS NOT NULL THEN EXTRACT(EPOCH FROM created_at)::BIGINT END,
                last_activity,
                EXTRACT(EPOCH FROM now())::BIGINT
            );
    END IF;
END $$;

UPDATE oauth_sessions
SET token_expires_at = EXTRACT(EPOCH FROM expires_at)::BIGINT
WHERE token_expires_at IS NULL
  AND expires_at IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_sessions_session_id
    ON oauth_sessions(session_id);

CREATE INDEX IF NOT EXISTS idx_oauth_sessions_tenant
    ON oauth_sessions(tenant_id) WHERE is_active = true;
