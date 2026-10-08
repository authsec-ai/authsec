-- ============================================================================
-- 110: voice_active_sessions
--
-- Voice auth (POST /uflow/auth/voice/*) records each signed-in voice device
-- here (database/voice_auth_repository.go), but no migration created the
-- table, so every voice sign-in failed (AS-047). Columns match
-- models.VoiceActiveSession; timestamps are Unix seconds as in voice_sessions.
-- Workspace-owned from the start (ADR-0001): workspace_id NOT NULL with FK.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.voice_active_sessions (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    client_id          uuid,
    user_id            uuid NOT NULL,
    user_email         text NOT NULL,
    session_id         varchar(128) NOT NULL,
    voice_platform     varchar(50),
    voice_user_id      text,
    device_info        jsonb NOT NULL DEFAULT '{}'::jsonb,
    device_name        text,
    access_token_hash  varchar(64),
    refresh_token_hash varchar(64),
    login_at           bigint NOT NULL DEFAULT 0,
    last_activity_at   bigint NOT NULL DEFAULT 0,
    expires_at         bigint NOT NULL,
    is_active          boolean NOT NULL DEFAULT true,
    revoked_at         bigint,
    revoked_reason     varchar(100),
    created_at         bigint NOT NULL DEFAULT 0,
    updated_at         bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_voice_active_sessions_session_id UNIQUE (session_id)
);

CREATE INDEX IF NOT EXISTS idx_voice_active_sessions_workspace_user
    ON public.voice_active_sessions (workspace_id, user_id);
CREATE INDEX IF NOT EXISTS idx_voice_active_sessions_platform_user
    ON public.voice_active_sessions (workspace_id, voice_platform, voice_user_id);
CREATE INDEX IF NOT EXISTS idx_voice_active_sessions_expires
    ON public.voice_active_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_voice_active_sessions_active
    ON public.voice_active_sessions (is_active);
