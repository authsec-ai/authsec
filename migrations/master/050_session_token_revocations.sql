-- ============================================================================
-- 050: revocation list for platform session tokens
--
-- Session JWTs (console, end-user, SDK) carried no jti and nothing checked a
-- revocation list, so logout and incident response could not end a session
-- before it expired (AS-031). New tokens carry a jti; AuthMiddleware rejects
-- any jti listed here. Rows can be deleted once expires_at has passed.
-- Numbers 045-049 are reserved for the tenancy schema migrations.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.revoked_session_tokens (
    jti          text PRIMARY KEY,
    workspace_id uuid,
    user_id      uuid,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz NOT NULL DEFAULT now(),
    reason       text NOT NULL DEFAULT 'logout'
);

CREATE INDEX IF NOT EXISTS idx_revoked_session_tokens_expires ON public.revoked_session_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_revoked_session_tokens_workspace ON public.revoked_session_tokens (workspace_id);
