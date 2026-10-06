-- ============================================================================
-- 043: login tickets -- server-side proof that a sign-in passed its first factor
--
-- The MFA step of interactive sign-in (WebAuthn, TOTP, SMS under
-- /authsec/webauthn/*) and the webauthn-callback endpoints that mint the
-- session token used to be anonymous: they trusted the email and workspace in
-- the request body and a client-asserted `mfa_verified: true`. Anyone who knew
-- a workspace UUID could mint its owner's admin token (AS-001/002/003).
--
-- A login ticket closes that gap. It is issued only after a first factor is
-- verified server-side (password, OIDC, SAML), names exactly one
-- (workspace, user), is marked mfa_verified_at only by a successful
-- second-factor verification, and is consumed once by the callback that mints
-- the session token. Only a SHA-256 hash of the ticket is stored.
--
-- Additive and idempotent: a new table, no change to existing rows.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.login_tickets (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_hash     text NOT NULL UNIQUE,
    realm           text NOT NULL CHECK (realm IN ('admin', 'enduser')),
    workspace_id    uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL,
    email           text NOT NULL,
    first_factor    text NOT NULL,
    mfa_verified_at timestamptz,
    consumed_at     timestamptz,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_tickets_workspace ON public.login_tickets (workspace_id);
CREATE INDEX IF NOT EXISTS idx_login_tickets_expires ON public.login_tickets (expires_at);

COMMENT ON TABLE public.login_tickets IS
    'Short-lived, single-use proof that an interactive sign-in passed its first '
    'factor; gates the anonymous MFA endpoints and the session-token callbacks. '
    'Stores only a SHA-256 hash of the ticket.';
