-- 032_alter_oidc_states_federated_hydra.sql
--
-- Extends oidc_states with the two columns the federated-login surface
-- (Session 4 of the v2 backport) needs to thread the Hydra login_challenge
-- through an upstream provider redirect.
--
-- application_id   : the AuthSec Application the user is logging into.
--                    Used post-callback for the per-Application IDP
--                    whitelist gate + scope intersection.
-- login_challenge  : Hydra's opaque token from /authorize. The callback
--                    handler needs it to call accept-login at Hydra.
--
-- Both are nullable so existing non-federated rows (action='login' /
-- 'register' from earlier flows) are unaffected.

ALTER TABLE oidc_states
  ADD COLUMN IF NOT EXISTS application_id  UUID NULL,
  ADD COLUMN IF NOT EXISTS login_challenge TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_oidc_states_login_challenge
  ON oidc_states (login_challenge)
  WHERE login_challenge IS NOT NULL;
