-- 017_azure_app_config.sql
--
-- Where a workspace's own Entra App Registration is recorded, so onboarding can
-- start from "here are my app's details" instead of a deployment restart.
--
-- WHY THIS EXISTS. AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_REDIRECT_URI
-- are read once at process start and are deployment-global. That makes three
-- things impossible: a customer bringing their own app registration, changing
-- the application without a restart, and two workspaces on one deployment using
-- different applications. It also leaves the operator with no way to hand the
-- product their details at all -- the only supported answer is "edit .env and
-- restart", which is not an onboarding flow.
--
-- WHY THE SECRET IS NOT HERE. Only a Vault path is. The secret value never
-- reaches Postgres, so a database dump, a replica, a backup or a stray SELECT
-- cannot leak it -- they leak a pointer to it. This is the same split
-- connector_provider_apps already uses for per-workspace OAuth apps
-- (001_bootstrap.sql), and the resolution order is deliberately identical:
-- this row for the workspace first, else the deployment-wide env vars. A
-- deployment that sets neither is unchanged.
--
-- WHY home_tenant IS SEPARATE FROM THE CONNECTOR TENANTS. An application object
-- exists ONLY in the directory it was created in; every other tenant holds a
-- service principal instead. So checking our own registration needs the home
-- tenant specifically, and it is not one of the tenants in azure_connectors --
-- those are customers. It was previously AZURE_HOME_TENANT, an env var that had
-- to be remembered separately from the client id it belongs to.

CREATE TABLE IF NOT EXISTS public.azure_app_config (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL REFERENCES public.workspaces (id) ON DELETE CASCADE,

    -- Application (client) id. Not a secret: it appears in every authorize URL.
    client_id     text NOT NULL,

    -- The directory the registration was created in. Needed to read the
    -- application object back, which is possible only there.
    home_tenant   text NOT NULL,

    -- Must match a redirect URI registered on the application EXACTLY, or
    -- Microsoft refuses with AADSTS50011 before a password is typed.
    redirect_uri  text NOT NULL,

    -- Vault path holding {"client_secret": "..."}. A path, never a value.
    -- Named auth_ref to match the pointer convention used elsewhere.
    auth_ref      text NOT NULL,

    -- Who submitted it, and when it was last checked against Microsoft. The
    -- verdict itself is not cached: it can change in the portal at any time
    -- without anything telling us, so it is re-read rather than remembered.
    created_by    text,
    checked_at    timestamptz,

    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    -- One application per workspace. Replacing it is an UPDATE, not a second
    -- row, so there is never an ambiguous "which app is this workspace using".
    CONSTRAINT azure_app_config_workspace_uq UNIQUE (workspace_id),
    CONSTRAINT azure_app_config_client_id_chk    CHECK (client_id <> ''),
    CONSTRAINT azure_app_config_home_tenant_chk  CHECK (home_tenant <> ''),
    CONSTRAINT azure_app_config_redirect_uri_chk CHECK (redirect_uri <> ''),
    CONSTRAINT azure_app_config_auth_ref_chk     CHECK (auth_ref <> '')
);
