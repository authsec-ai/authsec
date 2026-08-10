-- ============================================================================
-- One-off forward delta: bring a LIVE (data-bearing) database from the pre-P2
-- connector schema up to the current 001_bootstrap.sql connector state.
--
-- This is NOT a committed migration and NOT part of the single-state schema.
-- It is a manual, idempotent psql script for advancing a deployed DB that
-- cannot be wiped. Run once:
--     psql "$DATABASE_URL" -f connector_p2_p3_forward.sql
--
-- Idempotent: safe to re-run. Uses IF NOT EXISTS / ON CONFLICT throughout.
-- After running, verify: GET /authsec/connectors/providers shows slack/github
-- with oauth_authorize_url populated.
-- ============================================================================

BEGIN;

-- 1. OAuth metadata columns on connector_providers -------------------------
ALTER TABLE public.connector_providers
    ADD COLUMN IF NOT EXISTS supported_auth_methods text[] NOT NULL DEFAULT '{oauth2}'::text[],
    ADD COLUMN IF NOT EXISTS oauth_authorize_url    text   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS oauth_token_url        text   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS oauth_scopes_supported text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN IF NOT EXISTS oauth_default_scopes   text[] NOT NULL DEFAULT '{}'::text[];

-- 2. resource_servers: managed flag + connector_broker application_type ----
ALTER TABLE public.resource_servers
    ADD COLUMN IF NOT EXISTS managed boolean NOT NULL DEFAULT false;

-- Widen the application_type CHECK to include 'connector_broker'. The old
-- constraint name is resource_servers_application_type_chk; drop + re-add.
ALTER TABLE public.resource_servers
    DROP CONSTRAINT IF EXISTS resource_servers_application_type_chk;
ALTER TABLE public.resource_servers
    ADD CONSTRAINT resource_servers_application_type_chk
        CHECK (application_type IN ('mcp_server', 'ai_agent', 'clawbot', 'api_service', 'connector_broker'));

-- 3. connectors: composite unique so child tables can reference it ---------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'connectors_workspace_id_key'
    ) THEN
        ALTER TABLE public.connectors
            ADD CONSTRAINT connectors_workspace_id_key UNIQUE (workspace_id, id);
    END IF;
END $$;

-- 4. connector_assignments (P0) -------------------------------------------
CREATE TABLE IF NOT EXISTS public.connector_assignments (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    client_id    text NOT NULL,
    action_key   text,
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_assignments_pkey PRIMARY KEY (id),
    CONSTRAINT connector_assignments_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.connectors(workspace_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_assign_all    ON public.connector_assignments (connector_id, client_id)             WHERE action_key IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_assign_action ON public.connector_assignments (connector_id, client_id, action_key) WHERE action_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_connector_assignments_client ON public.connector_assignments(client_id);

-- 5. connector_actions (P2) -----------------------------------------------
CREATE TABLE IF NOT EXISTS public.connector_actions (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    provider_key    text NOT NULL,
    action_key      text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    adapter_key     text NOT NULL,
    http_method     text NOT NULL,
    input_schema    jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_schema   jsonb NOT NULL DEFAULT '{}'::jsonb,
    required_scopes text[] NOT NULL DEFAULT '{}'::text[],
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_actions_pkey PRIMARY KEY (id),
    CONSTRAINT connector_actions_provider_fkey FOREIGN KEY (provider_key)
        REFERENCES public.connector_providers(key) ON DELETE CASCADE,
    CONSTRAINT connector_actions_provider_action_key UNIQUE (provider_key, action_key)
);
CREATE INDEX IF NOT EXISTS idx_connector_actions_provider ON public.connector_actions(provider_key);

-- 6. connector_oauth_states (P3) ------------------------------------------
CREATE TABLE IF NOT EXISTS public.connector_oauth_states (
    state           text NOT NULL,
    workspace_id    uuid NOT NULL,
    connector_id    uuid NOT NULL,
    provider_key    text NOT NULL,
    binding_type    text NOT NULL DEFAULT 'workspace',
    subject_user_id text,
    code_verifier   text NOT NULL,
    redirect_after  text,
    created_by      text,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connector_oauth_states_pkey PRIMARY KEY (state)
);
CREATE INDEX IF NOT EXISTS idx_connector_oauth_states_expires ON public.connector_oauth_states(expires_at);

-- 7. Seed the curated OAuth provider catalog (adds slack/github/... alongside
--    any legacy rows; ON CONFLICT leaves existing rows untouched) -----------
INSERT INTO public.connector_providers
    (key, display_name, supported_auth_methods, oauth_authorize_url, oauth_token_url, oauth_scopes_supported, oauth_default_scopes)
VALUES
    ('slack',   'Slack',   '{oauth2}'::text[],
        'https://slack.com/oauth/v2/authorize', 'https://slack.com/api/oauth.v2.access',
        '{chat:write,channels:read,channels:history}'::text[], '{chat:write}'::text[]),
    ('github',  'GitHub',  '{oauth2}'::text[],
        'https://github.com/login/oauth/authorize', 'https://github.com/login/oauth/access_token',
        '{repo,read:org}'::text[], '{repo}'::text[]),
    ('google',  'Google',  '{oauth2}'::text[],
        'https://accounts.google.com/o/oauth2/v2/auth', 'https://oauth2.googleapis.com/token',
        '{https://www.googleapis.com/auth/gmail.send,https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/analytics.readonly}'::text[],
        '{}'::text[]),
    ('hubspot', 'HubSpot', '{oauth2}'::text[],
        'https://app.hubspot.com/oauth/authorize', 'https://api.hubapi.com/oauth/v1/token',
        '{crm.objects.contacts.read,crm.objects.contacts.write,crm.objects.deals.write}'::text[], '{}'::text[]),
    ('notion',  'Notion',  '{oauth2}'::text[],
        'https://api.notion.com/v1/oauth/authorize', 'https://api.notion.com/v1/oauth/token',
        '{}'::text[], '{}'::text[]),
    ('jira',    'Jira',    '{oauth2}'::text[],
        'https://auth.atlassian.com/authorize', 'https://auth.atlassian.com/oauth/token',
        '{read:jira-work,write:jira-work,offline_access}'::text[], '{read:jira-work,write:jira-work}'::text[])
ON CONFLICT (key) DO UPDATE SET
    -- On an existing row, OVERWRITE the OAuth metadata (a prior run may have
    -- inserted the row before these columns were populated, leaving them at
    -- their empty column defaults — DO NOTHING would keep them empty).
    supported_auth_methods = EXCLUDED.supported_auth_methods,
    oauth_authorize_url    = EXCLUDED.oauth_authorize_url,
    oauth_token_url        = EXCLUDED.oauth_token_url,
    oauth_scopes_supported = EXCLUDED.oauth_scopes_supported,
    oauth_default_scopes   = EXCLUDED.oauth_default_scopes;

-- 8. Seed the Slack + GitHub typed actions --------------------------------
INSERT INTO public.connector_actions
    (provider_key, action_key, display_name, adapter_key, http_method, input_schema, required_scopes)
VALUES
    ('slack', 'postMessage', 'Post a Slack message', 'slack', 'POST',
        '{"type":"object","required":["channel","text"],"properties":{"channel":{"type":"string"},"text":{"type":"string"}}}'::jsonb,
        '{chat:write}'::text[]),
    ('github', 'createIssue', 'Create a GitHub issue', 'github', 'POST',
        '{"type":"object","required":["owner","repo","title"],"properties":{"owner":{"type":"string"},"repo":{"type":"string"},"title":{"type":"string"},"body":{"type":"string"}}}'::jsonb,
        '{repo}'::text[])
ON CONFLICT (provider_key, action_key) DO NOTHING;

-- 9. Global connector RBAC permissions (workspace_id IS NULL) --------------
--    Requires the partial unique index on (resource, action) WHERE
--    workspace_id IS NULL (idx_permissions_global_resource_action). Present in
--    bootstrap; created here defensively in case the deployed DB lacks it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_global_resource_action
    ON public.permissions (resource, action) WHERE workspace_id IS NULL;

INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'connector', 'create',  'Create a connector',                  'connector:create',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'read',    'Read connectors',                     'connector:read',    NOW()),
    (gen_random_uuid(), NULL, 'connector', 'update',  'Update a connector',                  'connector:update',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'delete',  'Delete a connector',                  'connector:delete',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'config',  'Read connector config (non-secret)',  'connector:config',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'assign',  'Manage connector assignments',        'connector:assign',  NOW()),
    (gen_random_uuid(), NULL, 'connector', 'execute', 'Execute a connector action (broker)', 'connector:execute', NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;

COMMIT;

-- Post-run sanity (run manually):
--   SELECT key FROM connector_providers WHERE key IN ('slack','github');
--   SELECT provider_key, action_key FROM connector_actions;
--   SELECT resource, action FROM permissions WHERE resource='connector' AND workspace_id IS NULL;
--   \d connector_oauth_states
