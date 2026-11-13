-- ============================================================================
-- 154: model provider usage (SPEC-agent-runtime-provider-usage.md §4).
--
-- Opt-in per workspace: a workspace connects its OpenAI or Anthropic
-- organisation with an admin key, and AuthSec reads the organisation's API
-- keys and hourly model usage, then flags usage no AWS workload can be tied
-- to (agent_finding kind unaccounted_model_usage).
--
-- 1. model_provider_connection: one connected organisation. The admin key is
--    NOT here: only its Vault path (secret_ref, '' once revoked) and a
--    fingerprint (last 4 characters and a sha256 prefix). One live connection
--    per (workspace, provider, org).
-- 2. model_provider_key: one provider API key as last listed (names, project,
--    owner, dates, status, weak attribution links). Never a key value.
-- 3. model_provider_usage: one hour of one key on one model: requests (NULL
--    when the provider reports none), input / output tokens. Never a prompt.
-- 4. agent_finding (148): kind admits every kind of 148, 152 (ai_config_hint),
--    153 (ai_network_traffic) and 154 (unaccounted_model_usage), so any merge
--    order is safe; connector_id becomes nullable and provider_connection_id
--    is added: a finding names an AWS connector or a provider connection.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.model_provider_connection (
    id                   uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid        NOT NULL,
    provider             text        NOT NULL,
    display_name         text        NOT NULL DEFAULT '',
    -- Vault path of the admin key; '' once revoked. Never the key.
    secret_ref           text        NOT NULL DEFAULT '',
    -- '...' + last 4 characters + ' sha256:' + 12 hex characters.
    key_fingerprint      text        NOT NULL,
    -- As the provider reports them; '' when it names none.
    org_id               text        NOT NULL DEFAULT '',
    org_name             text        NOT NULL DEFAULT '',
    status               text        NOT NULL DEFAULT 'active',
    last_sync_at         timestamptz,
    last_sync_attempt_at timestamptz,
    -- When the worker syncs it next; NULL: not scheduled (revoked, or an
    -- error waiting for a rotation or a manual sync).
    next_sync_at         timestamptz,
    sync_lease_until     timestamptz,
    -- High-water mark of the usage read (start of the newest hour read).
    usage_cursor         timestamptz,
    last_error           text        NOT NULL DEFAULT '',
    created_by           uuid        NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    revoked_at           timestamptz,
    revoked_by           uuid,
    CONSTRAINT model_provider_connection_pkey PRIMARY KEY (id),
    CONSTRAINT model_provider_connection_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT model_provider_connection_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT model_provider_connection_provider_chk CHECK (provider IN ('openai', 'anthropic')),
    CONSTRAINT model_provider_connection_status_chk CHECK (status IN ('active', 'error', 'revoked')),
    CONSTRAINT model_provider_connection_fingerprint_chk CHECK (key_fingerprint <> ''),
    CONSTRAINT model_provider_connection_revoked_chk CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT model_provider_connection_secret_chk CHECK (status = 'revoked' OR secret_ref <> '')
);

-- One live connection per organisation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_model_provider_connection_live
    ON public.model_provider_connection (workspace_id, provider, org_id)
    WHERE status <> 'revoked';
CREATE INDEX IF NOT EXISTS idx_model_provider_connection_ws
    ON public.model_provider_connection (workspace_id, created_at DESC, id);
-- The sync worker's due scan.
CREATE INDEX IF NOT EXISTS idx_model_provider_connection_due
    ON public.model_provider_connection (next_sync_at)
    WHERE status <> 'revoked' AND next_sync_at IS NOT NULL;

COMMENT ON TABLE public.model_provider_connection IS
    'A connected OpenAI / Anthropic organisation (opt-in). The admin key is in Vault (secret_ref); never stored here.';

CREATE TABLE IF NOT EXISTS public.model_provider_key (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL,
    connection_id       uuid        NOT NULL,
    provider_key_id     text        NOT NULL,
    name                text        NOT NULL DEFAULT '',
    -- The provider's own redacted hint (e.g. sk-...abcd). Never the key.
    key_hint            text        NOT NULL DEFAULT '',
    -- OpenAI project / Anthropic workspace.
    project_id          text        NOT NULL DEFAULT '',
    project_name        text        NOT NULL DEFAULT '',
    owner_type          text        NOT NULL DEFAULT '',
    owner_id            text        NOT NULL DEFAULT '',
    owner_name          text        NOT NULL DEFAULT '',
    created_at_provider timestamptz,
    last_used_at        timestamptz,
    status              text        NOT NULL DEFAULT 'active',
    -- Weak attribution: [{strength, via, matched, ...}] (spec §5).
    links               jsonb       NOT NULL DEFAULT '[]'::jsonb,
    first_seen          timestamptz NOT NULL DEFAULT now(),
    last_seen           timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT model_provider_key_pkey PRIMARY KEY (id),
    CONSTRAINT model_provider_key_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT model_provider_key_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT model_provider_key_connection_fkey FOREIGN KEY (workspace_id, connection_id)
        REFERENCES public.model_provider_connection (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT model_provider_key_key UNIQUE (workspace_id, connection_id, provider_key_id),
    CONSTRAINT model_provider_key_id_chk CHECK (provider_key_id <> ''),
    CONSTRAINT model_provider_key_owner_chk CHECK (owner_type IN ('', 'user', 'service_account')),
    CONSTRAINT model_provider_key_status_chk
        CHECK (status IN ('active', 'inactive', 'archived', 'expired', 'deleted', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_model_provider_key_connection
    ON public.model_provider_key (workspace_id, connection_id, status, name);

COMMENT ON TABLE public.model_provider_key IS
    'Provider API keys of a connected organisation as last listed: names, project, owner, dates. Never a key value.';

CREATE TABLE IF NOT EXISTS public.model_provider_usage (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL,
    connection_id       uuid        NOT NULL,
    -- '' for usage the provider ties to no key (console, playground).
    provider_key_id     text        NOT NULL DEFAULT '',
    project_id          text        NOT NULL DEFAULT '',
    model               text        NOT NULL DEFAULT '',
    bucket_start        timestamptz NOT NULL,
    -- NULL when the provider reports no request count (Anthropic).
    requests            bigint,
    input_tokens        bigint      NOT NULL DEFAULT 0,
    cached_input_tokens bigint      NOT NULL DEFAULT 0,
    output_tokens       bigint      NOT NULL DEFAULT 0,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT model_provider_usage_pkey PRIMARY KEY (id),
    CONSTRAINT model_provider_usage_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT model_provider_usage_connection_fkey FOREIGN KEY (workspace_id, connection_id)
        REFERENCES public.model_provider_connection (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT model_provider_usage_bucket_key
        UNIQUE (workspace_id, connection_id, provider_key_id, project_id, model, bucket_start),
    CONSTRAINT model_provider_usage_counts_chk
        CHECK ((requests IS NULL OR requests >= 0) AND input_tokens >= 0 AND cached_input_tokens >= 0 AND output_tokens >= 0)
);

CREATE INDEX IF NOT EXISTS idx_model_provider_usage_bucket
    ON public.model_provider_usage (workspace_id, connection_id, bucket_start);

COMMENT ON TABLE public.model_provider_usage IS
    'Hourly model usage per provider key, project and model (token and request counts only; never a prompt).';

-- agent_finding: the kinds of every branch, and provider-connection findings.
DO $$
BEGIN
    IF to_regclass('public.agent_finding') IS NOT NULL THEN
        ALTER TABLE public.agent_finding DROP CONSTRAINT IF EXISTS agent_finding_kind_chk;
        ALTER TABLE public.agent_finding ADD CONSTRAINT agent_finding_kind_chk
            CHECK (kind IN ('shared_role', 'human_credentials', 'long_lived_key', 'model_key_secret',
                            'ai_config_hint', 'ai_network_traffic', 'unaccounted_model_usage'));
        ALTER TABLE public.agent_finding ALTER COLUMN connector_id DROP NOT NULL;
        ALTER TABLE public.agent_finding ADD COLUMN IF NOT EXISTS provider_connection_id uuid;
        ALTER TABLE public.agent_finding DROP CONSTRAINT IF EXISTS agent_finding_provider_connection_fkey;
        ALTER TABLE public.agent_finding ADD CONSTRAINT agent_finding_provider_connection_fkey
            FOREIGN KEY (workspace_id, provider_connection_id)
            REFERENCES public.model_provider_connection (workspace_id, id) ON DELETE CASCADE;
        ALTER TABLE public.agent_finding DROP CONSTRAINT IF EXISTS agent_finding_source_chk;
        ALTER TABLE public.agent_finding ADD CONSTRAINT agent_finding_source_chk
            CHECK (connector_id IS NOT NULL OR provider_connection_id IS NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_agent_finding_provider_connection
            ON public.agent_finding (workspace_id, provider_connection_id, state)
            WHERE provider_connection_id IS NOT NULL;
    END IF;
END $$;

-- Required for every workspace table; guarded as in 139 and 146.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.model_provider_connection');
        PERFORM public.tenancy_enable_rls('public.model_provider_key');
        PERFORM public.tenancy_enable_rls('public.model_provider_usage');
    END IF;
END $$;
