-- 240_agent_gateway_keys.sql
--
-- W6 (SPEC-secops-backend-upgrade.md C6): gateway keys held by AuthSec.
--
-- 1. agent_gateway_provider_key: a model provider API key a workspace's
--    gateways use upstream. The key itself is in Vault under the workspace's
--    path (kv/data/secret/workspaces/<ws>/agent-gateway/provider-keys/<id>-<nonce>);
--    this row holds only that path (secret_ref, '' once revoked) and a
--    fingerprint. A gateway fetches the keys assigned to it (gateway_id, or
--    NULL for every gateway of the workspace) with its agw_ credential and
--    keeps them in memory only. provider_key_id names the provider's own id
--    of the key (OpenAI key_..., Anthropic apikey_...) when known, so provider
--    usage can be joined to what the gateway sent (reconciliation).
-- 2. agent_gateway_agent_key: a per-agent gateway key ("agk_", shown once,
--    stored as its sha256) bound to a workload identity (a SPIFFE id, an
--    AuthSec workload id, or both). A gateway accepts the key only from the
--    workload identity it is bound to. agent_id is the W7 agent and
--    principal_user_id the human the agent acts for, when known (a held
--    call is never approved by that human).
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.agent_gateway_provider_key (
    id               uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    name             text        NOT NULL CHECK (btrim(name) <> '' AND length(name) <= 200),
    -- The provider as policies name it (openai, anthropic, groq ...).
    provider         text        NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,63}$'),
    -- NULL: every gateway of the workspace may fetch it.
    gateway_id       uuid,
    -- Vault path of the key; '' once revoked. Never the key.
    secret_ref       text        NOT NULL DEFAULT '',
    key_fingerprint  text        NOT NULL CHECK (key_fingerprint <> ''),
    provider_key_id  text        NOT NULL DEFAULT '' CHECK (length(provider_key_id) <= 200),
    connection_id    uuid,
    state            text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_by       uuid        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    rotated_at       timestamptz,
    revoked_at       timestamptz,
    revoked_by       uuid,
    last_fetched_at  timestamptz,
    version          integer     NOT NULL DEFAULT 1,
    CONSTRAINT agent_gateway_provider_key_pkey PRIMARY KEY (id),
    CONSTRAINT agent_gateway_provider_key_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_gateway_provider_key_gateway_fkey FOREIGN KEY (workspace_id, gateway_id)
        REFERENCES public.agent_gateway (workspace_id, id),
    CONSTRAINT agent_gateway_provider_key_revoked_chk CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT agent_gateway_provider_key_secret_chk CHECK (state = 'revoked' OR secret_ref <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_gateway_provider_key_live_name
    ON public.agent_gateway_provider_key (workspace_id, lower(name)) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_agent_gateway_provider_key_ws
    ON public.agent_gateway_provider_key (workspace_id, provider, state);

COMMENT ON TABLE public.agent_gateway_provider_key IS
    'Model provider keys gateways use upstream; the key is in Vault (secret_ref), never stored here or returned to the console.';

CREATE TABLE IF NOT EXISTS public.agent_gateway_agent_key (
    id                uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    name              text        NOT NULL CHECK (btrim(name) <> '' AND length(name) <= 200),
    -- The AuthZEN subject.id the gateway decides with.
    client_id         text        NOT NULL CHECK (btrim(client_id) <> '' AND length(client_id) <= 512),
    key_hash          text        NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    key_prefix        text        NOT NULL,
    -- The workload identity the key is bound to: a SPIFFE id, an AuthSec
    -- workload id, or both (both must then match).
    spiffe_id         text        NOT NULL DEFAULT '' CHECK (spiffe_id = '' OR (spiffe_id LIKE 'spiffe://%' AND length(spiffe_id) <= 512)),
    workload_id       uuid,
    identity_id       uuid,
    labels            jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(labels) = 'array'),
    agent_id          uuid,
    principal_user_id uuid,
    gateway_id        uuid,
    created_by        uuid        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    rotated_at        timestamptz,
    revoked_at        timestamptz,
    revoked_by        uuid,
    revoked_reason    text        NOT NULL DEFAULT '' CHECK (length(revoked_reason) <= 500),
    version           integer     NOT NULL DEFAULT 1,
    CONSTRAINT agent_gateway_agent_key_pkey PRIMARY KEY (id),
    CONSTRAINT agent_gateway_agent_key_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_gateway_agent_key_gateway_fkey FOREIGN KEY (workspace_id, gateway_id)
        REFERENCES public.agent_gateway (workspace_id, id),
    CONSTRAINT agent_gateway_agent_key_bound_chk CHECK (spiffe_id <> '' OR workload_id IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_gateway_agent_key_hash
    ON public.agent_gateway_agent_key (key_hash);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_gateway_agent_key_live_client
    ON public.agent_gateway_agent_key (workspace_id, client_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_agent_gateway_agent_key_ws
    ON public.agent_gateway_agent_key (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_agent_key_agent
    ON public.agent_gateway_agent_key (workspace_id, agent_id) WHERE agent_id IS NOT NULL;

COMMENT ON TABLE public.agent_gateway_agent_key IS
    'Per-agent gateway keys (agk_, sha256 only) bound to a workload identity; a gateway accepts a key only with that identity.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_gateway_provider_key');
        PERFORM public.tenancy_enable_rls('public.agent_gateway_agent_key');
    END IF;
END $$;
