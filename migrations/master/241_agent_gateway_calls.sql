-- 241_agent_gateway_calls.sql
--
-- W6 (SPEC-secops-backend-upgrade.md C6, P17): what the decision log keeps
-- about a call, and held calls.
--
-- 1. agent_gateway_decision gains, as metadata only:
--    run_id            the X-AuthSec-Run-Id that ties one agent run's calls
--                      across hops;
--    model_version     the model the provider says answered (the "model" of
--                      the OpenAI / Anthropic response), on outcomes;
--    provider_key_ref  the AuthSec-held provider key the gateway used;
--    hold_id           the held call a decision "ask" opened;
--    violations        the bounded argument paths a call broke and which
--                      rule -- never the values.
--    decision admits 'ask' (a call held for a person).
-- 2. agent_gateway_hold: a call held because its arguments are outside the
--    bounds of the policy that allowed it. It names its approver (responder
--    resolution) and expires. held_values are the bounded fields' values,
--    kept for the approver only and cleared when the hold ends; the decision
--    log never has them. The approver is never the agent's own human.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

ALTER TABLE public.agent_gateway_decision ADD COLUMN IF NOT EXISTS run_id text NOT NULL DEFAULT ''
    CHECK (length(run_id) <= 128);
ALTER TABLE public.agent_gateway_decision ADD COLUMN IF NOT EXISTS model_version text NOT NULL DEFAULT ''
    CHECK (length(model_version) <= 200);
ALTER TABLE public.agent_gateway_decision ADD COLUMN IF NOT EXISTS provider_key_ref uuid;
ALTER TABLE public.agent_gateway_decision ADD COLUMN IF NOT EXISTS hold_id uuid;
ALTER TABLE public.agent_gateway_decision ADD COLUMN IF NOT EXISTS violations jsonb;
ALTER TABLE public.agent_gateway_decision DROP CONSTRAINT IF EXISTS agent_gateway_decision_decision_check;
ALTER TABLE public.agent_gateway_decision DROP CONSTRAINT IF EXISTS agent_gateway_decision_decision_chk;
ALTER TABLE public.agent_gateway_decision ADD CONSTRAINT agent_gateway_decision_decision_chk
    CHECK (decision IN ('allow', 'deny', 'ask'));
CREATE INDEX IF NOT EXISTS idx_agent_gateway_decision_run
    ON public.agent_gateway_decision (workspace_id, run_id, decided_at) WHERE run_id <> '';
CREATE INDEX IF NOT EXISTS idx_agent_gateway_decision_provider_key
    ON public.agent_gateway_decision (workspace_id, provider_key_ref, decided_at) WHERE provider_key_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.agent_gateway_hold (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    gateway_id         uuid        NOT NULL,
    subject_id         text        NOT NULL CHECK (length(subject_id) <= 512),
    subject            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    kind               text        NOT NULL CHECK (kind IN ('mcp_tool', 'model')),
    resource_id        text        NOT NULL CHECK (length(resource_id) <= 1024),
    resource           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    policy_id          uuid,
    args_digest        text        NOT NULL CHECK (args_digest ~ '^sha256:[0-9a-f]{64}$'),
    run_id             text        NOT NULL DEFAULT '' CHECK (length(run_id) <= 128),
    request_id         text        NOT NULL DEFAULT '' CHECK (length(request_id) <= 128),
    violations         jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(violations) = 'array'),
    -- The bounded fields' values, for the approver; NULL once the hold ended.
    held_values        jsonb,
    agent_key_id       uuid,
    agent_id           uuid,
    principal_user_id  uuid,
    responder_group_id uuid,
    responder_via      text        NOT NULL DEFAULT '',
    approver_user_id   uuid,
    deciders           jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(deciders) = 'array'),
    state              text        NOT NULL DEFAULT 'pending'
                       CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    decided_by         uuid,
    decided_at         timestamptz,
    decision_reason    text        NOT NULL DEFAULT '' CHECK (length(decision_reason) <= 2000),
    consumed_at        timestamptz,
    CONSTRAINT agent_gateway_hold_pkey PRIMARY KEY (id),
    CONSTRAINT agent_gateway_hold_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_gateway_hold_not_principal_chk
        CHECK (decided_by IS NULL OR principal_user_id IS NULL OR decided_by <> principal_user_id),
    CONSTRAINT agent_gateway_hold_decided_chk CHECK ((decided_by IS NULL) = (decided_at IS NULL)),
    CONSTRAINT agent_gateway_hold_values_chk CHECK (held_values IS NULL OR state IN ('pending', 'approved'))
);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_hold_ws_state
    ON public.agent_gateway_hold (workspace_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_hold_due
    ON public.agent_gateway_hold (expires_at) WHERE state IN ('pending', 'approved');

COMMENT ON TABLE public.agent_gateway_hold IS
    'Gateway calls held for a person (argument bounds): approver, expiry; bounded values kept for the approver only until the hold ends.';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_gateway_hold');
    END IF;
END $$;
