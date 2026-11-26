-- 156_agent_runtime_gateway.sql
--
-- Agent runtime gateway (SPEC-agent-runtime-gateway.md): AuthSec as the
-- policy decision point for MCP tool calls and model calls made through a
-- gateway that runs in the customer's environment.
--
-- 1. agent_gateway: one gateway (policy enforcement point) of a workspace,
--    with its credential's sha256 (the credential is shown once, never
--    stored), prefix, last contact and revocation.
-- 2. agent_gateway_setting: per workspace, the default decision (observe =
--    allow, enforce = deny), the decision cache lifetime handed to gateways,
--    and the decision log retention.
-- 3. agent_tool_policy: allow / deny policies on MCP tools or models, per
--    agent selector, with conditions (time window, calls per minute).
-- 4. agent_gateway_decision: every decision (made by the PDP or by a gateway
--    from its cache or fail mode) and every outcome (token usage) as
--    metadata only -- never prompts, completions or argument values.
--    Append-only (trigger); deleted only by a workspace purge or the
--    retention purge of rows older than 7 days. Keyed (workspace_id, id):
--    a gateway chooses the ids of the rows it uploads, so one workspace's
--    ids can never collide with another's.
--
-- gateway_id on decisions and policies is deliberately not a foreign key:
-- a decision outlives its gateway's revocation, and gateways are revoked,
-- never deleted.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS agent_gateway (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id      uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name              text NOT NULL CHECK (btrim(name) <> '' AND length(name) <= 200),
  credential_hash   text NOT NULL CHECK (credential_hash ~ '^[0-9a-f]{64}$'),
  credential_prefix text NOT NULL,
  created_by        uuid NOT NULL REFERENCES users(id),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  rotated_at        timestamptz,
  revoked_at        timestamptz,
  last_seen_at      timestamptz,
  software_version  text NOT NULL DEFAULT '' CHECK (length(software_version) <= 64),
  version           integer NOT NULL DEFAULT 1,
  UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_gateway_credential ON agent_gateway (credential_hash);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_gateway_live_name ON agent_gateway (workspace_id, lower(name))
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_agent_gateway_ws ON agent_gateway (workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_gateway_setting (
  workspace_id            uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  mode                    text NOT NULL DEFAULT 'observe' CHECK (mode IN ('observe','enforce')),
  cache_ttl_seconds       integer NOT NULL DEFAULT 30 CHECK (cache_ttl_seconds BETWEEN 0 AND 300),
  decision_retention_days integer NOT NULL DEFAULT 30 CHECK (decision_retention_days BETWEEN 7 AND 3650),
  updated_by              uuid REFERENCES users(id),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  version                 integer NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS agent_tool_policy (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name                text NOT NULL CHECK (btrim(name) <> '' AND length(name) <= 200),
  description         text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
  -- Subject selector: every non-empty field must match; none = every agent.
  subject_identity_id uuid,
  subject_workload_id uuid,
  subject_agent_label text NOT NULL DEFAULT '' CHECK (length(subject_agent_label) <= 200),
  subject_client_id   text NOT NULL DEFAULT '' CHECK (length(subject_client_id) <= 512),
  gateway_id          uuid,
  effect              text NOT NULL CHECK (effect IN ('allow','deny')),
  kind                text NOT NULL CHECK (kind IN ('mcp_tool','model')),
  -- Target patterns ('*' matches any run of characters; '' = any).
  target_server       text NOT NULL DEFAULT '' CHECK (length(target_server) <= 512),
  target_server_url   text NOT NULL DEFAULT '' CHECK (length(target_server_url) <= 512),
  target_tool         text NOT NULL DEFAULT '' CHECK (length(target_tool) <= 512),
  target_provider     text NOT NULL DEFAULT '' CHECK (length(target_provider) <= 512),
  target_model        text NOT NULL DEFAULT '' CHECK (length(target_model) <= 512),
  conditions          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(conditions) = 'object'),
  deny_unlisted       boolean NOT NULL DEFAULT false,
  priority            integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN -1000000 AND 1000000),
  enabled             boolean NOT NULL DEFAULT true,
  created_by          uuid NOT NULL REFERENCES users(id),
  updated_by          uuid REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  version             integer NOT NULL DEFAULT 1,
  UNIQUE (workspace_id, id),
  CONSTRAINT agent_tool_policy_target_kind_chk CHECK (
    (kind = 'mcp_tool' AND target_provider = '' AND target_model = '') OR
    (kind = 'model' AND target_server = '' AND target_server_url = '' AND target_tool = '')),
  CONSTRAINT agent_tool_policy_deny_unlisted_chk CHECK (effect = 'allow' OR NOT deny_unlisted)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_tool_policy_name ON agent_tool_policy (workspace_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_agent_tool_policy_ws ON agent_tool_policy (workspace_id, kind, enabled);

CREATE TABLE IF NOT EXISTS agent_gateway_decision (
  id              uuid NOT NULL DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  gateway_id      uuid NOT NULL,
  record_type     text NOT NULL DEFAULT 'decision' CHECK (record_type IN ('decision','outcome')),
  -- Who decided: the PDP, or the gateway from its cache, its fail mode or
  -- its own checks (tool definition pinning).
  source          text NOT NULL CHECK (source IN ('pdp','cache','gateway','fail_open','fail_closed')),
  decided_at      timestamptz NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now(),
  subject_type    text NOT NULL DEFAULT 'agent' CHECK (length(subject_type) <= 64),
  subject_id      text NOT NULL CHECK (length(subject_id) <= 512),
  subject         jsonb NOT NULL DEFAULT '{}'::jsonb,
  action          text NOT NULL CHECK (length(action) <= 128),
  kind            text NOT NULL CHECK (kind IN ('mcp_tool','model')),
  resource_id     text NOT NULL CHECK (length(resource_id) <= 1024),
  resource        jsonb NOT NULL DEFAULT '{}'::jsonb,
  decision        text NOT NULL CHECK (decision IN ('allow','deny')),
  reason          text NOT NULL DEFAULT '' CHECK (length(reason) <= 64),
  policy_id       uuid,
  -- The PDP decision a cached decision or an outcome refers to.
  decision_ref    uuid,
  latency_ms      double precision CHECK (latency_ms IS NULL OR latency_ms >= 0),
  args_digest     text CHECK (args_digest IS NULL OR args_digest ~ '^sha256:[0-9a-f]{64}$'),
  usage           jsonb,
  upstream_status integer CHECK (upstream_status IS NULL OR upstream_status BETWEEN 100 AND 599),
  request_id      text NOT NULL DEFAULT '' CHECK (length(request_id) <= 128),
  PRIMARY KEY (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_decision_ws_time ON agent_gateway_decision (workspace_id, decided_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_decision_gateway ON agent_gateway_decision (workspace_id, gateway_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_decision_subject ON agent_gateway_decision (workspace_id, subject_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_gateway_decision_retention ON agent_gateway_decision (decided_at);

CREATE OR REPLACE FUNCTION agent_gateway_decision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('authsec.workspace_purge', true) = 'on' THEN
    RETURN OLD;
  END IF;
  IF TG_OP = 'DELETE' AND current_setting('authsec.gateway_decision_purge', true) = 'on'
     AND OLD.decided_at < now() - interval '7 days' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'agent_gateway_decision is append-only';
END $$;
DROP TRIGGER IF EXISTS agent_gateway_decision_no_update ON agent_gateway_decision;
CREATE TRIGGER agent_gateway_decision_no_update BEFORE UPDATE OR DELETE ON agent_gateway_decision
  FOR EACH ROW EXECUTE FUNCTION agent_gateway_decision_immutable();

-- Required for every workspace table; guarded as in 146.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_gateway');
        PERFORM public.tenancy_enable_rls('public.agent_gateway_setting');
        PERFORM public.tenancy_enable_rls('public.agent_tool_policy');
        PERFORM public.tenancy_enable_rls('public.agent_gateway_decision');
    END IF;
END $$;
