-- 147_agentkit.sql
--
-- AuthSec Agent Kit (authsec-cli) control plane. A machine running the
-- daemon is a discovery source of kind vm_sensor; its agents arrive as
-- sightings. Two workspace tables are added:
--
-- 1. agentkit_events: what a machine's daemon decided or detected (a denied
--    connection, a killed command, a quarantine, an ARTEX detection), for the
--    console's logs and impact views. Append-only; the source is pinned to the
--    same workspace by a composite foreign key. Type access is a machine's
--    periodic summary of what one agent reached (files, hosts, services).
-- 2. agentkit_policies: agent policies (authsec.ai/v1 AgentPolicy YAML) kept
--    per workspace, one row per version, which machines pull.
--
-- Quarantine and release of a machine's agent reuse provisioning_instructions
-- (kinds quarantine/unquarantine), leased by the machine with its actuation
-- credential, so no table is added for them.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS agentkit_events (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  discovery_source_id uuid NOT NULL,
  observed_at         timestamptz NOT NULL,
  received_at         timestamptz NOT NULL DEFAULT now(),
  type                text NOT NULL CHECK (type IN ('decision','detection','agent_started','agent_stopped','sensor','access')),
  kind                text NOT NULL DEFAULT '' CHECK (length(kind) <= 40),
  action              text NOT NULL DEFAULT '' CHECK (length(action) <= 40),
  rule                text NOT NULL DEFAULT '' CHECK (length(rule) <= 200),
  severity            text NOT NULL DEFAULT '' CHECK (severity IN ('','high','medium','low')),
  enforced            boolean NOT NULL DEFAULT false,
  agent_id            text NOT NULL DEFAULT '' CHECK (length(agent_id) <= 100),
  agent_name          text NOT NULL DEFAULT '' CHECK (length(agent_name) <= 200),
  agent_pid           integer NOT NULL DEFAULT 0,
  -- The whole record as the daemon logged it (names, paths, scrubbed
  -- command lines; never secret values), at most 16 KiB.
  record              jsonb NOT NULL CHECK (pg_column_size(record) <= 16384),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, discovery_source_id) REFERENCES discovery_sources (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agentkit_events_ws_time ON agentkit_events (workspace_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentkit_events_source ON agentkit_events (workspace_id, discovery_source_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentkit_events_type ON agentkit_events (workspace_id, type, observed_at DESC);

CREATE TABLE IF NOT EXISTS agentkit_policies (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  -- The agent the policy applies to (a recogniser id such as claude-code),
  -- or '*' for every agent without its own.
  agent_id     text NOT NULL CHECK (agent_id ~ '^(\*|[a-z0-9][a-z0-9._-]{0,99})$'),
  version      integer NOT NULL CHECK (version > 0),
  document     text NOT NULL CHECK (length(document) BETWEEN 1 AND 262144),
  sha256       text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  comment      text NOT NULL DEFAULT '' CHECK (length(comment) <= 500),
  created_by   uuid, -- the console user who saved it (audit_events has the rest)
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, agent_id, version)
);
CREATE INDEX IF NOT EXISTS idx_agentkit_policies_latest ON agentkit_policies (workspace_id, agent_id, version DESC);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agentkit_events');
        PERFORM public.tenancy_enable_rls('public.agentkit_policies');
    END IF;
END $$;
