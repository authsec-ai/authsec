-- 002_agent_discovery.sql
--
-- Adds the Agent Discovery (IGA) tables and their RBAC permissions to an
-- ALREADY-BOOTSTRAPPED database. 001_bootstrap.sql carries the same definitions
-- for fresh installs; the two must stay in agreement.
--
-- Applied automatically at boot by internal/migration/runner.go and recorded in
-- migration_logs. Every statement is IF NOT EXISTS / ON CONFLICT DO NOTHING, so
-- it is a no-op where these tables already exist.

-- Agent Discovery (IGA) ---------------------------------------------------
-- A quarantine-first inventory of every AI agent running in a workspace's
-- estate, including ones nobody registered. A sighting NEVER grants access: it
-- only makes an agent visible, which is what makes it safe to run discovery
-- against production before anything is provisioned or enforced. An agent
-- becomes a governed principal only when a human claims it (linking it to an
-- mcp_oauth_clients identity and an accountable owner) -- otherwise an admin
-- quarantines it.

-- discovery_sources -- a configured connector that produces sightings.
-- kind: k8s_webhook and repo_scan are the active channels; aws/azure/gcp/
--   vm_sensor are designed but deferred and need no schema change to enable.
-- config: non-secret connector settings. Secrets belong in Vault, not here.
CREATE TABLE IF NOT EXISTS public.discovery_sources (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    kind         text NOT NULL,
    display_name text NOT NULL,
    config       jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled      boolean NOT NULL DEFAULT true,
    last_sync_at timestamptz,
    last_status  text NOT NULL DEFAULT '',
    last_error   text NOT NULL DEFAULT '',
    created_by   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovery_sources_pkey PRIMARY KEY (id),
    CONSTRAINT discovery_sources_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT discovery_sources_kind_chk CHECK (
        kind IN ('k8s_webhook', 'aws', 'azure', 'gcp', 'vm_sensor', 'repo_scan')),
    CONSTRAINT discovery_sources_workspace_kind_name_key UNIQUE (workspace_id, kind, display_name)
);

CREATE INDEX IF NOT EXISTS idx_discovery_sources_workspace ON public.discovery_sources(workspace_id);

-- discovered_agents -- one row per distinct agent sighting, keyed by a stable
-- fingerprint. UNIQUE(workspace_id, source, fingerprint) is what makes a
-- repeated sighting an upsert (a last_seen_at / sighting_count bump) instead of
-- a duplicate row -- the connector can re-report freely and idempotently.
--
-- status moves forward only (unregistered -> registered | quarantined |
--   ignored); it never returns to unregistered. 'ignored' is the "keep the row
--   but stop surfacing it" state, so there is no soft-delete column here.
-- deployment_origin: a manually run agent (a developer's script with no
--   pipeline behind it) is the higher-risk, harder-to-attribute case, since its
--   permissions are typically whatever the developer's own credentials allow --
--   so the Unregistered Agents report surfaces manual first. It is a heuristic;
--   an admin correction is audited like any other decision.
-- archetype: '' until known. Autonomous agents hold their own authority;
--   user-delegated agents borrow a scoped slice of a user's.
CREATE TABLE IF NOT EXISTS public.discovered_agents (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    source              text NOT NULL,
    discovery_source_id uuid,
    fingerprint         text NOT NULL,
    display_name        text NOT NULL DEFAULT '',
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
    deployment_origin   text NOT NULL DEFAULT 'unknown',
    archetype           text NOT NULL DEFAULT '',
    -- the governed identity this sighting was claimed into
    matched_client_id   uuid,
    -- the accountable human; mandatory to register (see registered_chk)
    owner_user_id       uuid,
    status              text NOT NULL DEFAULT 'unregistered',
    claimed_by          uuid,
    claimed_at          timestamptz,
    quarantined_by      uuid,
    quarantined_at      timestamptz,
    quarantine_reason   text NOT NULL DEFAULT '',
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    sighting_count      integer NOT NULL DEFAULT 1,
    created_by          text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovered_agents_pkey PRIMARY KEY (id),
    CONSTRAINT discovered_agents_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- A single-column FK (not the composite (workspace_id, id) pattern used by
    -- connector children) because an agent must OUTLIVE its source: deleting a
    -- connector nulls the pointer and keeps the inventory row. A composite FK
    -- cannot ON DELETE SET NULL without nulling the NOT NULL workspace_id. The
    -- service only ever resolves a source inside the caller's workspace.
    CONSTRAINT discovered_agents_source_id_fkey FOREIGN KEY (discovery_source_id)
        REFERENCES public.discovery_sources(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agents_matched_client_fkey FOREIGN KEY (matched_client_id)
        REFERENCES public.mcp_oauth_clients(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agents_owner_fkey FOREIGN KEY (owner_user_id)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT discovered_agents_source_chk CHECK (
        source IN ('k8s_webhook', 'aws', 'azure', 'gcp', 'vm_sensor', 'repo_scan')),
    CONSTRAINT discovered_agents_origin_chk CHECK (
        deployment_origin IN ('manual', 'automated', 'unknown')),
    CONSTRAINT discovered_agents_status_chk CHECK (
        status IN ('unregistered', 'registered', 'quarantined', 'ignored')),
    CONSTRAINT discovered_agents_archetype_chk CHECK (
        archetype IN ('', 'autonomous', 'user_delegated', 'hybrid')),
    -- Registered means claimed: a governed principal always has both an identity
    -- to trace tokens to and an accountable human owner. Enforced in the DB so
    -- no code path can produce an unowned registered agent.
    CONSTRAINT discovered_agents_registered_chk CHECK (
        status <> 'registered'
        OR (matched_client_id IS NOT NULL AND owner_user_id IS NOT NULL)),
    CONSTRAINT discovered_agents_fingerprint_key UNIQUE (workspace_id, source, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_discovered_agents_workspace_status_origin
    ON public.discovered_agents(workspace_id, status, deployment_origin);
CREATE INDEX IF NOT EXISTS idx_discovered_agents_last_seen ON public.discovered_agents(last_seen_at);

-- Discovery RBAC permissions -- GLOBAL (workspace_id IS NULL) so they apply in
-- every workspace, exactly like the connector:* permissions above. Admins grant
-- the matching role per workspace via normal RBAC. discovery:report is split out
-- from the rest so a connector's service account can report sightings without
-- holding any authority to claim or quarantine.
INSERT INTO public.permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
VALUES
    (gen_random_uuid(), NULL, 'discovery', 'report',     'Report an agent sighting',            'discovery:report',     NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'read',       'Read the discovered-agent inventory', 'discovery:read',       NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'claim',      'Claim an agent into an identity',     'discovery:claim',      NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'quarantine', 'Quarantine a discovered agent',       'discovery:quarantine', NOW()),
    (gen_random_uuid(), NULL, 'discovery', 'admin',      'Manage discovery sources',            'discovery:admin',      NOW())
ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING;
