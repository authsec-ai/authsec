-- ============================================================================
-- 120: embedded SPIRE control plane tables, per workspace (AS-081)
--
-- The embedded SPIRE control plane (internal/spire, ENABLE_EMBEDDED_SPIRE)
-- queried agents, workload_entries, workloads, certificates,
-- attestation_policies, audit_icp_logs and workload_svids: tables of the old
-- per-tenant databases that the shared database never had. They are created
-- here with a spire_ prefix, owned by a workspace:
--
--   spire_agents                 attested nodes (agent SVIDs)
--   spire_join_tokens            single-use node attestation tokens; the
--                                token, not the caller, decides the workspace
--   spire_workload_entries       registration entries (selectors -> SPIFFE ID)
--   spire_workload_svids         X.509 SVIDs issued to workloads by agents
--   spire_attested_workloads     workloads attested directly (mTLS /v1/attest);
--                                spire_workloads is the headless registry and
--                                has a different shape
--   spire_certificates           certificates issued to attested workloads
--   spire_attestation_policies   attestation policies
--   spire_icp_audit_logs         attest / renew / revoke audit trail
--
-- Every table: workspace_id NOT NULL with a cascading FK to workspaces, a
-- workspace-leading index, per-workspace uniques, UNIQUE (workspace_id, id)
-- where children reference it, and row-level security
-- (tenancy_enable_rls). spire_join_tokens.token_hash stays globally unique:
-- it is a SHA-256 of 32 random bytes and is looked up before any workspace is
-- known.
--
-- spire_policies.name becomes unique per workspace instead of globally: the
-- policy engine now reads only the caller's workspace's policies.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.spire_agents (
    id                 uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id       uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    node_id            varchar(255) NOT NULL,
    spiffe_id          varchar(512) NOT NULL,
    attestation_type   varchar(100) NOT NULL,
    node_selectors     jsonb DEFAULT '{}'::jsonb NOT NULL,
    certificate_serial varchar(255),
    status             varchar(50) DEFAULT 'active' NOT NULL,
    cluster_name       varchar(255),
    join_token_id      uuid,
    last_seen          timestamptz,
    last_heartbeat     timestamptz,
    created_at         timestamptz DEFAULT now() NOT NULL,
    updated_at         timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_agents_pkey PRIMARY KEY (id),
    CONSTRAINT spire_agents_status_check CHECK (status IN ('active', 'expired', 'revoked')),
    CONSTRAINT uq_spire_agents_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT uq_spire_agents_workspace_spiffe UNIQUE (workspace_id, spiffe_id),
    CONSTRAINT uq_spire_agents_workspace_node UNIQUE (workspace_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_spire_agents_workspace_status
    ON public.spire_agents (workspace_id, status);

CREATE TABLE IF NOT EXISTS public.spire_join_tokens (
    id               uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id     uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    token_hash       char(64) NOT NULL,
    description      text,
    created_by       uuid,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    used_by_node_id  varchar(255),
    revoked_at       timestamptz,
    created_at       timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_join_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT uq_spire_join_tokens_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT uq_spire_join_tokens_hash UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS idx_spire_join_tokens_workspace_created
    ON public.spire_join_tokens (workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.spire_workload_entries (
    id              uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id    uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    spiffe_id       varchar(512) NOT NULL,
    parent_id       varchar(512) DEFAULT '' NOT NULL,
    selectors       jsonb NOT NULL,
    ttl             integer,
    admin           boolean DEFAULT false NOT NULL,
    downstream      boolean DEFAULT false NOT NULL,
    federates_with  text[],
    dns_names       text[],
    spire_entry_id  varchar(255),
    created_at      timestamptz DEFAULT now() NOT NULL,
    updated_at      timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_workload_entries_pkey PRIMARY KEY (id),
    CONSTRAINT uq_spire_workload_entries_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT uq_spire_workload_entries_workspace_spiffe UNIQUE (workspace_id, spiffe_id)
);
CREATE INDEX IF NOT EXISTS idx_spire_workload_entries_workspace_parent
    ON public.spire_workload_entries (workspace_id, parent_id);

CREATE TABLE IF NOT EXISTS public.spire_workload_svids (
    id               uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id     uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    entry_id         uuid NOT NULL,
    agent_spiffe_id  varchar(512),
    spiffe_id        varchar(512) NOT NULL,
    serial_number    varchar(255) NOT NULL,
    ttl              integer,
    issued_at        timestamptz DEFAULT now() NOT NULL,
    expires_at       timestamptz,
    revoked_at       timestamptz,
    created_at       timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_workload_svids_pkey PRIMARY KEY (id),
    CONSTRAINT uq_spire_workload_svids_workspace_serial UNIQUE (workspace_id, serial_number),
    CONSTRAINT fk_spire_workload_svids_entry FOREIGN KEY (workspace_id, entry_id)
        REFERENCES public.spire_workload_entries (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_spire_workload_svids_workspace_entry
    ON public.spire_workload_svids (workspace_id, entry_id);

CREATE TABLE IF NOT EXISTS public.spire_attested_workloads (
    id                uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id      uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    spiffe_id         varchar(512) NOT NULL,
    selectors         jsonb DEFAULT '{}'::jsonb NOT NULL,
    vault_role        varchar(255) NOT NULL,
    status            varchar(50) DEFAULT 'active' NOT NULL,
    attestation_type  varchar(50) NOT NULL,
    created_at        timestamptz DEFAULT now() NOT NULL,
    updated_at        timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_attested_workloads_pkey PRIMARY KEY (id),
    CONSTRAINT uq_spire_attested_workloads_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT uq_spire_attested_workloads_workspace_spiffe UNIQUE (workspace_id, spiffe_id)
);

CREATE TABLE IF NOT EXISTS public.spire_certificates (
    id                  uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id        uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    workload_id         uuid NOT NULL,
    serial_number       varchar(255) NOT NULL,
    sha256_fingerprint  varchar(128),
    spiffe_id           varchar(512) NOT NULL,
    cert_pem            text NOT NULL,
    ca_chain            jsonb DEFAULT '[]'::jsonb NOT NULL,
    issued_at           timestamptz DEFAULT now() NOT NULL,
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,
    status              varchar(50) DEFAULT 'active' NOT NULL,
    issue_type          varchar(50) NOT NULL,
    created_at          timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_certificates_pkey PRIMARY KEY (id),
    CONSTRAINT uq_spire_certificates_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT uq_spire_certificates_workspace_serial UNIQUE (workspace_id, serial_number),
    CONSTRAINT fk_spire_certificates_workload FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.spire_attested_workloads (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_spire_certificates_workspace_workload
    ON public.spire_certificates (workspace_id, workload_id, status);

CREATE TABLE IF NOT EXISTS public.spire_attestation_policies (
    id                uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id      uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    name              varchar(255) NOT NULL,
    description       text,
    attestation_type  varchar(50) NOT NULL,
    selector_rules    jsonb DEFAULT '{}'::jsonb NOT NULL,
    vault_role        varchar(255) NOT NULL,
    ttl               integer DEFAULT 3600 NOT NULL,
    priority          integer DEFAULT 0 NOT NULL,
    enabled           boolean DEFAULT true NOT NULL,
    created_at        timestamptz DEFAULT now() NOT NULL,
    updated_at        timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_attestation_policies_pkey PRIMARY KEY (id),
    CONSTRAINT uq_spire_attestation_policies_workspace_id UNIQUE (workspace_id, id),
    CONSTRAINT uq_spire_attestation_policies_workspace_name UNIQUE (workspace_id, name)
);
CREATE INDEX IF NOT EXISTS idx_spire_attestation_policies_workspace_type
    ON public.spire_attestation_policies (workspace_id, attestation_type);

CREATE TABLE IF NOT EXISTS public.spire_icp_audit_logs (
    id              uuid DEFAULT gen_random_uuid() NOT NULL,
    workspace_id    uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    event_type      varchar(50) NOT NULL,
    workload_id     varchar(255),
    certificate_id  varchar(255),
    spiffe_id       varchar(512),
    success         boolean NOT NULL,
    error_message   text,
    metadata        jsonb,
    ip_address      varchar(64),
    user_agent      text,
    created_at      timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT spire_icp_audit_logs_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_spire_icp_audit_logs_workspace_created
    ON public.spire_icp_audit_logs (workspace_id, created_at DESC);

-- Audit rows are not rewritten (DELETE stays for retention and workspace
-- deletion, as for audit_events in 108).
CREATE OR REPLACE FUNCTION public.spire_icp_audit_logs_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'spire_icp_audit_logs rows are append-only';
END;
$$;
DROP TRIGGER IF EXISTS trg_spire_icp_audit_logs_immutable ON public.spire_icp_audit_logs;
CREATE TRIGGER trg_spire_icp_audit_logs_immutable
    BEFORE UPDATE ON public.spire_icp_audit_logs
    FOR EACH ROW EXECUTE FUNCTION public.spire_icp_audit_logs_immutable();

SELECT public.tenancy_enable_rls('public.spire_agents');
SELECT public.tenancy_enable_rls('public.spire_join_tokens');
SELECT public.tenancy_enable_rls('public.spire_workload_entries');
SELECT public.tenancy_enable_rls('public.spire_workload_svids');
SELECT public.tenancy_enable_rls('public.spire_attested_workloads');
SELECT public.tenancy_enable_rls('public.spire_certificates');
SELECT public.tenancy_enable_rls('public.spire_attestation_policies');
SELECT public.tenancy_enable_rls('public.spire_icp_audit_logs');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authsec_tenant') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            public.spire_agents, public.spire_join_tokens,
            public.spire_workload_entries, public.spire_workload_svids,
            public.spire_attested_workloads, public.spire_certificates,
            public.spire_attestation_policies, public.spire_icp_audit_logs
        TO authsec_tenant;
    END IF;
END $$;

-- spire_policies.name: unique per workspace (expand, then drop the global one).
CREATE UNIQUE INDEX IF NOT EXISTS uq_spire_policies_workspace_name
    ON public.spire_policies (workspace_id, name);
DROP INDEX IF EXISTS public.idx_spire_policies_name;
