-- 051_identity_binding.sql
-- Identity Model Extensions (Batch 5): machine identity bindings and
-- execution-scoped identity bindings.
--
-- Additive and re-runnable. No transaction wrapper — each DDL statement is
-- its own implicit transaction in PostgreSQL.

-- Machine identity bindings link agents to their identity mode (SPIFFE or
-- enrolled_mtls) and track the lifecycle from reservation through attestation
-- to enrollment verification.
CREATE TABLE IF NOT EXISTS public.machine_identity_bindings (
    id                      uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id            uuid NOT NULL,
    agent_id                uuid NOT NULL,
    workload_id             uuid,
    identity_mode           text NOT NULL DEFAULT 'spiffe',
    primary_spiffe_id       text,
    verified_principal_id   text,
    binding_generation      integer NOT NULL DEFAULT 1,
    state                   text NOT NULL DEFAULT 'reserved',
    assurance               text NOT NULL DEFAULT 'attestation_pending',
    cert_serial             text,
    key_identifier          text,
    public_key_hash         text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT machine_identity_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT machine_identity_bindings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

-- Index for workspace-scoped queries.
CREATE INDEX IF NOT EXISTS machine_identity_bindings_ws_idx
    ON public.machine_identity_bindings (workspace_id);

-- Index for agent lookups within a workspace.
CREATE INDEX IF NOT EXISTS machine_identity_bindings_ws_agent_idx
    ON public.machine_identity_bindings (workspace_id, agent_id);

-- Index for SPIFFE URI resolution.
CREATE INDEX IF NOT EXISTS machine_identity_bindings_spiffe_idx
    ON public.machine_identity_bindings (primary_spiffe_id)
    WHERE primary_spiffe_id IS NOT NULL;

-- Index for enrolled_mtls cert serial resolution.
CREATE INDEX IF NOT EXISTS machine_identity_bindings_cert_serial_idx
    ON public.machine_identity_bindings (cert_serial)
    WHERE cert_serial IS NOT NULL;

-- Partial unique: at most one non-terminal binding per agent per workspace per mode.
CREATE UNIQUE INDEX IF NOT EXISTS machine_identity_bindings_active_idx
    ON public.machine_identity_bindings (workspace_id, agent_id, identity_mode)
    WHERE state NOT IN ('disabled', 'revoked');


-- Execution identity bindings are per-execution scoped identities derived
-- from a parent machine identity binding.
CREATE TABLE IF NOT EXISTS public.execution_identity_bindings (
    id                      uuid NOT NULL DEFAULT gen_random_uuid(),
    parent_binding_id       uuid NOT NULL,
    workspace_id            uuid NOT NULL,
    execution_id            text NOT NULL,
    spiffe_uri              text,
    principal_uri           text,
    binding_generation      integer NOT NULL DEFAULT 1,
    state                   text NOT NULL DEFAULT 'reserved',
    issued_at               timestamptz,
    expires_at              timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT execution_identity_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT execution_identity_bindings_parent_fkey FOREIGN KEY (parent_binding_id)
        REFERENCES public.machine_identity_bindings (id) ON DELETE CASCADE,
    CONSTRAINT execution_identity_bindings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

-- Index for workspace-scoped queries.
CREATE INDEX IF NOT EXISTS execution_identity_bindings_ws_idx
    ON public.execution_identity_bindings (workspace_id);

-- Index for parent binding lookups.
CREATE INDEX IF NOT EXISTS execution_identity_bindings_parent_idx
    ON public.execution_identity_bindings (parent_binding_id);

-- Unique: one execution binding per parent + execution_id.
CREATE UNIQUE INDEX IF NOT EXISTS execution_identity_bindings_parent_exec_idx
    ON public.execution_identity_bindings (parent_binding_id, execution_id);


-- Add identity extension columns to application_spiffe_identities if not present.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'application_spiffe_identities'
          AND column_name = 'identity_mode'
    ) THEN
        ALTER TABLE public.application_spiffe_identities
            ADD COLUMN identity_mode text NOT NULL DEFAULT 'spiffe',
            ADD COLUMN execution_binding_id uuid,
            ADD COLUMN binding_generation integer NOT NULL DEFAULT 0,
            ADD COLUMN verified_principal_id text,
            ADD COLUMN enrollment_state text NOT NULL DEFAULT '',
            ADD COLUMN certificate_serial text,
            ADD COLUMN key_identifier text,
            ADD COLUMN public_key_hash text;
    END IF;
END $$;


-- Add identity extension columns to collector_instances if not present.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'collector_instances'
          AND column_name = 'identity_mode'
    ) THEN
        ALTER TABLE public.collector_instances
            ADD COLUMN identity_mode text NOT NULL DEFAULT 'spiffe',
            ADD COLUMN identity_binding_id uuid,
            ADD COLUMN verified_principal_id text NOT NULL DEFAULT '',
            ADD COLUMN certificate_profile text NOT NULL DEFAULT '';
    END IF;
END $$;
