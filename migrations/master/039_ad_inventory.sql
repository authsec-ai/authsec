-- ============================================================================
-- 039: AD directory inventory (scopes, cursors, runs)
--
-- Stores administrator-approved base DNs and the status of each scoped read.
-- Sanitized objects are evidence on the existing iga_* tables (provider "ad",
-- observation mode "observed"). This migration does not depend on 038 and does
-- not project iga_identity_accounts: canonical projection for provider ad
-- waits for the TRD2 M3 vocabulary.
--
-- A uSNChanged cursor is per scope. It is not advanced after a partial read,
-- and a DirSync configuration does not store a cookie — the next run is a
-- full scoped read. Deletions are not inferred from an incremental cursor.
-- ============================================================================

ALTER TABLE public.sync_configurations
    ADD COLUMN IF NOT EXISTS ad_ca_bundle text,
    ADD COLUMN IF NOT EXISTS ad_page_size integer NOT NULL DEFAULT 500,
    ADD COLUMN IF NOT EXISTS ad_change_tracking boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS ad_start_tls boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS ad_tracking_mode text NOT NULL DEFAULT 'usn';

CREATE TABLE IF NOT EXISTS public.ad_inventory_scopes (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    sync_config_id       uuid NOT NULL,
    integration_scope_id uuid,
    base_dn              text NOT NULL,
    object_classes       jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled              boolean NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ad_inventory_scopes_pkey PRIMARY KEY (id),
    CONSTRAINT ad_inventory_scopes_config_fkey
        FOREIGN KEY (sync_config_id) REFERENCES public.sync_configurations (id) ON DELETE CASCADE,
    CONSTRAINT ad_inventory_scopes_workspace_dn UNIQUE (workspace_id, sync_config_id, base_dn)
);

CREATE INDEX IF NOT EXISTS idx_ad_inventory_scopes_workspace
    ON public.ad_inventory_scopes (workspace_id, sync_config_id);

-- integration_scope_id points at iga_integration_scopes but is not a foreign
-- key: migration 018 left that column nullable without a constraint, and a
-- scope row can exist before the evidence integration is created.

CREATE TABLE IF NOT EXISTS public.ad_inventory_cursors (
    workspace_id  uuid NOT NULL,
    scope_id      uuid NOT NULL,
    invocation_id text NOT NULL DEFAULT '',
    highest_usn   bigint NOT NULL DEFAULT 0,
    tracking_mode text NOT NULL DEFAULT 'usn',
    dirsync_valid boolean NOT NULL DEFAULT false,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ad_inventory_cursors_pkey PRIMARY KEY (workspace_id, scope_id),
    CONSTRAINT ad_inventory_cursors_scope_fkey
        FOREIGN KEY (scope_id) REFERENCES public.ad_inventory_scopes (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.ad_inventory_runs (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    sync_config_id  uuid NOT NULL,
    integration_id  uuid,
    scan_run_id     uuid,
    status          text NOT NULL,
    mode            text NOT NULL,
    started_at      timestamptz,
    completed_at    timestamptz,
    requested_by    text NOT NULL DEFAULT '',
    coverage        jsonb NOT NULL DEFAULT '[]'::jsonb,
    error_text      text NOT NULL DEFAULT '',
    objects_seen    integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ad_inventory_runs_pkey PRIMARY KEY (id),
    CONSTRAINT ad_inventory_runs_config_fkey
        FOREIGN KEY (sync_config_id) REFERENCES public.sync_configurations (id) ON DELETE CASCADE,
    CONSTRAINT ad_inventory_runs_status_chk CHECK (
        status IN ('pending', 'running', 'succeeded', 'partial', 'failed')),
    CONSTRAINT ad_inventory_runs_mode_chk CHECK (mode IN ('full', 'incremental')),
    -- Nullable composite pointers. MATCH SIMPLE skips the check while the
    -- pointer is null (the run row is inserted before the evidence rows exist).
    -- ON DELETE SET NULL clears only the pointer, not workspace_id.
    CONSTRAINT ad_inventory_runs_integration_fkey
        FOREIGN KEY (workspace_id, integration_id)
        REFERENCES public.iga_integrations (workspace_id, id)
        ON DELETE SET NULL (integration_id),
    CONSTRAINT ad_inventory_runs_scan_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.iga_scan_runs (workspace_id, id)
        ON DELETE SET NULL (scan_run_id)
);

CREATE INDEX IF NOT EXISTS idx_ad_inventory_runs_workspace
    ON public.ad_inventory_runs (workspace_id, sync_config_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.ad_directory_instances (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    sync_config_id uuid NOT NULL,
    forest_id      text NOT NULL,
    domain_sid     text NOT NULL DEFAULT '',
    domain_dn      text NOT NULL DEFAULT '',
    dns_host_name  text NOT NULL DEFAULT '',
    invocation_id  text NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ad_directory_instances_pkey PRIMARY KEY (id),
    CONSTRAINT ad_directory_instances_config_fkey
        FOREIGN KEY (sync_config_id) REFERENCES public.sync_configurations (id) ON DELETE CASCADE,
    CONSTRAINT ad_directory_instances_workspace_cfg UNIQUE (workspace_id, sync_config_id)
);

COMMENT ON TABLE public.ad_inventory_scopes IS
    'Administrator-approved AD base DNs. Objects are evidence, not iga_identity_accounts.';
COMMENT ON TABLE public.ad_inventory_cursors IS
    'Per-scope uSNChanged cursor. dirsync_valid stays false: DirSync cookies are not stored.';
COMMENT ON COLUMN public.sync_configurations.ad_ca_bundle IS
    'PEM trust anchor for LDAPS or StartTLS. Empty uses the system pool.';

-- Evidence basis "observed" is an authoritative directory read. It is not
-- platform_declared, so it cannot auto-confirm an agent.
DO $$
BEGIN
    ALTER TABLE public.iga_observations DROP CONSTRAINT IF EXISTS iga_observations_mode_chk;
    ALTER TABLE public.iga_observations ADD CONSTRAINT iga_observations_mode_chk CHECK (mode IN (
        'platform_declared',
        'deployment_declared',
        'invocation_declared',
        'framework_dependency',
        'tool_configuration',
        'secret_reference',
        'identity_grant',
        'audit_event',
        'observed'));
END
$$;
