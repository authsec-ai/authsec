-- 180_directory_person.sql
--
-- The directory (SPEC-secops-backend-upgrade.md W7, C10). Who a person is in
-- the customer's directory: manager, whether they are active, on leave or
-- gone, whether they are a contractor. Filled from SCIM (core active and
-- userType, the enterprise extension's manager and employeeType) and from
-- Microsoft Entra where an Azure connector reads the directory (manager,
-- accountEnabled, employeeLeaveDateTime).
--
-- A person who leaves (status left) is the trigger W7 cares about: every
-- agent whose responder group they are the only accepted member of raises
-- agent.ask_needed (TODO(W4): an ask).
--
-- One row per (workspace, source, external_id). user_id links an AuthSec user
-- when the directory's person is one (SCIM-provisioned users are).
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.directory_person (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL,
    user_id             uuid,
    source              text        NOT NULL,
    external_id         text        NOT NULL,
    email               text        NOT NULL DEFAULT '',
    display_name        text        NOT NULL DEFAULT '',
    -- The manager as the directory names them (its id there), and the
    -- manager's own row once it is known.
    manager_external_id text        NOT NULL DEFAULT '',
    manager_person_id   uuid,
    status              text        NOT NULL DEFAULT 'active',
    contractor          boolean     NOT NULL DEFAULT false,
    employee_type       text        NOT NULL DEFAULT '',
    leave_from          timestamptz,
    leave_to            timestamptz,
    left_at             timestamptz,
    synced_at           timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT directory_person_pkey PRIMARY KEY (id),
    CONSTRAINT directory_person_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT directory_person_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT directory_person_user_fkey FOREIGN KEY (user_id)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT directory_person_manager_fkey FOREIGN KEY (workspace_id, manager_person_id)
        REFERENCES public.directory_person (workspace_id, id) ON DELETE SET NULL (manager_person_id),
    CONSTRAINT directory_person_external_key UNIQUE (workspace_id, source, external_id),
    CONSTRAINT directory_person_source_chk CHECK (source IN ('scim', 'entra', 'okta')),
    CONSTRAINT directory_person_external_chk CHECK (external_id <> ''),
    CONSTRAINT directory_person_status_chk CHECK (status IN ('active', 'leave', 'left')),
    CONSTRAINT directory_person_left_chk CHECK ((status = 'left') = (left_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_directory_person_user
    ON public.directory_person (workspace_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_directory_person_status
    ON public.directory_person (workspace_id, status, id);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.directory_person');
    END IF;
END $$;
