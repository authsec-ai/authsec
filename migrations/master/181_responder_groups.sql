-- 181_responder_groups.sql
--
-- Responder groups (SPEC-secops-backend-upgrade.md decision 1, P10). An ask
-- about an agent goes to the responder group of its estate scope, and any
-- accepted member answers. Who decides for agent X:
--   1. the group holding a scope of kind 'agent' for X;
--   2. else the group holding one of X's estate scopes (cluster, account,
--      subscription, estate_scope -- in that order);
--   3. else the workspace's default group (is_default), created with every
--      workspace admin as a member.
--
-- A member is assigned as a candidate and becomes accepted when THEY accept;
-- a member may delegate to another person until an end date; a group hands
-- over all its scopes to another group in one step.
--
-- The 2026-10-13 no-ownership decision stands (owner gates stay off).
-- owner_user_id is nullable and unused: a named owner or sponsor can replace
-- the group later without a schema change.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.responder_group (
    id            uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid        NOT NULL,
    name          text        NOT NULL,
    description   text        NOT NULL DEFAULT '',
    is_default    boolean     NOT NULL DEFAULT false,
    owner_user_id uuid,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT responder_group_pkey PRIMARY KEY (id),
    CONSTRAINT responder_group_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT responder_group_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT responder_group_name_key UNIQUE (workspace_id, name),
    CONSTRAINT responder_group_name_chk CHECK (length(name) BETWEEN 1 AND 200)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_responder_group_default
    ON public.responder_group (workspace_id) WHERE is_default;

CREATE TABLE IF NOT EXISTS public.responder_group_member (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL,
    group_id        uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    role            text        NOT NULL DEFAULT 'member',
    state           text        NOT NULL DEFAULT 'candidate',
    assigned_by     uuid,
    assigned_at     timestamptz NOT NULL DEFAULT now(),
    accepted_at     timestamptz,
    delegated_to    uuid,
    delegated_until timestamptz,
    CONSTRAINT responder_group_member_pkey PRIMARY KEY (id),
    CONSTRAINT responder_group_member_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT responder_group_member_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT responder_group_member_group_fkey FOREIGN KEY (workspace_id, group_id)
        REFERENCES public.responder_group (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT responder_group_member_user_fkey FOREIGN KEY (user_id)
        REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT responder_group_member_key UNIQUE (workspace_id, group_id, user_id),
    CONSTRAINT responder_group_member_role_chk CHECK (role IN ('member', 'lead')),
    CONSTRAINT responder_group_member_state_chk CHECK (state IN ('candidate', 'accepted')),
    CONSTRAINT responder_group_member_accepted_chk CHECK ((state = 'accepted') = (accepted_at IS NOT NULL)),
    CONSTRAINT responder_group_member_delegation_chk CHECK ((delegated_to IS NULL) = (delegated_until IS NULL)),
    CONSTRAINT responder_group_member_delegate_self_chk CHECK (delegated_to IS NULL OR delegated_to <> user_id)
);
CREATE INDEX IF NOT EXISTS idx_responder_group_member_user
    ON public.responder_group_member (workspace_id, user_id);

CREATE TABLE IF NOT EXISTS public.responder_group_scope (
    id           uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL,
    group_id     uuid        NOT NULL,
    scope_kind   text        NOT NULL,
    -- The account id, subscription id, cluster's discovery source id, agent
    -- id or iga_estate_scopes id, as text.
    scope_ref    text        NOT NULL,
    created_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT responder_group_scope_pkey PRIMARY KEY (id),
    CONSTRAINT responder_group_scope_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT responder_group_scope_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT responder_group_scope_group_fkey FOREIGN KEY (workspace_id, group_id)
        REFERENCES public.responder_group (workspace_id, id) ON DELETE CASCADE,
    -- One group decides for a scope.
    CONSTRAINT responder_group_scope_key UNIQUE (workspace_id, scope_kind, scope_ref),
    CONSTRAINT responder_group_scope_kind_chk CHECK (scope_kind IN
        ('account', 'subscription', 'cluster', 'agent', 'estate_scope')),
    CONSTRAINT responder_group_scope_ref_chk CHECK (scope_ref <> '')
);
CREATE INDEX IF NOT EXISTS idx_responder_group_scope_group
    ON public.responder_group_scope (workspace_id, group_id);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.responder_group');
        PERFORM public.tenancy_enable_rls('public.responder_group_member');
        PERFORM public.tenancy_enable_rls('public.responder_group_scope');
    END IF;
END $$;
