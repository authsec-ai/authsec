-- 230_agent_remediation.sql
--
-- Remediation (SPEC-secops-backend-upgrade.md W8, P5, C11; decision 2).
--
-- 1. cloud_remediation_binding: the customer-consented REMEDIATION role of
--    one connected account (authsec-aws-remediation-role.yaml; the Azure
--    custom role and the Kubernetes ClusterRole are documented under
--    deploy/remediation). Separate from discovery and enforcement: its own
--    template, its own ExternalId (Vault, auth_ref), its own state. A
--    workspace starts with none; without a verified binding every
--    remediation is a prepared change (or an IaC pull request), never a
--    write. One live binding per connector.
-- 2. agent_remediation: one remediation of one target (remove a grant,
--    rotate a secret, an IAM key or a provider key, retire an agent, revert
--    a policy from a snapshot): its mode (write | prepared | iac_pr), the
--    collateral shown when it was requested, the prepared change, who
--    requested and who approved it, its proof (the change event AND a read
--    of the end state) and, for IaC, its pull request.
-- 3. agent_remediation_step: one change per row, in order, written BEFORE
--    the write with the exact before-state (so a revert can restore it), the
--    intended after-state and the readback.
--
-- connector_id and the target ids are deliberately not foreign keys on
-- agent_remediation: a remediation is a record that outlives the role, the
-- secret or the account it acted on.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.cloud_remediation_binding (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    connector_id     uuid        NOT NULL,
    provider         text        NOT NULL DEFAULT 'aws' CHECK (provider IN ('aws', 'azure', 'k8s')),
    -- The AWS account id, the Azure subscription id or the cluster id.
    account_ref      text        NOT NULL CHECK (btrim(account_ref) <> '' AND length(account_ref) <= 256),
    role_arn         text        NOT NULL DEFAULT '' CHECK (length(role_arn) <= 2048),
    -- Vault path of the remediation ExternalId; never the value.
    auth_ref         text        NOT NULL DEFAULT '' CHECK (length(auth_ref) <= 512),
    template_version text        NOT NULL DEFAULT '' CHECK (length(template_version) <= 64),
    state            text        NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'verified', 'error', 'revoked')),
    last_error       text        NOT NULL DEFAULT '' CHECK (length(last_error) <= 2000),
    consented_by     uuid        NOT NULL,
    verified_at      timestamptz,
    revoked_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_remediation_binding_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT cloud_remediation_binding_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_remediation_binding_verified_chk CHECK (state <> 'verified' OR (verified_at IS NOT NULL AND role_arn <> '')),
    CONSTRAINT cloud_remediation_binding_revoked_chk CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_remediation_binding_live
    ON public.cloud_remediation_binding (workspace_id, connector_id) WHERE state <> 'revoked';
CREATE INDEX IF NOT EXISTS idx_cloud_remediation_binding_ws
    ON public.cloud_remediation_binding (workspace_id, state);

CREATE TABLE IF NOT EXISTS public.agent_remediation (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    kind             text        NOT NULL CHECK (kind IN ('remove_grant', 'rotate_secret', 'rotate_iam_key',
                                                          'rotate_provider_key', 'retire_agent', 'revert_snapshot')),
    -- The target: its provider, what it is and its ARN or id, as requested.
    target_provider  text        NOT NULL CHECK (target_provider IN ('aws', 'azure', 'k8s', 'model_provider', 'authsec')),
    target_kind      text        NOT NULL CHECK (target_kind ~ '^[a-z_]{1,64}$'),
    target_ref       text        NOT NULL CHECK (btrim(target_ref) <> '' AND length(target_ref) <= 2048),
    -- The request's own details (policy ARN, inline name, statement sid,
    -- key id, handover secret, snapshot stable id and date, ...). Never a
    -- secret value.
    target_detail    jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(target_detail) = 'object'),
    connector_id     uuid,
    agent_id         uuid,
    case_id          uuid,
    state            text        NOT NULL DEFAULT 'draft'
                     CHECK (state IN ('draft', 'prepared', 'awaiting_approval', 'applying', 'applied', 'proven',
                                      'failed', 'pr_open', 'pr_merged', 'pr_closed', 'cancelled')),
    state_reason     text        NOT NULL DEFAULT '' CHECK (length(state_reason) <= 2000),
    mode             text        NOT NULL CHECK (mode IN ('write', 'prepared', 'iac_pr')),
    -- Why this mode (no remediation role, managed by CloudFormation stack X,
    -- the provider cannot create keys, ...).
    mode_reason      text        NOT NULL DEFAULT '' CHECK (length(mode_reason) <= 2000),
    reason           text        NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 2000),
    requested_by     uuid        NOT NULL,
    approved_by      uuid,
    pending_change_id uuid,
    break_glass      boolean     NOT NULL DEFAULT false,
    collateral       jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(collateral) = 'object'),
    -- The exact change (API calls, JSON documents, CLI commands) for a
    -- person or a pipeline to run; kept in every mode.
    prepared         jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(prepared) = 'object'),
    -- IaC detection (CloudFormation stack, Terraform hints) of the target.
    iac              jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(iac) = 'object'),
    proof            jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(proof) = 'object'),
    error            text        NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    -- RoleSessionName of the remediation session (write mode): what the
    -- change event's caller must name.
    session_name     text        NOT NULL DEFAULT '' CHECK (length(session_name) <= 64),
    plan_hash        text        NOT NULL DEFAULT '' CHECK (plan_hash = '' OR plan_hash ~ '^[0-9a-f]{64}$'),
    -- Pull request (mode iac_pr).
    iac_source_id    uuid,
    pr_number        integer,
    pr_url           text        NOT NULL DEFAULT '' CHECK (length(pr_url) <= 2048),
    pr_branch        text        NOT NULL DEFAULT '' CHECK (length(pr_branch) <= 256),
    pr_state         text        NOT NULL DEFAULT '' CHECK (pr_state IN ('', 'open', 'merged', 'closed')),
    pr_count         integer     NOT NULL DEFAULT 0 CHECK (pr_count >= 0),
    -- Every ask raised for this remediation (code owners, a provider
    -- console step), as the ask creator returned its references.
    asks             jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(asks) = 'array'),
    apply_requested_at timestamptz,
    applied_at       timestamptz,
    proven_at        timestamptz,
    cancelled_at     timestamptz,
    cancelled_by     uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_remediation_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_remediation_proven_chk CHECK ((state = 'proven') = (proven_at IS NOT NULL)),
    CONSTRAINT agent_remediation_cancelled_chk CHECK ((state = 'cancelled') = (cancelled_at IS NOT NULL)),
    CONSTRAINT agent_remediation_second_person_chk CHECK (approved_by IS NULL OR approved_by <> requested_by),
    CONSTRAINT agent_remediation_pr_chk CHECK ((pr_state = '') = (pr_number IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_agent_remediation_ws_state
    ON public.agent_remediation (workspace_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_remediation_ws_case
    ON public.agent_remediation (workspace_id, case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_remediation_ws_target
    ON public.agent_remediation (workspace_id, target_ref);
-- One open remediation of a kind per target.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_remediation_open
    ON public.agent_remediation (workspace_id, kind, target_ref)
    WHERE state IN ('draft', 'prepared', 'awaiting_approval', 'applying', 'pr_open', 'pr_closed');
-- The worker's sweep: deferred steps due, pull requests to sync.
CREATE INDEX IF NOT EXISTS idx_agent_remediation_open
    ON public.agent_remediation (state) WHERE state IN ('applying', 'applied', 'pr_open', 'pr_merged');

CREATE TABLE IF NOT EXISTS public.agent_remediation_step (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    remediation_id uuid        NOT NULL,
    seq            integer     NOT NULL CHECK (seq > 0),
    op             text        NOT NULL CHECK (op ~ '^[a-z_]{1,64}$'),
    target         text        NOT NULL CHECK (btrim(target) <> '' AND length(target) <= 2048),
    -- The provider call (CloudTrail eventSource / eventName) whose record
    -- proves the write; '' for a step AuthSec records itself.
    event_source   text        NOT NULL DEFAULT '' CHECK (length(event_source) <= 256),
    event_name     text        NOT NULL DEFAULT '' CHECK (length(event_name) <= 256),
    before         jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(before) = 'object'),
    after          jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(after) = 'object'),
    readback       jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(readback) = 'object'),
    state          text        NOT NULL DEFAULT 'pending'
                   CHECK (state IN ('pending', 'waiting', 'applied', 'skipped', 'failed', 'asked')),
    error          text        NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    -- A deferred step (deactivate the old key after its grace) is due then.
    due_at         timestamptz,
    applied_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_remediation_step_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_remediation_step_seq_key UNIQUE (workspace_id, remediation_id, seq),
    CONSTRAINT agent_remediation_step_remediation_fkey FOREIGN KEY (workspace_id, remediation_id)
        REFERENCES public.agent_remediation (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_remediation_step_due
    ON public.agent_remediation_step (due_at) WHERE state = 'waiting';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.cloud_remediation_binding');
        PERFORM public.tenancy_enable_rls('public.agent_remediation');
        PERFORM public.tenancy_enable_rls('public.agent_remediation_step');
    END IF;
END $$;
