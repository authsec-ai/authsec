-- 043_trd2_runtime_policy.sql — TRD 2 M5 runtime policy lifecycle (WP-A6).
--
-- Additive and re-runnable. No transaction wrapper: the runner and CI apply
-- this file with psql -1. Nothing here uses CREATE INDEX CONCURRENTLY.
-- 044, 046 and 047 are not required and are not referenced. 043 applies on a
-- database that already has 045 (the runner tracks version plus name) and on
-- a fresh bootstrap, where numeric order places 043 before 045.
--
-- Every foreign key is composite (workspace_id, col) except the anchor to
-- workspaces(id). Parents already have UNIQUE(workspace_id, id):
-- workspaces, iga_workload, iga_runtime_instances, collector_instances, and
-- the new tables in this file.
--
-- Bare user uuids, same treatment as iga_workload_classification.decided_by_user_id.
-- users is not an iga_* or cloud_* table, and the B9 bare-uuid catalog only
-- scans those prefixes, so these columns are not listed in bfkNoForeignKey
-- (adding them would fail the "no longer a bare uuid" check):
--   runtime_policies.owner_user_id
--   runtime_policy_revisions.author_user_id
--   runtime_policy_approvals.actor_user_id
--   runtime_policy_publications.author_user_id
--   runtime_policy_audit.actor_user_id
-- The candidate-generator system actor is a well-known id in Go, not a users row.
--
-- runtime_policy_settings is the workspace setting §13.1 names and §21.4 does
-- not give a table: second approver, and the configured broker paths a
-- require_approval rule may name. It is not a policy document.
--
-- These are all new, empty tables. Checks and foreign keys are valid
-- immediately. Nothing is NOT VALID. scripts/validate-043-runtime-policy.sql
-- only asserts that, and is re-runnable outside the deploy transaction.
--
-- Workspace deletion. A direct UPDATE or DELETE of a receipt or audit row,
-- and a direct DELETE of a non-draft revision, raises 55000 while the
-- workspace row is still visible. DELETE FROM workspaces removes that row
-- first; the BEFORE DELETE triggers then see it is gone and allow the
-- cascade. Receipt and audit foreign keys along that path are ON DELETE
-- CASCADE (policy, publication, target). They are not RESTRICT: RESTRICT
-- fired before the cascade could delete the child, so one created policy
-- made the workspace undeletable. Target foreign keys to workload, runtime
-- instance and collector are CASCADE for the same reason: those parents are
-- removed on their own cascade from the workspace while a target still
-- points at them. The publication self-reference is ON DELETE SET NULL.
-- A direct delete of a receipt, an audit row, or a non-draft revision, with
-- the workspace still present, is still rejected.
--
-- Lock and runtime. No existing table is altered, so there is no ACCESS
-- EXCLUSIVE on a populated relation and no VALIDATE step inside this file.
--
--   Statement                         Lock                         Notes
--   CREATE TABLE / INDEX              SHARE on the new table       empty
--   CREATE TRIGGER                    SHARE ROW EXCLUSIVE          new, empty
--   VALIDATE CONSTRAINT               not in this file             nothing pending
--
-- Down: forward-only. Rollback is IGA_V2_POLICY off. The tables stay.

CREATE TABLE IF NOT EXISTS public.runtime_policy_settings (
    workspace_id uuid NOT NULL,
    second_approver_required boolean NOT NULL DEFAULT false,
    configured_brokers jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policy_settings_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT runtime_policy_settings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.runtime_policies (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    name text NOT NULL,
    owner_user_id uuid NOT NULL,
    current_draft_revision integer NOT NULL DEFAULT 0,
    lifecycle text NOT NULL DEFAULT 'draft',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policies_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policies_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policies_name_key UNIQUE (workspace_id, name),
    CONSTRAINT runtime_policies_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT runtime_policies_name_chk CHECK (name <> ''),
    CONSTRAINT runtime_policies_lifecycle_chk CHECK (
        lifecycle IN ('draft', 'validated', 'simulated', 'approved', 'published', 'superseded', 'revoked')),
    CONSTRAINT runtime_policies_draft_chk CHECK (current_draft_revision >= 0)
);

CREATE TABLE IF NOT EXISTS public.runtime_policy_revisions (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision integer NOT NULL,
    document jsonb NOT NULL,
    content_hash text NOT NULL,
    author_user_id uuid NOT NULL,
    state text NOT NULL,
    graph_revision bigint NOT NULL DEFAULT 0,
    compiler_format text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policy_revisions_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_revisions_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_revisions_policy_rev_key UNIQUE (policy_id, revision),
    CONSTRAINT runtime_policy_revisions_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.runtime_policies (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_revisions_state_chk CHECK (
        state IN ('draft', 'validated', 'simulated', 'approved', 'published', 'superseded', 'revoked')),
    CONSTRAINT runtime_policy_revisions_hash_chk CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT runtime_policy_revisions_format_chk CHECK (compiler_format = 'authsec.runtime.v1'),
    CONSTRAINT runtime_policy_revisions_rev_chk CHECK (revision >= 1)
);

CREATE INDEX IF NOT EXISTS idx_runtime_policy_revisions_policy
    ON public.runtime_policy_revisions (workspace_id, policy_id, revision);

CREATE TABLE IF NOT EXISTS public.runtime_policy_simulations (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision integer NOT NULL,
    revision_hash text NOT NULL,
    graph_revision bigint NOT NULL,
    event_window jsonb NOT NULL DEFAULT '{}'::jsonb,
    target_digest text NOT NULL,
    input_coverage jsonb NOT NULL DEFAULT '{}'::jsonb,
    result_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    artifact_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policy_simulations_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_simulations_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_simulations_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.runtime_policies (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_simulations_hash_chk CHECK (revision_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT runtime_policy_simulations_digest_chk CHECK (target_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS public.runtime_policy_approvals (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision integer NOT NULL,
    revision_hash text NOT NULL,
    simulation_id uuid NOT NULL,
    target_digest text NOT NULL,
    actor_user_id uuid NOT NULL,
    mfa_context jsonb NOT NULL DEFAULT '{}'::jsonb,
    reason text NOT NULL,
    expires_at timestamptz,
    invalidated_at timestamptz,
    invalidated_reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policy_approvals_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_approvals_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_approvals_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.runtime_policies (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_approvals_simulation_fkey FOREIGN KEY (workspace_id, simulation_id)
        REFERENCES public.runtime_policy_simulations (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_approvals_hash_chk CHECK (revision_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT runtime_policy_approvals_digest_chk CHECK (target_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT runtime_policy_approvals_reason_chk CHECK (reason <> '')
);

CREATE INDEX IF NOT EXISTS idx_runtime_policy_approvals_policy
    ON public.runtime_policy_approvals (workspace_id, policy_id, revision);

CREATE TABLE IF NOT EXISTS public.runtime_policy_publications (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision integer NOT NULL,
    revision_hash text NOT NULL,
    rollout_plan jsonb NOT NULL DEFAULT '{}'::jsonb,
    signed_manifest_hash text NOT NULL DEFAULT '',
    author_user_id uuid NOT NULL,
    superseded_publication_id uuid,
    revocation_epoch bigint NOT NULL DEFAULT 0,
    mode text NOT NULL DEFAULT 'observe',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policy_publications_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_publications_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_publications_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.runtime_policies (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_publications_superseded_fkey FOREIGN KEY (workspace_id, superseded_publication_id)
        REFERENCES public.runtime_policy_publications (workspace_id, id) ON DELETE SET NULL,
    CONSTRAINT runtime_policy_publications_hash_chk CHECK (revision_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT runtime_policy_publications_mode_chk CHECK (mode IN ('observe', 'enforce'))
);

CREATE TABLE IF NOT EXISTS public.runtime_policy_targets (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    runtime_instance_id uuid,
    collector_id uuid NOT NULL,
    desired_delivery_revision bigint NOT NULL,
    capability_digest text NOT NULL DEFAULT '',
    required_controls jsonb NOT NULL DEFAULT '[]'::jsonb,
    CONSTRAINT runtime_policy_targets_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_targets_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_targets_publication_fkey FOREIGN KEY (workspace_id, publication_id)
        REFERENCES public.runtime_policy_publications (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_targets_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_targets_runtime_fkey FOREIGN KEY (workspace_id, workload_id, runtime_instance_id)
        REFERENCES public.iga_runtime_instances (workspace_id, workload_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_targets_collector_fkey FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_targets_delivery_chk CHECK (desired_delivery_revision >= 1),
    CONSTRAINT runtime_policy_targets_digest_chk CHECK (
        capability_digest = '' OR capability_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS public.runtime_policy_receipts (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    target_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    delivery_revision bigint NOT NULL,
    runtime_generation text NOT NULL DEFAULT '',
    control_status jsonb NOT NULL DEFAULT '[]'::jsonb,
    artifact_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
    error text NOT NULL DEFAULT '',
    observed_at timestamptz NOT NULL DEFAULT now(),
    graph_revision bigint NOT NULL DEFAULT 0,
    CONSTRAINT runtime_policy_receipts_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_receipts_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_receipts_target_fkey FOREIGN KEY (workspace_id, target_id)
        REFERENCES public.runtime_policy_targets (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_receipts_publication_fkey FOREIGN KEY (workspace_id, publication_id)
        REFERENCES public.runtime_policy_publications (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_receipts_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.runtime_policies (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.runtime_policy_audit (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id uuid,
    actor_user_id uuid NOT NULL,
    action text NOT NULL,
    reason text NOT NULL DEFAULT '',
    request_hash text NOT NULL DEFAULT '',
    affected_targets jsonb NOT NULL DEFAULT '[]'::jsonb,
    before_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    after_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT runtime_policy_audit_pkey PRIMARY KEY (id),
    CONSTRAINT runtime_policy_audit_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT runtime_policy_audit_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_audit_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.runtime_policies (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT runtime_policy_audit_action_chk CHECK (action <> '')
);

CREATE INDEX IF NOT EXISTS idx_runtime_policy_audit_policy
    ON public.runtime_policy_audit (workspace_id, policy_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.collector_capability_reports (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    capability_digest text NOT NULL,
    report jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_capability_reports_pkey PRIMARY KEY (id),
    CONSTRAINT collector_capability_reports_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT collector_capability_reports_digest_key UNIQUE (workspace_id, collector_id, capability_digest),
    CONSTRAINT collector_capability_reports_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT collector_capability_reports_collector_fkey FOREIGN KEY (workspace_id, collector_id)
        REFERENCES public.collector_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT collector_capability_reports_digest_chk CHECK (capability_digest ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE public.runtime_policy_revisions IS
    'Identity columns never change. document and content_hash change only while state stays draft. state moves only along draft, validated, simulated, approved, published, then superseded or revoked. A direct delete is rejected; a workspace cascade is allowed once the workspace row is gone.';
COMMENT ON TABLE public.runtime_policy_approvals IS
    'Invalidated in place when the revision content changes. Never deleted to hide an approval.';
COMMENT ON TABLE public.runtime_policy_receipts IS
    'Append-only. A later policy revision must not rewrite a receipt.';
COMMENT ON TABLE public.collector_capability_reports IS
    'One row per collector capability digest observed on agent sync. Evidence, not a policy decision.';

-- True once DELETE FROM workspaces has removed the owning row. The cascade
-- then reaches these tables. A direct delete still sees the workspace.
CREATE OR REPLACE FUNCTION public.runtime_policy_workspace_gone(ws uuid)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
    RETURN NOT EXISTS (SELECT 1 FROM public.workspaces WHERE id = ws);
END;
$$;

CREATE OR REPLACE FUNCTION public.runtime_policy_revisions_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF public.runtime_policy_workspace_gone(OLD.workspace_id) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'runtime policy revisions cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
       OR NEW.revision IS DISTINCT FROM OLD.revision
       OR NEW.author_user_id IS DISTINCT FROM OLD.author_user_id
       OR NEW.compiler_format IS DISTINCT FROM OLD.compiler_format THEN
        RAISE EXCEPTION 'runtime policy revision identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT (
            (OLD.state = 'draft' AND NEW.state = 'validated')
            OR (OLD.state = 'validated' AND NEW.state = 'simulated')
            OR (OLD.state = 'simulated' AND NEW.state = 'approved')
            OR (OLD.state = 'approved' AND NEW.state = 'published')
            OR (OLD.state = 'published' AND NEW.state = 'superseded')
            OR (OLD.state = 'published' AND NEW.state = 'revoked')
        ) THEN
            RAISE EXCEPTION 'runtime policy revision cannot move from % to %', OLD.state, NEW.state
                USING ERRCODE = '55000';
        END IF;
    END IF;
    IF NEW.document IS DISTINCT FROM OLD.document
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash THEN
        IF OLD.state <> 'draft' OR NEW.state <> 'draft' THEN
            RAISE EXCEPTION 'runtime policy revision document is immutable once state is %', OLD.state
                USING ERRCODE = '55000';
        END IF;
        UPDATE public.runtime_policy_approvals
           SET invalidated_at = now(),
               invalidated_reason = 'content_changed'
         WHERE workspace_id = OLD.workspace_id
           AND policy_id = OLD.policy_id
           AND revision = OLD.revision
           AND invalidated_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS runtime_policy_revisions_immutable_trg ON public.runtime_policy_revisions;
CREATE TRIGGER runtime_policy_revisions_immutable_trg
    BEFORE UPDATE OR DELETE ON public.runtime_policy_revisions
    FOR EACH ROW EXECUTE FUNCTION public.runtime_policy_revisions_immutable();

CREATE OR REPLACE FUNCTION public.runtime_policy_receipts_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND public.runtime_policy_workspace_gone(OLD.workspace_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'runtime policy receipts are append-only'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS runtime_policy_receipts_append_trg ON public.runtime_policy_receipts;
CREATE TRIGGER runtime_policy_receipts_append_trg
    BEFORE UPDATE OR DELETE ON public.runtime_policy_receipts
    FOR EACH ROW EXECUTE FUNCTION public.runtime_policy_receipts_append_only();

CREATE OR REPLACE FUNCTION public.runtime_policy_audit_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND public.runtime_policy_workspace_gone(OLD.workspace_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'runtime policy audit is append-only'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS runtime_policy_audit_append_trg ON public.runtime_policy_audit;
CREATE TRIGGER runtime_policy_audit_append_trg
    BEFORE UPDATE OR DELETE ON public.runtime_policy_audit
    FOR EACH ROW EXECUTE FUNCTION public.runtime_policy_audit_append_only();
