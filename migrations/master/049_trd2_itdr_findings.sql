-- 049_trd2_itdr_findings.sql — TRD 2 ITDR detections, findings, response
-- plans, escalation leases and alert deliveries (WP-A8).
--
-- Additive and re-runnable. No transaction wrapper: the runner and CI apply
-- this file with psql -1. Nothing here uses CREATE INDEX CONCURRENTLY.
--
-- Every foreign key is composite (workspace_id, col) except the anchor to
-- workspaces(id). Parents already have UNIQUE(workspace_id, id):
-- workspaces, iga_workload, iga_runtime_instances, iga_resources, and
-- runtime_policy_revisions.
--
-- Bare user uuids, same treatment as runtime_policies.owner_user_id:
--   itdr_response_plans.actor_id
--   itdr_response_plans.approved_by
--   itdr_escalation_leases.approver_id
--   itdr_escalation_leases.client_identity_id
--
-- These are all new, empty tables. Checks and foreign keys are valid
-- immediately. Nothing is NOT VALID.
--
-- Lock and runtime. No existing table is altered, so there is no ACCESS
-- EXCLUSIVE on a populated relation and no VALIDATE step inside this file.
--
-- Down: forward-only. Rollback is IGA_V2_ITDR off. The tables stay.

-- ────────────────────────────────────────────────────
-- Detection rules: the rule catalog evaluated by the ITDR engine.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_detection_rules (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    rule_key text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    severity text NOT NULL,
    confidence text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT itdr_detection_rules_pkey PRIMARY KEY (id),
    CONSTRAINT itdr_detection_rules_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT itdr_detection_rules_rule_key_key UNIQUE (workspace_id, rule_key),
    CONSTRAINT itdr_detection_rules_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT itdr_detection_rules_name_chk CHECK (name <> ''),
    CONSTRAINT itdr_detection_rules_rule_key_chk CHECK (rule_key <> ''),
    CONSTRAINT itdr_detection_rules_severity_chk CHECK (
        severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT itdr_detection_rules_confidence_chk CHECK (
        confidence IN ('low', 'medium', 'high')),
    CONSTRAINT itdr_detection_rules_version_chk CHECK (version >= 1)
);

-- ────────────────────────────────────────────────────
-- Findings: grouped detection events within a configurable window.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_findings (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    rule_version integer NOT NULL DEFAULT 1,
    severity text NOT NULL,
    confidence text NOT NULL,
    status text NOT NULL DEFAULT 'open',
    outcome text NOT NULL DEFAULT 'unknown',
    workload_id uuid,
    runtime_instance_id uuid,
    resource_id uuid,
    graph_revision bigint NOT NULL DEFAULT 0,
    observation_ids uuid[] NOT NULL DEFAULT '{}',
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    event_count integer NOT NULL DEFAULT 1,
    finding_window_seconds integer NOT NULL DEFAULT 3600,
    recommended_response text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT itdr_findings_pkey PRIMARY KEY (id),
    CONSTRAINT itdr_findings_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT itdr_findings_rule_fkey FOREIGN KEY (workspace_id, rule_id)
        REFERENCES public.itdr_detection_rules (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT itdr_findings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT itdr_findings_severity_chk CHECK (
        severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT itdr_findings_confidence_chk CHECK (
        confidence IN ('low', 'medium', 'high')),
    CONSTRAINT itdr_findings_status_chk CHECK (
        status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    CONSTRAINT itdr_findings_outcome_chk CHECK (
        outcome IN ('attempted', 'prevented', 'successful', 'unknown')),
    CONSTRAINT itdr_findings_event_count_chk CHECK (event_count >= 1),
    CONSTRAINT itdr_findings_window_chk CHECK (finding_window_seconds >= 1)
);

CREATE INDEX IF NOT EXISTS idx_itdr_findings_workspace_status
    ON public.itdr_findings (workspace_id, status, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_itdr_findings_rule
    ON public.itdr_findings (workspace_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_itdr_findings_workload
    ON public.itdr_findings (workspace_id, workload_id)
    WHERE workload_id IS NOT NULL;

-- ────────────────────────────────────────────────────
-- Finding ↔ identity join table.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_finding_identities (
    finding_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    identity_account_id uuid NOT NULL,
    CONSTRAINT itdr_finding_identities_pkey PRIMARY KEY (finding_id, identity_account_id),
    CONSTRAINT itdr_finding_identities_finding_fkey FOREIGN KEY (workspace_id, finding_id)
        REFERENCES public.itdr_findings (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT itdr_finding_identities_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_itdr_finding_identities_identity
    ON public.itdr_finding_identities (workspace_id, identity_account_id);

-- ────────────────────────────────────────────────────
-- Finding ↔ policy revision join table.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_finding_policy_revisions (
    finding_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    policy_revision_id uuid NOT NULL,
    CONSTRAINT itdr_finding_policy_revisions_pkey PRIMARY KEY (finding_id, policy_revision_id),
    CONSTRAINT itdr_finding_policy_revisions_finding_fkey FOREIGN KEY (workspace_id, finding_id)
        REFERENCES public.itdr_findings (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT itdr_finding_policy_revisions_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

-- ────────────────────────────────────────────────────
-- Response plans: immutable once approved.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_response_plans (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'requested',
    targets jsonb NOT NULL DEFAULT '[]'::jsonb,
    actions jsonb NOT NULL DEFAULT '[]'::jsonb,
    shared_use_impact text NOT NULL DEFAULT '',
    expiry timestamptz,
    rollback_behavior text NOT NULL DEFAULT '',
    actor_id uuid NOT NULL,
    approved_by uuid,
    approved_at timestamptz,
    reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT itdr_response_plans_pkey PRIMARY KEY (id),
    CONSTRAINT itdr_response_plans_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT itdr_response_plans_finding_fkey FOREIGN KEY (workspace_id, finding_id)
        REFERENCES public.itdr_findings (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT itdr_response_plans_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT itdr_response_plans_status_chk CHECK (
        status IN ('requested', 'approved', 'executing', 'verified', 'failed', 'refused'))
);

CREATE INDEX IF NOT EXISTS idx_itdr_response_plans_finding
    ON public.itdr_response_plans (workspace_id, finding_id);

-- ────────────────────────────────────────────────────
-- Escalation leases: bounded privileged access.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_escalation_leases (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    workload_id uuid,
    client_identity_id uuid NOT NULL,
    resource_id uuid,
    action text NOT NULL,
    policy_revision_id uuid,
    approver_id uuid,
    audience text NOT NULL DEFAULT '',
    expiry timestamptz NOT NULL,
    nonce text NOT NULL DEFAULT '',
    max_uses integer NOT NULL DEFAULT 1,
    uses_remaining integer NOT NULL DEFAULT 1,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    redeemed_at timestamptz,
    CONSTRAINT itdr_escalation_leases_pkey PRIMARY KEY (id),
    CONSTRAINT itdr_escalation_leases_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT itdr_escalation_leases_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT itdr_escalation_leases_status_chk CHECK (
        status IN ('pending', 'approved', 'redeemed', 'expired', 'denied')),
    CONSTRAINT itdr_escalation_leases_action_chk CHECK (action <> ''),
    CONSTRAINT itdr_escalation_leases_max_uses_chk CHECK (max_uses >= 1),
    CONSTRAINT itdr_escalation_leases_uses_chk CHECK (uses_remaining >= 0),
    CONSTRAINT itdr_escalation_leases_nonce_key UNIQUE (workspace_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_itdr_escalation_leases_identity
    ON public.itdr_escalation_leases (workspace_id, client_identity_id, status);

CREATE INDEX IF NOT EXISTS idx_itdr_escalation_leases_expiry
    ON public.itdr_escalation_leases (workspace_id, expiry)
    WHERE status IN ('pending', 'approved');

-- ────────────────────────────────────────────────────
-- Alert deliveries: webhook dispatch log.
-- ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.itdr_alert_deliveries (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    webhook_url text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempt integer NOT NULL DEFAULT 0,
    delivered_at timestamptz,
    response_code integer,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT itdr_alert_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT itdr_alert_deliveries_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT itdr_alert_deliveries_finding_fkey FOREIGN KEY (workspace_id, finding_id)
        REFERENCES public.itdr_findings (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT itdr_alert_deliveries_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT itdr_alert_deliveries_status_chk CHECK (
        status IN ('pending', 'delivered', 'failed')),
    CONSTRAINT itdr_alert_deliveries_attempt_chk CHECK (attempt >= 0),
    CONSTRAINT itdr_alert_deliveries_url_chk CHECK (webhook_url <> '')
);

CREATE INDEX IF NOT EXISTS idx_itdr_alert_deliveries_finding
    ON public.itdr_alert_deliveries (workspace_id, finding_id);

CREATE INDEX IF NOT EXISTS idx_itdr_alert_deliveries_status
    ON public.itdr_alert_deliveries (workspace_id, status)
    WHERE status = 'pending';

-- ────────────────────────────────────────────────────
-- Response plans are immutable once approved.
-- ────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.itdr_response_plans_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF public.runtime_policy_workspace_gone(OLD.workspace_id) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'itdr response plans cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.status NOT IN ('requested') THEN
        IF NEW.targets IS DISTINCT FROM OLD.targets
           OR NEW.actions IS DISTINCT FROM OLD.actions
           OR NEW.shared_use_impact IS DISTINCT FROM OLD.shared_use_impact
           OR NEW.expiry IS DISTINCT FROM OLD.expiry
           OR NEW.rollback_behavior IS DISTINCT FROM OLD.rollback_behavior THEN
            RAISE EXCEPTION 'itdr response plan is immutable once approved'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS itdr_response_plans_immutable_trg ON public.itdr_response_plans;
CREATE TRIGGER itdr_response_plans_immutable_trg
    BEFORE UPDATE OR DELETE ON public.itdr_response_plans
    FOR EACH ROW EXECUTE FUNCTION public.itdr_response_plans_immutable();

-- ────────────────────────────────────────────────────
-- Alert deliveries are append-only.
-- ────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.itdr_alert_deliveries_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND public.runtime_policy_workspace_gone(OLD.workspace_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'itdr alert deliveries are append-only'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS itdr_alert_deliveries_append_trg ON public.itdr_alert_deliveries;
CREATE TRIGGER itdr_alert_deliveries_append_trg
    BEFORE UPDATE OR DELETE ON public.itdr_alert_deliveries
    FOR EACH ROW EXECUTE FUNCTION public.itdr_alert_deliveries_append_only();

COMMENT ON TABLE public.itdr_detection_rules IS
    'Detection rule catalog for ITDR. Each workspace configures its own rule set.';
COMMENT ON TABLE public.itdr_findings IS
    'Grouped detection events. A finding aggregates repeated events by workload, identity, resource, and rule within a configurable window.';
COMMENT ON TABLE public.itdr_response_plans IS
    'Response plans are immutable once approved. Status moves through requested, approved, executing, verified, failed, refused.';
COMMENT ON TABLE public.itdr_escalation_leases IS
    'Bounded privileged access leases. Default: 15 minutes, one-shot (max_uses=1).';
COMMENT ON TABLE public.itdr_alert_deliveries IS
    'Append-only webhook dispatch log for finding alerts.';
