-- ============================================================================
-- Forward delta: separation of duties.
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_sod.sql
--
-- Phase 3 of PROVISIONING-GOVERNANCE-ARCHITECTURE.md §11. Depends on
-- governance_provenance.sql.
--
-- TWO RULE SHAPES, because the agentic cases are not all classic SoD:
--
--   'conflict'    — the textbook shape. Holding capabilities from BOTH sides at once
--                   is the violation (raise a purchase order AND approve payments).
--   'prohibition' — one side only. Holding ANY of these at all is the violation, for
--                   the subjects the rule applies to. This is what expresses "no
--                   agent principal may hold role-management authority", which is not
--                   a conflict between two duties but a capability an agent must
--                   never have. Forcing that into the two-set shape would have meant
--                   inventing a fake second side.
--
-- PREVENTIVE AND DETECTIVE. The preventive check runs inside the provisioning
-- transaction, so a grant that would create a violation is REFUSED rather than
-- recorded and reported later. The detective scan catches what predates the rule, or
-- what arrived through a path that does not yet call the check.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- sod_rules ----------------------------------------------------------------
--
-- Capabilities are named in the platform's OWN vocabulary — role ids and
-- `resource:action` permission strings — so a rule means exactly what enforcement
-- means. Expressing rules in a parallel vocabulary is how an SoD engine drifts from
-- the thing it is supposed to police, and a drifted engine gives false assurance,
-- which is worse than none.
--
-- workspace_id NULL marks a GLOBAL rule, the same convention permissions use. Global
-- + is_system rules are the seeded controls; the API refuses to edit or delete them.
CREATE TABLE IF NOT EXISTS public.sod_rules (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid,
    name          text NOT NULL,
    description   text NOT NULL DEFAULT '',
    kind          text NOT NULL DEFAULT 'conflict',
    severity      text NOT NULL DEFAULT 'high',
    enabled       boolean NOT NULL DEFAULT true,
    -- A system rule is immutable through the API. The self-modification control has to
    -- be un-editable, or an attacker who reaches the governance API simply turns it off
    -- before escalating.
    is_system     boolean NOT NULL DEFAULT false,
    -- Which subjects the rule applies to. 'agents' means a service account that is an
    -- agent's entitlement anchor (service_accounts.oauth_client_id IS NOT NULL) —
    -- which is precisely the population the self-modification control targets.
    subject_scope text NOT NULL DEFAULT 'any',

    -- Side A. Always meaningful.
    left_label       text NOT NULL DEFAULT '',
    left_roles       text[] NOT NULL DEFAULT '{}',
    left_permissions text[] NOT NULL DEFAULT '{}',

    -- Side B. Empty for a prohibition.
    right_label       text NOT NULL DEFAULT '',
    right_roles       text[] NOT NULL DEFAULT '{}',
    right_permissions text[] NOT NULL DEFAULT '{}',

    -- 'block' refuses the grant in the preventive check; 'warn' records the violation
    -- and allows it. Warn exists so a rule can be rolled out in observation mode
    -- before it starts refusing real requests.
    enforcement text NOT NULL DEFAULT 'block',

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sod_rules_pkey PRIMARY KEY (id),
    CONSTRAINT sod_rules_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT sod_rules_kind_chk CHECK (kind IN ('conflict', 'prohibition')),
    CONSTRAINT sod_rules_severity_chk CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT sod_rules_subject_scope_chk CHECK (subject_scope IN ('any', 'agents', 'humans')),
    CONSTRAINT sod_rules_enforcement_chk CHECK (enforcement IN ('block', 'warn')),
    -- Side A must name something, or the rule matches everything.
    CONSTRAINT sod_rules_left_nonempty_chk CHECK (
        cardinality(left_roles) > 0 OR cardinality(left_permissions) > 0),
    -- A conflict needs a second side; a prohibition must not have one, or it is
    -- silently a conflict wearing the wrong label.
    CONSTRAINT sod_rules_shape_chk CHECK (
        (kind = 'conflict'
            AND (cardinality(right_roles) > 0 OR cardinality(right_permissions) > 0))
     OR (kind = 'prohibition'
            AND cardinality(right_roles) = 0 AND cardinality(right_permissions) = 0))
);

-- One rule name per workspace. Partial-by-coalesce so global rules (workspace_id
-- NULL) share one namespace rather than every NULL being distinct.
CREATE UNIQUE INDEX IF NOT EXISTS sod_rules_name_key
    ON public.sod_rules(COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE INDEX IF NOT EXISTS idx_sod_rules_enabled
    ON public.sod_rules(workspace_id) WHERE enabled;

-- sod_violations -----------------------------------------------------------
--
-- Records the CONFLICTING PATHS, not just a flag. A reviewer told "this subject
-- violates rule X" cannot act; one told "it holds governance:admin via role
-- platform-admin, bound by binding <id>" can.
CREATE TABLE IF NOT EXISTS public.sod_violations (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    rule_id      uuid NOT NULL,
    rule_name    text NOT NULL DEFAULT '',

    subject_type  text NOT NULL,
    subject_id    uuid NOT NULL,
    subject_label text NOT NULL DEFAULT '',

    -- Which capabilities matched each side, and through which bindings.
    left_evidence  jsonb NOT NULL DEFAULT '[]'::jsonb,
    right_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,

    status text NOT NULL DEFAULT 'open',
    -- 'accepted' is a documented risk acceptance, not a fix. It needs a note and an
    -- owner, because an unexplained acceptance is indistinguishable from neglect.
    resolution_note text NOT NULL DEFAULT '',
    resolved_by     uuid,
    resolved_at     timestamptz,

    detected_at timestamptz NOT NULL DEFAULT now(),
    -- Refreshed by each scan that still sees it, so an open violation's age is real.
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    -- 'preventive' means a grant was refused; 'detective' means a scan found an
    -- existing one. Preventive rows are evidence of an attempt, which is worth
    -- keeping distinct.
    detected_via text NOT NULL DEFAULT 'detective',

    CONSTRAINT sod_violations_pkey PRIMARY KEY (id),
    CONSTRAINT sod_violations_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT sod_violations_rule_fkey FOREIGN KEY (rule_id)
        REFERENCES public.sod_rules(id) ON DELETE CASCADE,
    CONSTRAINT sod_violations_resolved_by_fkey FOREIGN KEY (resolved_by)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT sod_violations_status_chk CHECK (status IN ('open', 'accepted', 'remediated')),
    CONSTRAINT sod_violations_detected_via_chk CHECK (detected_via IN ('preventive', 'detective')),
    CONSTRAINT sod_violations_resolution_chk CHECK (
        status = 'open' OR (resolved_at IS NOT NULL AND resolution_note <> ''))
);

-- One OPEN violation per (rule, subject). Re-detecting refreshes last_seen_at rather
-- than piling up duplicates, so the count means "how many problems" and not "how many
-- times the scan ran".
CREATE UNIQUE INDEX IF NOT EXISTS sod_violations_open_key
    ON public.sod_violations(workspace_id, rule_id, subject_type, subject_id)
    WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_sod_violations_open
    ON public.sod_violations(workspace_id, status, detected_at DESC);

-- The seeded self-modification control -------------------------------------
--
-- An agent that can grant itself permissions is not governed, whatever the inventory
-- says. This is the preventive half of that control; the other half is that the PDP
-- resolves no scope for a binding an agent does not hold.
--
-- GLOBAL and is_system, so it applies in every workspace and cannot be edited or
-- disabled through the API. 'prohibition' rather than 'conflict' because these are
-- capabilities an agent must never hold at all, not two duties that must stay apart.
INSERT INTO public.sod_rules
    (workspace_id, name, description, kind, severity, is_system, subject_scope,
     left_label, left_permissions, enforcement, created_by)
VALUES (
    NULL,
    'agent-self-modification',
    'An agent principal may not hold governance, role-management, or binding-write '
        || 'authority. An agent that can widen its own access is ungoverned however '
        || 'complete its inventory record looks.',
    'prohibition',
    'critical',
    true,
    'agents',
    'governance and role-management authority',
    ARRAY[
        'governance:admin',
        'governance:revoke',
        'governance:certify',
        'roles:create', 'roles:update', 'roles:delete',
        'role_bindings:create', 'role_bindings:update', 'role_bindings:delete',
        'permissions:create', 'permissions:update', 'permissions:delete',
        'discovery:claim', 'discovery:admin'
    ]::text[],
    'block',
    'system'
)
ON CONFLICT (COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), name)
DO NOTHING;

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.sod_rules')      AS rules_table,
       to_regclass('public.sod_violations')  AS violations_table,
       (SELECT count(*) FROM public.sod_rules WHERE is_system) AS system_rules;
