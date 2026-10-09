-- ============================================================================
-- Forward delta: entitlement provenance + ownership + request intent.
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_provenance.sql
--
-- Phase 1 of PROVISIONING-GOVERNANCE-ARCHITECTURE.md §11.
--
-- THE GAP THIS CLOSES
-- The platform can answer "what does this subject have?" precisely — the
-- ScopeResolver walks role_bindings -> roles -> permissions -> oauth_scopes and
-- honours expires_at. It cannot answer "WHY does this subject have it?" at all.
-- There is no record of who asked, who approved, what justification was given, what
-- it was for, or whether it was meant to be temporary.
--
-- That is not a reporting nicety. It is the prerequisite for certification: a
-- reviewer asked "should this agent still have this?" has nothing to review without
-- it, and every answer becomes a guess. It is also what makes revocation auditable
-- after the fact, once the grant row itself is gone.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- 1. ownership -------------------------------------------------------------
--
-- Certification needs a reviewer, and the reviewer of an entitlement is the owner
-- of the thing it grants access to. Without owner_user_id there is nobody to route
-- a review to, so this has to land before campaigns can exist at all.
ALTER TABLE public.resource_servers
    ADD COLUMN IF NOT EXISTS owner_user_id uuid,
    -- risk_tier drives certification frequency and review ordering: a critical
    -- Application's entitlements get reviewed more often and sort first.
    ADD COLUMN IF NOT EXISTS risk_tier text NOT NULL DEFAULT 'medium';

DO $$ BEGIN
    ALTER TABLE public.resource_servers
        ADD CONSTRAINT resource_servers_risk_tier_chk
        CHECK (risk_tier IN ('low', 'medium', 'high', 'critical'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE public.resource_servers
        ADD CONSTRAINT resource_servers_owner_fkey FOREIGN KEY (owner_user_id)
        REFERENCES public.users(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- The accountable human for an agent, and its governance state.
--
-- governance_status is deliberately SEPARATE from anything the agent's runtime does
-- (see discovered_agents.runtime_status): this is what a human decided about the
-- agent's authority, not whether its workload happens to be running.
ALTER TABLE public.mcp_oauth_clients
    ADD COLUMN IF NOT EXISTS owner_user_id uuid,
    ADD COLUMN IF NOT EXISTS governance_status text NOT NULL DEFAULT 'ungoverned';

DO $$ BEGIN
    ALTER TABLE public.mcp_oauth_clients
        ADD CONSTRAINT mcp_oauth_clients_governance_status_chk
        CHECK (governance_status IN ('ungoverned', 'active', 'suspended', 'deprovisioned'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE public.mcp_oauth_clients
        ADD CONSTRAINT mcp_oauth_clients_owner_fkey FOREIGN KEY (owner_user_id)
        REFERENCES public.users(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_clients_owner
    ON public.mcp_oauth_clients(owner_user_id) WHERE owner_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_resource_servers_owner
    ON public.resource_servers(owner_user_id) WHERE owner_user_id IS NOT NULL;

-- 2. request intent --------------------------------------------------------
--
-- Extends access_requests, which is the LIVE request pipeline. Deliberately NOT
-- role_assignment_requests: that table is vestigial (referenced by no service or
-- controller) and lacks expires_at, requested_scopes, and a usable status enum.
ALTER TABLE public.access_requests
    -- Why the requester says they need it. Mandatory for a standing grant.
    ADD COLUMN IF NOT EXISTS justification text NOT NULL DEFAULT '',
    -- What it is FOR, in the requester's words. Certification compares stated
    -- purpose against observed usage, which is impossible without capturing it.
    ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS request_origin text NOT NULL DEFAULT 'admin',
    -- What the requester ASKED for, distinct from access_requests.expires_at, which
    -- is what they were GRANTED. Keeping both is what makes "we always cut requests
    -- to a fraction of what was asked" visible instead of folklore.
    ADD COLUMN IF NOT EXISTS requested_duration interval,
    ADD COLUMN IF NOT EXISTS discovered_agent_id uuid;

DO $$ BEGIN
    ALTER TABLE public.access_requests
        ADD CONSTRAINT access_requests_origin_chk
        CHECK (request_origin IN ('discovery_claim', 'self_service', 'birthright',
                                  'admin', 'escalation'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE public.access_requests
        ADD CONSTRAINT access_requests_discovered_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- 3. entitlement_provenance ------------------------------------------------
--
-- One row per grant DECISION. Rows are opened when a grant is made and closed when
-- it is revoked; nothing is ever deleted, because this is evidence.
--
-- WHY BOTH A POINTER AND A SNAPSHOT
-- The live pointers (role_binding_id etc.) are ON DELETE SET NULL, because
-- provenance has to OUTLIVE the grant it describes — an expired binding is deleted,
-- and that is exactly the moment the record of it mattering becomes important. So
-- entitlement_snapshot carries a denormalised copy of the essentials, and stays
-- readable after the pointer is nulled. Pointer alone would lose the evidence;
-- snapshot alone could not be joined while the grant is live.
CREATE TABLE IF NOT EXISTS public.entitlement_provenance (
    id                       uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id             uuid NOT NULL,

    -- WHAT was granted
    entitlement_type         text NOT NULL,
    role_binding_id          uuid,
    client_registration_id   uuid,
    connector_assignment_id  uuid,
    entitlement_snapshot     jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Human-readable one-liner for a review queue, so a reviewer does not have to
    -- read jsonb to know what they are deciding on.
    entitlement_label        text NOT NULL DEFAULT '',

    -- WHO holds it. Not an FK: the subject may be a user, a service account, or an
    -- oauth client, and a polymorphic FK cannot express that. The service resolves
    -- and validates the subject before writing.
    subject_type             text NOT NULL,
    subject_id               uuid NOT NULL,
    subject_label            text NOT NULL DEFAULT '',

    -- WHY it was granted
    origin                   text NOT NULL,
    justification            text NOT NULL DEFAULT '',
    purpose                  text NOT NULL DEFAULT '',
    access_request_id        uuid,
    discovered_agent_id      uuid,

    -- BY WHOM. granted_by_label is denormalised on purpose: a deactivated user's row
    -- can be deleted, and "granted by <null>" is useless in an audit six months on.
    granted_by               uuid,
    granted_by_label         text NOT NULL DEFAULT '',
    granted_at               timestamptz NOT NULL DEFAULT now(),

    -- FOR HOW LONG. is_standing marks a deliberate permanent grant; those require a
    -- justification and sort first in every certification campaign (PG-4).
    expires_at               timestamptz,
    is_standing              boolean NOT NULL DEFAULT false,

    -- CLOSING
    revoked_at               timestamptz,
    revoked_by               uuid,
    revoked_reason           text NOT NULL DEFAULT '',
    -- Which mechanism closed it. All five funnel through one de-provision path
    -- (PG-6); this records which caller invoked it.
    revoked_via              text NOT NULL DEFAULT '',

    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT entitlement_provenance_pkey PRIMARY KEY (id),
    CONSTRAINT entitlement_provenance_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT entitlement_provenance_role_binding_fkey FOREIGN KEY (role_binding_id)
        REFERENCES public.role_bindings(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_client_reg_fkey FOREIGN KEY (client_registration_id)
        REFERENCES public.resource_server_client_registrations(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_connector_assignment_fkey FOREIGN KEY (connector_assignment_id)
        REFERENCES public.connector_assignments(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_access_request_fkey FOREIGN KEY (access_request_id)
        REFERENCES public.access_requests(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_discovered_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE SET NULL,
    CONSTRAINT entitlement_provenance_granted_by_fkey FOREIGN KEY (granted_by)
        REFERENCES public.users(id) ON DELETE SET NULL,

    CONSTRAINT entitlement_provenance_type_chk CHECK (
        entitlement_type IN ('role_binding', 'client_registration', 'secret_access')),
    CONSTRAINT entitlement_provenance_subject_chk CHECK (
        subject_type IN ('user', 'service_account', 'oauth_client', 'group')),
    CONSTRAINT entitlement_provenance_origin_chk CHECK (
        origin IN ('discovery_claim', 'self_service', 'birthright', 'admin',
                   'escalation', 'connection_approval', 'migration')),
    CONSTRAINT entitlement_provenance_revoked_via_chk CHECK (
        revoked_via IN ('', 'expiry', 'certification', 'leaver', 'quarantine',
                        'admin', 'sod_remediation')),
    -- A standing grant must say why it is standing. This is the mechanism behind
    -- "ephemeral is the default, permanent is the audited exception" — without it,
    -- is_standing would just be a boolean nobody has to defend.
    CONSTRAINT entitlement_provenance_standing_needs_justification_chk CHECK (
        NOT is_standing OR justification <> ''),
    -- A closed row must say when and why.
    CONSTRAINT entitlement_provenance_revocation_complete_chk CHECK (
        (revoked_at IS NULL AND revoked_via = '')
        OR (revoked_at IS NOT NULL AND revoked_via <> '')),
    -- Exactly one live pointer, matching entitlement_type. Prevents a row that
    -- claims to describe a role binding while pointing at a client registration.
    CONSTRAINT entitlement_provenance_pointer_chk CHECK (
        (entitlement_type = 'role_binding'
            AND client_registration_id IS NULL AND connector_assignment_id IS NULL)
     OR (entitlement_type = 'client_registration'
            AND role_binding_id IS NULL AND connector_assignment_id IS NULL)
     OR (entitlement_type = 'secret_access'
            AND role_binding_id IS NULL AND client_registration_id IS NULL))
);

-- At most ONE OPEN provenance row per live entitlement. Partial, so the history of
-- closed rows for a recreated entitlement is unconstrained. Without this, a retried
-- provision would silently double-record and every "why" query would return two
-- conflicting answers.
CREATE UNIQUE INDEX IF NOT EXISTS entitlement_provenance_open_role_binding_key
    ON public.entitlement_provenance(role_binding_id)
    WHERE role_binding_id IS NOT NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS entitlement_provenance_open_client_reg_key
    ON public.entitlement_provenance(client_registration_id)
    WHERE client_registration_id IS NOT NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS entitlement_provenance_open_connector_key
    ON public.entitlement_provenance(connector_assignment_id)
    WHERE connector_assignment_id IS NOT NULL AND revoked_at IS NULL;

-- "What does this subject have, and why?" — the certification and console query.
CREATE INDEX IF NOT EXISTS idx_entitlement_provenance_subject
    ON public.entitlement_provenance(workspace_id, subject_type, subject_id)
    WHERE revoked_at IS NULL;
-- The expiry worker's sweep: open, expiring, not standing.
CREATE INDEX IF NOT EXISTS idx_entitlement_provenance_expiring
    ON public.entitlement_provenance(expires_at)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
-- "Show me every standing grant" — the first page of any campaign.
CREATE INDEX IF NOT EXISTS idx_entitlement_provenance_standing
    ON public.entitlement_provenance(workspace_id)
    WHERE revoked_at IS NULL AND is_standing;
CREATE INDEX IF NOT EXISTS idx_entitlement_provenance_agent
    ON public.entitlement_provenance(discovered_agent_id)
    WHERE discovered_agent_id IS NOT NULL;

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.entitlement_provenance') AS provenance_table,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'access_requests'
           AND column_name IN ('justification','purpose','request_origin',
                               'requested_duration','discovered_agent_id')) AS request_cols,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'resource_servers'
           AND column_name IN ('owner_user_id','risk_tier')) AS rs_cols,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'mcp_oauth_clients'
           AND column_name IN ('owner_user_id','governance_status')) AS client_cols;
