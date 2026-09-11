-- 015_azure_connectors.sql
--
-- Azure onboarding: which Entra tenants this workspace has admin-consented the
-- AuthSec application into, and whether that consent actually bought ARM read
-- access.
--
-- WHY THIS IS NOT cloud_connector. cloud_connector records a proven read-only
-- connection to one cloud scope and is the row every AWS scan resolves against.
-- Azure onboarding is a step earlier and a different shape: an operator signs in
-- with their own Azure work account, AuthSec lists the tenants THAT PERSON can
-- see, and each selected tenant is admin-consented separately. Until ARM Reader
-- is assigned there is nothing to scan, so writing a cloud_connector row here
-- would claim a working connection that does not exist yet. This table is the
-- consent ledger; promoting a tenant to a cloud_connector is a later ticket.
--
-- WHY workspace_id, WHEN THE SPEC SAID tenant_id UNIQUE. Every data operation in
-- this codebase is workspace-scoped unless the object is platform-global, and an
-- Entra tenant is emphatically not platform-global -- two workspaces in the same
-- deployment onboarding the same tenant must not see each other's rows. The
-- uniqueness the spec asked for is preserved as UNIQUE (workspace_id,
-- tenant_id), the same shape cloud_connector uses for (workspace_id, provider,
-- scope_id).
--
-- WHY arm_reader_ok STARTS false. Consent alone never means access, so a tenant
-- is not usable the moment it is consented -- it is usable when an ARM Reader
-- check has actually passed. Starting at false makes "complete" a single
-- condition: a row exists AND arm_reader_ok is true. The "never checked" case is
-- not lost; arm_checked_at IS NULL still says it, and arm_last_error says why a
-- check failed.

CREATE TABLE IF NOT EXISTS public.azure_connectors (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL REFERENCES public.workspaces (id) ON DELETE CASCADE,

    -- The Entra tenant (directory) id. From the ARM tenant list or the verified
    -- admin-consent callback state, never from a caller-supplied body.
    tenant_id      text NOT NULL,

    -- Both come from the ARM tenant list and are display sugar. Nullable because
    -- ARM omits them for tenants the signed-in account can see but has no
    -- directory read on.
    display_name   text,
    domain         text,

    -- When admin consent last completed for this tenant. Refreshed on re-consent.
    consented_at   timestamptz,

    -- false until an ARM Reader check actually succeeds. Onboarding is complete
    -- only when a row exists AND this is true.
    arm_reader_ok  boolean NOT NULL DEFAULT false,

    -- NULL here is what still distinguishes "never checked" from "checked and
    -- refused", now that arm_reader_ok itself no longer carries that.
    arm_checked_at timestamptz,
    arm_last_error text,

    -- Object id of the AuthSec service principal INSIDE the customer's tenant.
    -- Created by admin consent, so unknown until then, and read from the oid
    -- claim of an app-only token rather than from Graph -- which keeps the
    -- promise that this flow never calls /servicePrincipals. It is what an
    -- Azure RBAC role assignment must name; the application (client) id does
    -- not work there.
    principal_object_id text,

    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT azure_connectors_tenant_uq UNIQUE (workspace_id, tenant_id),
    CONSTRAINT azure_connectors_tenant_id_chk CHECK (tenant_id <> '')
);

CREATE INDEX IF NOT EXISTS idx_azure_connectors_workspace
    ON public.azure_connectors (workspace_id);

-- One-shot OAuth state for the two browser redirects this flow performs.
--
-- WHY A TABLE AND NOT A LITERAL STRING. The state parameter is the only thing
-- standing between this flow and a forged callback: the browser arrives at
-- /api/azure/callback from Microsoft with query parameters an attacker can also
-- produce. A fixed literal like state=login is not validatable -- anyone can
-- send it. A row here makes the state unguessable, single-use (deleted on
-- redemption), expiring, and -- the part that matters most -- the ONLY place the
-- workspace and the consented tenant are read from. The tenant query parameter
-- Microsoft appends is compared against this row and never trusted alone.
--
-- Mirrors connector_oauth_state, which does the same job for the connector
-- broker's OAuth providers.
CREATE TABLE IF NOT EXISTS public.azure_oauth_state (
    state        text PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES public.workspaces (id) ON DELETE CASCADE,

    -- 'login'   -- delegated sign-in, returns an ARM token for the tenant list.
    -- 'consent' -- admin consent for one tenant, named in tenant_id.
    purpose      text NOT NULL,
    tenant_id    text,

    created_by   text,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT azure_oauth_state_purpose_chk CHECK (purpose IN ('login', 'consent')),

    -- A consent redirect must name a tenant; a login redirect must not. Written
    -- against emptiness rather than NULL because the Go model types tenant_id as
    -- a plain string: GORM sends '' for a login state, not NULL, so a bare
    -- IS NOT NULL test would reject every sign-in.
    CONSTRAINT azure_oauth_state_consent_tenant_chk CHECK (
        (purpose = 'consent') = (tenant_id IS NOT NULL AND tenant_id <> '')
    )
);

CREATE INDEX IF NOT EXISTS idx_azure_oauth_state_expires
    ON public.azure_oauth_state (expires_at);
