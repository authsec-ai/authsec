-- 016_azure_graph_and_subscriptions.sql
--
-- Close the two places Azure onboarding claims something it has not checked.
--
-- WHY THIS EXISTS. Onboarding spans two independent authorisation systems, and
-- 015 only ever verified one of them. Admin consent is recorded as consented_at
-- and nothing afterwards asks Microsoft whether a single permission was
-- actually granted -- observed against a real tenant reporting a connector as
-- consented while its app-only token carried no roles claim at all and every
-- Graph call returned Authorization_RequestDenied. The cause was an application
-- that declared no permissions, so .default consent granted nothing; the code
-- could not detect it because it never looked. graph_ok is to Entra what
-- arm_reader_ok already is to ARM.
--
-- WHY SUBSCRIPTIONS BECOME ROWS. 015 listed subscriptions during the ARM probe
-- and threw them away, keeping one boolean for the whole tenant. Two problems
-- follow. A tenant with five subscriptions and Reader on two reported true --
-- an all-clear that was not earned, the same class of error as the empty-list
-- false positive already fixed. And every later discovery object -- a resource,
-- a managed identity, a role assignment -- hangs off a subscription, so with no
-- subscription row there is nothing for the access graph to attach to.
--
-- The composite foreign key is the point of the table as much as the rows are:
-- a subscription cannot exist without the tenant it belongs to, so a
-- subscription id can never be trusted without its tenant context.

/* ------------------------- plane 1: entra / graph ------------------------- */

ALTER TABLE public.azure_connectors
    ADD COLUMN IF NOT EXISTS graph_ok boolean NOT NULL DEFAULT false;

-- NULL distinguishes "never checked" from "checked and refused", exactly as
-- arm_checked_at does for the other plane.
ALTER TABLE public.azure_connectors
    ADD COLUMN IF NOT EXISTS graph_checked_at timestamptz;

ALTER TABLE public.azure_connectors
    ADD COLUMN IF NOT EXISTS graph_last_error text;

-- The roles claim of the app-only Graph token, stored verbatim.
--
-- Read from the token rather than by probing a Graph endpoint: it costs no call,
-- needs no permission of its own to work, and enumerates exactly what was
-- granted instead of proving that one endpoint happened to answer. Keeping the
-- list -- not just a boolean -- is what lets an operator see WHICH permission is
-- missing when a later discovery ticket needs one that was never consented.
ALTER TABLE public.azure_connectors
    ADD COLUMN IF NOT EXISTS graph_granted_roles text[] NOT NULL DEFAULT '{}';

/* ---------------------- plane 2: subscriptions per tenant ---------------------- */

CREATE TABLE IF NOT EXISTS public.azure_subscriptions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    tenant_id       text NOT NULL,

    -- Unique within a tenant, and globally unique in practice, but never
    -- treated as sufficient on its own: the tenant is what says whose
    -- subscription this is and which credential may read it.
    subscription_id text NOT NULL,

    display_name    text,

    -- Azure's own word: Enabled, Warned, PastDue, Disabled, Deleted.
    -- Open text rather than a CHECK enum -- this mirrors a vendor's vocabulary
    -- and a new value must not fail an insert.
    state           text,

    -- Per subscription, because Reader is assigned per scope. A tenant is only
    -- fully covered when every subscription reads true; anything less is
    -- partial and must not present as an all-clear.
    reader_ok         boolean NOT NULL DEFAULT false,
    reader_checked_at timestamptz,

    -- When ARM last returned this subscription. A subscription that stops being
    -- returned has been removed, renamed out of scope, or lost its role
    -- assignment -- distinguishable only if the last sighting is recorded.
    last_seen_at    timestamptz NOT NULL DEFAULT now(),

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT azure_subscriptions_uq UNIQUE (workspace_id, tenant_id, subscription_id),
    CONSTRAINT azure_subscriptions_subscription_id_chk CHECK (subscription_id <> ''),

    -- Composite FK to the connector, not to workspaces: it is what makes the
    -- tenant relationship structural rather than conventional, and it cascades
    -- so a revoked tenant does not leave orphaned subscriptions behind.
    CONSTRAINT azure_subscriptions_connector_fk
        FOREIGN KEY (workspace_id, tenant_id)
        REFERENCES public.azure_connectors (workspace_id, tenant_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_azure_subscriptions_tenant
    ON public.azure_subscriptions (workspace_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_azure_subscriptions_reader
    ON public.azure_subscriptions (workspace_id, reader_ok);
