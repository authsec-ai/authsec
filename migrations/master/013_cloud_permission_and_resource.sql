-- 013_cloud_permission_and_resource.sql
--
-- Ticket [2] of AWS cloud discovery: what each identity is permitted to do,
-- and what it is permitted to do it to.
--
-- WHY THESE TWO TOGETHER, AND WHY cloud_resource IS EMPTY WITHOUT A GRANT.
-- cloud_permission is the identity-to-resource edge, so there is no separate
-- grant table -- a permission IS the grant. cloud_resource exists only because
-- a permission statement named it: this migration never scans an account for
-- resources, it only records what a policy document already claimed. A row
-- created any other way would overstate what AuthSec actually knows.
--
-- WHY A WILDCARD NEVER PRODUCES A cloud_resource ROW. Resource: "*" or a
-- partial wildcard like "arn:aws:s3:::bucket/*" both describe a SCOPE, not a
-- thing. Inventing a resource row per wildcard would let one broad statement
-- manufacture a resource that was never independently observed, which is
-- exactly the false precision the AWS plan's section 2 rules out ("we only
-- record a resource if a discovered permission actually names it").
-- scope_kind carries the distinction instead: resource | prefix | account_wide.
--
-- WHY role_name IS ALWAYS NULL HERE. The shared cross-cloud note says so
-- explicitly: "Null for AWS" -- an IAM policy statement has no role name of its
-- own, unlike an Azure RBAC role assignment. The column exists for Azure, not
-- for us.
--
-- WHY plane IS ALWAYS 'cloud'. The shared note adds `plane` so Azure's two
-- permission systems -- ARM RBAC and Graph API permissions -- can share this
-- table. AWS has one permission system, so every AWS row is plane='cloud' and
-- 'api' never appears here.
--
-- WHY derivation IS ALWAYS 'granted' HERE, AND WHAT 'effective' WOULD MEAN.
-- 'granted' is a statement that exists in a policy document, which is all this
-- ticket reads. 'effective' would mean the permission actually applies after
-- service control policies, permission boundaries and session policies are
-- evaluated -- and the AWS plan's section 2 puts computing that explicitly out
-- of scope. The column exists now so a later ticket can add effective rows
-- without a schema change, and so a reader always knows which kind of claim one
-- row is making.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction -- so there is deliberately no BEGIN/COMMIT here.

-- ===========================================================================
-- cloud_resource — the thing a grant points at.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_resource (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- Typed by service, e.g. "s3_bucket", "dynamodb_table", "secretsmanager_secret".
    -- Text, not an enum: the shared note is explicit that a schema-wide enum of
    -- every AWS resource type would need a migration for every new service AWS
    -- ships, which defeats the point of the column.
    kind text NOT NULL,

    -- The ARN, verbatim. The cross-connector and cross-scan join key.
    native_id text NOT NULL,

    name text NOT NULL DEFAULT '',

    -- Rule-based per the AWS plan's section 5: Secrets Manager, KMS and IAM
    -- resources are high; everything else starts low. This is a starting
    -- heuristic, not a risk engine -- a later ticket may read activity or tags
    -- to refine it, which is why this is a plain column and not computed at
    -- read time.
    sensitivity text NOT NULL DEFAULT 'low',

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_resource_kind_chk CHECK (kind <> ''),
    CONSTRAINT cloud_resource_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_resource_sensitivity_chk CHECK (
        sensitivity IN ('low', 'med', 'high')
    ),
    CONSTRAINT cloud_resource_generation_chk CHECK (last_seen_generation >= 0)
);

-- One resource, one row, matched on the ARN -- two statements naming the same
-- ARN update it rather than forking it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_resource_native
    ON public.cloud_resource (workspace_id, native_id);

CREATE INDEX IF NOT EXISTS idx_cloud_resource_connector_generation
    ON public.cloud_resource (connector_id, last_seen_generation);

-- ===========================================================================
-- cloud_permission — one grant: this identity may do these actions on that
-- resource.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_permission (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,

    -- NULL on a wildcard or prefix grant. Never invent a resource row to fill
    -- this in -- see the file header.
    resource_id uuid
        REFERENCES public.cloud_resource(id) ON DELETE CASCADE,

    plane text NOT NULL DEFAULT 'cloud',
    effect text NOT NULL,

    -- Null for AWS. See the file header.
    role_name text,

    -- The statement's Action list, normalised to an array whether the policy
    -- document wrote a single string or a list.
    actions text[] NOT NULL,

    scope_kind text NOT NULL,

    derivation text NOT NULL DEFAULT 'granted',

    -- Same starting heuristic as cloud_resource.sensitivity, applied to the
    -- actions themselves: a grant touching Secrets Manager, KMS or IAM is high
    -- regardless of what it names, because the action is the risk even before
    -- a resource is known.
    sensitivity text NOT NULL DEFAULT 'low',

    -- Aggregated from cloud_usage by a later ticket. Always NULL as written by
    -- this one -- ticket [2] parses grants, it does not read activity.
    last_exercised_at timestamptz,

    -- Where the grant came from: a managed policy ARN, or "inline:<policy
    -- name>" for one defined directly on the identity, suffixed with the
    -- statement's position so two statements in one document do not collide.
    native_id text NOT NULL,

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_permission_plane_chk CHECK (plane IN ('cloud', 'api')),
    CONSTRAINT cloud_permission_effect_chk CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT cloud_permission_scope_kind_chk CHECK (
        scope_kind IN ('resource', 'prefix', 'account_wide')
    ),
    -- A resource-scoped grant must name the resource it was scoped to; an
    -- account-wide or prefix grant must not claim one, which is the structural
    -- form of "never invent a resource row for a wildcard".
    CONSTRAINT cloud_permission_scope_resource_chk CHECK (
        (scope_kind = 'resource') = (resource_id IS NOT NULL)
    ),
    CONSTRAINT cloud_permission_derivation_chk CHECK (
        derivation IN ('granted', 'effective')
    ),
    CONSTRAINT cloud_permission_sensitivity_chk CHECK (
        sensitivity IN ('low', 'med', 'high')
    ),
    CONSTRAINT cloud_permission_actions_chk CHECK (array_length(actions, 1) > 0),
    CONSTRAINT cloud_permission_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_permission_generation_chk CHECK (last_seen_generation >= 0)
);

-- One row per (identity, source statement, resource). native_id already
-- encodes the statement; resource_id (nullable) completes the key for a
-- statement naming more than one resource, which fans out to one row per
-- resource sharing the same native_id.
--
-- NULLS NOT DISTINCT (PostgreSQL 15+; this repo's CI runs 16) so that two
-- account_wide or prefix grants from the same statement -- both with
-- resource_id NULL -- collide as a conflict target instead of silently
-- duplicating on every scan. A plain UNIQUE index treats every NULL as
-- distinct from every other, which would defeat the upsert for exactly the
-- wildcard rows this table exists to get right.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_permission_grant
    ON public.cloud_permission (identity_id, native_id, resource_id)
    NULLS NOT DISTINCT;

CREATE INDEX IF NOT EXISTS idx_cloud_permission_connector_generation
    ON public.cloud_permission (connector_id, last_seen_generation);

-- The console's list query: everything one identity is granted.
CREATE INDEX IF NOT EXISTS idx_cloud_permission_identity
    ON public.cloud_permission (identity_id);

-- The console's reverse query: everything permitted to reach one resource.
CREATE INDEX IF NOT EXISTS idx_cloud_permission_resource
    ON public.cloud_permission (resource_id) WHERE resource_id IS NOT NULL;
