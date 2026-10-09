-- 011_cloud_identity_and_secret.sql
--
-- The identity foundation of cloud discovery: what code runs as, and the
-- long-lived secrets that prove it. Every later surface — permissions,
-- resources, assume edges, activity, agent classification — resolves against
-- cloud_identity.
--
-- WHY THESE TWO TOGETHER. An access key has no meaning apart from the user it
-- belongs to; cloud_secret.identity_id is NOT NULL and the FK is the point.
-- Splitting them across migrations would leave a release where a secret could
-- be written with nothing to attach it to.
--
-- WHY "no cloud has a list-agents API" MATTERS HERE. cloud_identity is the
-- CANDIDATE POOL, not a list of agents. An IAM role is not evidence of an
-- agent; it is the thing an agent would run as. Classification happens later
-- and writes discovered_agents, which points here. Nothing in these two tables
-- asserts that anything is an agent.
--
-- ---------------------------------------------------------------------------
-- created_at MEANS THE PROVIDER'S CREATION TIME, NOT THE ROW'S.
-- ---------------------------------------------------------------------------
-- The shared cross-cloud note names this column `created_at`, and for
-- cloud_secret it says of it: "Age is the finding". A five-year-old access key
-- is the report; when AuthSec first happened to see it is not. So the provider
-- value keeps the contract's name, and our own bookkeeping uses first_seen_at /
-- last_seen_at — which is what the existing discovered_agents table already
-- calls the same idea, and is more useful for discovery than a row timestamp.
--
-- The Go models therefore map ProviderCreatedAt -> created_at explicitly. A Go
-- field literally named CreatedAt would be auto-populated by GORM with the
-- insert time and would silently overwrite the provider's value with today's
-- date, turning "this key is five years old" into "this key is new" — the exact
-- inversion of the finding.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction — so there is deliberately no BEGIN/COMMIT here.

-- ===========================================================================
-- cloud_identity — what code runs as.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.cloud_identity (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    -- The connector that most recently saw this identity. ON DELETE CASCADE:
    -- disconnecting an account removes what that account's connector found.
    -- There is no orphan state worth keeping — an identity with no way to reach
    -- it can never be refreshed, re-verified or acted on.
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The real provider object name, never an AuthSec abstraction.
    --   AWS   iam_role | iam_user   (agentcore_workload_identity to follow)
    --   GCP   service_account
    --   AZURE service_principal | managed_identity
    kind text NOT NULL,

    -- The provider's own id, verbatim. For AWS the role or user ARN. This is
    -- the cross-connector join key, which is why it is unique per workspace
    -- rather than per connector: the shared note's rule is "one identity, one
    -- row — two connectors seeing the same principal update the same row,
    -- matched on native_id". An ARN already encodes its account, so this cannot
    -- collide across two legitimately different principals.
    native_id text NOT NULL,

    name text NOT NULL DEFAULT '',

    -- PROVIDER creation time. See the header. Nullable because a provider may
    -- not report one.
    created_at timestamptz,

    -- NULL means UNKNOWN, never "never used". The distinction is load-bearing:
    -- an unused over-privileged role is a finding, and an unknown one is a gap
    -- in our coverage. Reporting the second as the first would manufacture
    -- findings out of our own blind spots.
    last_used_at timestamptz,

    -- AWS has no disable switch for a role or user, so this is always true
    -- there. It exists for the providers that do.
    enabled boolean NOT NULL DEFAULT true,

    -- Small provider extras. For AWS: the unique id (AROA.../AIDA...), path,
    -- description, tags, max session duration.
    --
    -- The unique id lives here rather than replacing native_id as the key: the
    -- ARN is what every other connector and every policy document refers to, so
    -- it has to stay the join key. But a role deleted and recreated with the
    -- same name has the SAME ARN and a DIFFERENT unique id, so keeping the id
    -- is the only way to notice that the principal is not the one we saw last
    -- week.
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Reconciliation. Stamped with cloud_connector.scan_generation on every
    -- scan that sees this row. A row whose generation has fallen behind was not
    -- seen last time — which is only meaningful if that surface was actually
    -- reached, hence cloud_connector.coverage.
    last_seen_generation integer NOT NULL DEFAULT 0,

    -- OUR bookkeeping, deliberately named apart from created_at.
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_identity_kind_chk CHECK (kind <> ''),
    CONSTRAINT cloud_identity_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_identity_generation_chk CHECK (last_seen_generation >= 0)
);

-- One identity, one row. The conflict target for the scan's upsert, and what
-- makes a repeat scan an update rather than a duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_identity_native
    ON public.cloud_identity (workspace_id, native_id);

-- The scan's own reconciliation query: everything this connector saw, by
-- generation.
CREATE INDEX IF NOT EXISTS idx_cloud_identity_connector_generation
    ON public.cloud_identity (connector_id, last_seen_generation);

-- The console's list query.
CREATE INDEX IF NOT EXISTS idx_cloud_identity_workspace_kind
    ON public.cloud_identity (workspace_id, kind);

-- ===========================================================================
-- cloud_secret — the long-lived secret that proves an identity.
-- ===========================================================================
--
-- METADATA ONLY. There is no column here that accepts a secret value, and that
-- is a deliberate structural guarantee rather than a convention: a schema with
-- nowhere to put a value cannot leak one through a careless INSERT, a debug
-- log of a row, or a database backup. native_id holds a key IDENTIFIER — an
-- AWS access key id (AKIA...), which is public in the sense that it appears in
-- CloudTrail and in the credential report.

CREATE TABLE IF NOT EXISTS public.cloud_secret (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The identity this secret proves. NOT NULL: an access key without its user
    -- is not a finding, it is a fragment.
    --
    -- NOTE for the schema owner: AgentCore OAuth2 and API-key credential
    -- providers are account-scoped rather than owned by one identity, so
    -- writing them here (planned for ticket [3]) will need this relaxed to
    -- nullable. Raised in the AWS plan's section 6 and not yet decided; left
    -- NOT NULL until it is, because loosening a constraint later is an
    -- expand-only change while tightening one is not.
    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,

    -- AWS access_key. GCP sa_json_key. AZURE client_secret | certificate.
    kind text NOT NULL,

    -- The key IDENTIFIER only. Never material.
    native_id text NOT NULL,

    -- PROVIDER creation time. "Age is the finding" — this is the column the
    -- stale-credential report reads.
    created_at timestamptz,

    -- NULL where the provider has no expiry, which is the case for every AWS
    -- access key. Not "no expiry recorded" — AWS access keys genuinely do not
    -- expire, which is itself why their age matters.
    expires_at timestamptz,

    -- NULL means unknown, never "never used". AWS reports a key that has never
    -- been used by omitting the date, so the scanner must not turn that into a
    -- zero timestamp.
    last_used_at timestamptz,

    -- active | inactive, the provider's own words.
    status text NOT NULL DEFAULT 'active',

    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_secret_kind_chk CHECK (kind <> ''),
    CONSTRAINT cloud_secret_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_secret_status_chk CHECK (status IN ('active', 'inactive')),
    CONSTRAINT cloud_secret_generation_chk CHECK (last_seen_generation >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_secret_native
    ON public.cloud_secret (workspace_id, native_id);

CREATE INDEX IF NOT EXISTS idx_cloud_secret_identity
    ON public.cloud_secret (identity_id);

CREATE INDEX IF NOT EXISTS idx_cloud_secret_connector_generation
    ON public.cloud_secret (connector_id, last_seen_generation);

-- Stale-credential reporting: oldest active keys first, which is the whole
-- point of holding created_at.
CREATE INDEX IF NOT EXISTS idx_cloud_secret_age
    ON public.cloud_secret (workspace_id, status, created_at);
