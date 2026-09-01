-- 010_cloud_discovery_connector.sql
--
-- The first table of the shared cloud discovery schema: one onboarded cloud
-- scope. AWS, Azure and GCP all point every row they write at one of these.
--
-- WHY THIS TABLE FIRST. Nothing else in cloud discovery can exist without it.
-- cloud_identity, cloud_secret, cloud_permission, cloud_resource,
-- cloud_assume_edge and cloud_usage all carry connector_id, and reconciliation
-- is driven by scan_generation, which lives here. Onboarding is also the only
-- step that touches customer credentials, so it is the piece worth getting
-- right before any scanner reads a single IAM role.
--
-- WHY ONE SHARED TABLE AND NOT cloud_connector_aws. The cross-cloud schema
-- note is explicit: provider differences are values in a column, never separate
-- tables. `provider` and `scope_kind` carry the difference — an AWS account, a
-- GCP org/folder/project, an Azure subscription with its tenant in
-- parent_scope_id. A per-cloud table would fork every downstream join three
-- ways for no gain.
--
-- WHY THE cloud_ PREFIX. agents, credentials, permissions, resources and
-- workloads already exist in the AuthSec databases as unrelated concepts.
--
-- WHY SINGULAR, AGAINST THIS REPO'S PLURAL CONVENTION. The name is a contract
-- with two connectors that are not built here. The shared schema note names the
-- table `cloud_connector`, and the Azure and GCP tracks are writing against
-- that name. A local naming preference is not worth a three-way mismatch, so
-- the models carry an explicit TableName() override instead.
--
-- TEXT + CHECK RATHER THAN POSTGRES ENUM TYPES, for every column the shared
-- note calls an enum. Two of those enums are already known to need new values
-- (cloud_identity.kind for AgentCore workload identities, cloud_secret.kind for
-- AgentCore credential providers). ALTER TYPE ... ADD VALUE cannot run inside a
-- transaction block, and the migration runner wraps every file in one, so a
-- native enum would make each of those a two-release dance. A CHECK constraint
-- is one DDL statement in one transaction.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction -- so there is deliberately no BEGIN/COMMIT here (see the
-- note in 006 for what happens when a migration opens a second one).

CREATE TABLE IF NOT EXISTS public.cloud_connector (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,

    -- aws | gcp | azure.
    provider text NOT NULL,

    -- What kind of scope was onboarded. AWS onboards an account; GCP may onboard
    -- an org, a folder or a project; Azure onboards a subscription.
    scope_kind text NOT NULL,

    -- The provider's own identifier for that scope, verbatim: a 12-digit AWS
    -- account id, a GCP project id, an Azure subscription guid. Never a display
    -- name -- this is a join key.
    scope_id text NOT NULL,

    -- Azure tenant, GCP org. NULL, not '', when there is no parent: the shared
    -- schema treats null as "unknown / not applicable", and a connector writing
    -- '' where another writes NULL would break `IS NULL` for everyone.
    parent_scope_id text,

    -- A HANDLE, never key material. For AWS this is the secrets-store path
    -- holding the ExternalId; the role ARN is not secret and lives in attrs so
    -- it stays queryable. No column in this schema accepts a secret value.
    auth_ref text NOT NULL DEFAULT '',

    -- active | revoked | error.
    status text NOT NULL DEFAULT 'active',

    -- Bumped once per scan and stamped onto every row that scan touches, as
    -- last_seen_generation. Reconciliation ages out rows by comparing the two --
    -- but only within surfaces the scan actually reached, which is what coverage
    -- below records.
    scan_generation integer NOT NULL DEFAULT 0,

    -- Per surface: reached | denied | not_configured | throttled. This is the
    -- column that keeps "could not read" distinguishable from "found nothing",
    -- which is the difference between a partial scan and an all-clear.
    --
    -- For AWS the natural key is (region, surface) rather than surface alone,
    -- because a scan can reach IAM (global) and be denied in one of eight
    -- regions. Writing surface alone would let one denied region read as a
    -- denied service.
    coverage jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Provider extras, mirroring cloud_identity.attrs. NOT in the shared note's
    -- column list -- see the note at the end of this file for why it is here and
    -- what it holds.
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- When the connection was last PROVEN, by actually assuming the role and
    -- reading back the identity it produced. Distinct from updated_at, which any
    -- edit moves. NULL means never proven, which is not the same as broken.
    verified_at timestamptz,

    -- Why status is 'error', in the provider's own words. A connector that is
    -- broken without saying how is a support ticket.
    last_error text NOT NULL DEFAULT '',

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_connector_provider_chk CHECK (
        provider IN ('aws', 'gcp', 'azure')
    ),
    CONSTRAINT cloud_connector_scope_kind_chk CHECK (
        scope_kind IN ('account', 'project', 'folder', 'org', 'subscription')
    ),
    CONSTRAINT cloud_connector_status_chk CHECK (
        status IN ('active', 'revoked', 'error')
    ),
    CONSTRAINT cloud_connector_scope_id_chk CHECK (scope_id <> ''),
    -- An error state must carry its reason, and an active connector must carry
    -- the handle needed to authenticate. Both are enforced here rather than in
    -- Go because both are invariants of the row, not of one code path: a future
    -- scanner marking a connector errored has to supply a reason too.
    CONSTRAINT cloud_connector_error_chk CHECK (
        status <> 'error' OR last_error <> ''
    ),
    CONSTRAINT cloud_connector_auth_ref_chk CHECK (
        status <> 'active' OR auth_ref <> ''
    ),
    CONSTRAINT cloud_connector_scan_generation_chk CHECK (scan_generation >= 0)
);

-- One row per onboarded scope. Re-running onboarding for an account already
-- connected must UPDATE that row: a second row would split one account's
-- inventory in two and double every scan against it. This index is the conflict
-- target the upsert names.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_connector_scope
    ON public.cloud_connector (workspace_id, provider, scope_id);

-- The console's list query.
CREATE INDEX IF NOT EXISTS idx_cloud_connector_workspace
    ON public.cloud_connector (workspace_id, provider, status);

-- ---------------------------------------------------------------------------
-- DEVIATIONS FROM THE SHARED SCHEMA NOTE, recorded here so the schema owner can
-- accept or reject them rather than discover them.
-- ---------------------------------------------------------------------------
--
-- attrs jsonb -- ADDED. The shared note asks each provider whether anything
--   missing "belongs in attrs rather than as a new column". Three things do,
--   and AWS cannot be onboarded without them:
--
--     role_arn         the cross-account role AuthSec assumes. Not secret, and
--                      needed on every scan, so a column-adjacent jsonb key
--                      rather than a second secrets-store round trip.
--     regions          the operator-selected regions in scope. There is no
--                      region concept anywhere in the shared columns, and scan
--                      cost grows with regions x services, so the selection has
--                      to be recorded with the connector that made it.
--     caller_arn       what GetCallerIdentity returned when the connection was
--                      last proven. Evidence, not configuration.
--
--   A `regions text[]` column was rejected: it is meaningful to exactly one of
--   the three providers, which is the shape the shared note exists to prevent.
--
-- verified_at, last_error -- ADDED, and provider-neutral. `status` alone cannot
--   distinguish a connector that has never been proven from one proven an hour
--   ago, and 'error' with no reason is not actionable. All three connectors
--   need both; proposing them for the shared note rather than keeping them AWS-
--   only.
--
-- parent_scope_id stays NULLABLE, matching the note, against this repo's usual
--   `NOT NULL DEFAULT ''`. See the column comment.
