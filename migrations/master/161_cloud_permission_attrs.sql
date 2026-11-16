-- ============================================================================
-- 161: GCP-3 -- provenance column on cloud_permission, and an unresolved-role
-- exception to the actions-present rule.
--
-- attrs: provider-specific detail that has no column of its own. GCP writes the
-- attachment point, the ancestor chain, the raw binding, the read time and the
-- parsed condition bounds here. AWS and Azure rows simply carry {}.
--
-- actions_present: a grant must say which actions it is about, through actions
-- or not_actions. A GCP binding to a custom role that was deleted, or to a basic
-- role stored unexpanded, names its role and has no expanded permission list. A
-- row that names a role is therefore allowed to have none. AWS rows never set
-- role_name, so for them the rule is unchanged.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same definitions.
-- ============================================================================

ALTER TABLE public.cloud_permission
    ADD COLUMN IF NOT EXISTS attrs jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN public.cloud_permission.attrs IS
    'Provider-specific provenance (GCP: attached_to, gcp_scope_kind, ancestors, binding_raw, read_time, expires_at, starts_at, role_unresolved, basic_role). {} for AWS and Azure.';

ALTER TABLE public.cloud_permission
    DROP CONSTRAINT IF EXISTS cloud_permission_actions_present_chk;

ALTER TABLE public.cloud_permission
    ADD CONSTRAINT cloud_permission_actions_present_chk
    CHECK (
        COALESCE(array_length(actions, 1), 0) > 0
        OR COALESCE(array_length(not_actions, 1), 0) > 0
        OR role_name IS NOT NULL
    );
