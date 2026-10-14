-- 138_cloud_connector_azure_tenant_scope.sql — an Entra tenant is a scope.
--
-- expand only. Widens cloud_connector_scope_kind_chk to admit 'tenant'.
--
-- WHY A TENANT ROW, NOT ONLY SUBSCRIPTION ROWS
-- 010 anticipated Azure as "a subscription with its tenant in
-- parent_scope_id". That covers the Azure RBAC half of onboarding: each
-- subscription carries its own Reader assignment and its own inventory. It
-- does not cover the Microsoft Graph half. Admin consent grants the AuthSec
-- service principal directory read access in the TENANT, independently of any
-- subscription -- a tenant with no subscriptions at all is still a complete
-- Entra connection -- and the two halves fail separately (consent revoked
-- while every subscription still has Reader, or the reverse). Folding the
-- Graph state into every subscription row would duplicate it N times and
-- leave a subscription-less tenant with nowhere to record it.
--
-- So one Azure tenant onboards as one scope_kind='tenant' row (scope_id = the
-- tenant id, parent_scope_id NULL) plus one scope_kind='subscription' row per
-- subscription (parent_scope_id = the tenant id). Tenant and subscription ids
-- are distinct GUIDs, so uq_cloud_connector_scope keeps both unique within a
-- workspace.
--
-- No data changes: no existing row has scope_kind 'tenant', and every value
-- the old CHECK admitted is still admitted.

ALTER TABLE public.cloud_connector
    DROP CONSTRAINT IF EXISTS cloud_connector_scope_kind_chk;

ALTER TABLE public.cloud_connector
    ADD CONSTRAINT cloud_connector_scope_kind_chk CHECK (
        scope_kind IN ('account', 'project', 'folder', 'org', 'subscription', 'tenant')
    );

-- verify ----------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'cloud_connector_scope_kind_chk'
           AND pg_get_constraintdef(oid) LIKE '%tenant%'
    ) THEN
        RAISE EXCEPTION '138: cloud_connector_scope_kind_chk does not admit tenant';
    END IF;
END $$;
