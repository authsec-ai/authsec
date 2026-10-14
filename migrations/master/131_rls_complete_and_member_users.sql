-- ============================================================================
-- 131: row-level security on every workspace table; members' user rows
--
-- 1. 111 enabled RLS on the tables that had workspace_id when it ran. A table
--    created by a migration that sorts before 111 but was applied after it
--    (047-059 on a database built from the tenancy branch before it merged
--    authsec-staging) was left without the policy. Every public table with a
--    workspace_id column and no tenancy_isolation policy gets it now.
--    Idempotent; a table that already has the policy is not touched.
--
-- 2. An operator may hold memberships in workspaces other than their home one
--    (ADR-0001 §3). Under RLS a workspace saw only the users homed in it, so
--    such a member vanished from every member read of that workspace (owner
--    rules, reviews, approvals). The users table gains a second, SELECT-only
--    policy: a user row is readable in a workspace that has a membership row
--    for it. Writes stay limited to the home workspace (tenancy_isolation's
--    WITH CHECK); the membership subquery is itself under RLS, so it sees
--    only the current workspace's memberships.
--
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
DECLARE
    t regclass;
BEGIN
    FOR t IN
        SELECT c.oid::regclass
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
           AND NOT EXISTS (SELECT 1 FROM pg_policies p
                            WHERE p.schemaname = 'public' AND p.tablename = c.relname
                              AND p.policyname = 'tenancy_isolation')
         ORDER BY 1
    LOOP
        PERFORM public.tenancy_enable_rls(t);
    END LOOP;
END $$;

DROP POLICY IF EXISTS tenancy_member_users ON public.users;
CREATE POLICY tenancy_member_users ON public.users
    FOR SELECT
    USING (EXISTS (SELECT 1 FROM public.workspace_memberships m
                    WHERE m.user_id = users.id
                      AND m.workspace_id = public.tenancy_current_workspace()));
