-- ============================================================================
-- 136: R3 runtime holds and budgets reference their policy, version and
-- resumed decision within their own workspace
--
-- 062 left iga_gov_runtime_hold.policy_id / version_id / resumed_decision_id
-- and iga_gov_runtime_budget.version_id as bare uuids, so a row could name
-- another workspace's policy, version or decision. They get composite keys
-- on (workspace_id, ...), the same shape 062 already uses for the budget's
-- policy and the budget entry's version. Added NOT VALID, then validated;
-- a row that already names another workspace's object leaves the key NOT
-- VALID (new rows are still checked) and is reported for review.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

DO $$
DECLARE
    k record;
BEGIN
    FOR k IN SELECT * FROM (VALUES
        ('iga_gov_runtime_hold', 'iga_gov_rth_policy_ws_fkey',
         'FOREIGN KEY (workspace_id, policy_id) REFERENCES public.iga_gov_policy (workspace_id, id) ON DELETE CASCADE'),
        ('iga_gov_runtime_hold', 'iga_gov_rth_version_ws_fkey',
         'FOREIGN KEY (workspace_id, version_id, policy_id) REFERENCES public.iga_gov_runtime_version (workspace_id, id, policy_id) ON DELETE CASCADE'),
        ('iga_gov_runtime_hold', 'iga_gov_rth_resumed_decision_ws_fkey',
         'FOREIGN KEY (workspace_id, resumed_decision_id) REFERENCES public.iga_gov_runtime_decision (workspace_id, id)'),
        ('iga_gov_runtime_budget', 'iga_gov_rtb_version_ws_fkey',
         'FOREIGN KEY (workspace_id, version_id, policy_id) REFERENCES public.iga_gov_runtime_version (workspace_id, id, policy_id) ON DELETE CASCADE')
    ) AS v(tbl, name, def)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = k.name) THEN
            EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I %s NOT VALID', k.tbl, k.name, k.def);
        END IF;
        BEGIN
            EXECUTE format('ALTER TABLE public.%I VALIDATE CONSTRAINT %I', k.tbl, k.name);
        EXCEPTION WHEN foreign_key_violation THEN
            RAISE NOTICE '136: % has rows naming another workspace''s object; % left NOT VALID for review', k.tbl, k.name;
        END;
    END LOOP;
END $$;
