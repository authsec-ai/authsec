-- 195_agent_containment_hold_case_fk.sql
--
-- A containment hold names the case that holds the stop (194). agent_case
-- (186) is now on the same branch, so the case reference becomes a foreign
-- key within the workspace: a hold can only name a case of its own
-- workspace. W2 shipped holds before cases existed on its branch; no
-- deployed database has rows in agent_containment_hold yet.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_containment_hold_case_fk') THEN
        ALTER TABLE public.agent_containment_hold
            ADD CONSTRAINT agent_containment_hold_case_fk
            FOREIGN KEY (workspace_id, case_id) REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_agent_containment_hold_case ON public.agent_containment_hold (workspace_id, case_id);
