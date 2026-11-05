-- 152_agent_containment_live_target.sql
--
-- One live containment per target (SPEC-agent-runtime-visibility.md §5.8).
--
-- A step records the target's exact before-state before AuthSec writes. When
-- two live containments hold the same target (the same Lambda function, ECS
-- service, scaling target or access key), the second records the first's
-- change (concurrency 0, desired count 0) as its "before", and releasing in
-- the wrong order restores a contained state. The partial unique index below
-- makes that impossible: a step is LIVE while it holds a change that is not
-- yet restored (pending, applied, restoring, restore_failed). A failed or
-- skipped step changed nothing and holds nothing; a restored one has let go.
--
-- The containment job maps the violation to a failed step that names the
-- holding containment ("target already held by containment <id>").
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same index.

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_containment_step_live_target
  ON agent_containment_step (workspace_id, kind, target)
  WHERE state IN ('pending','applied','restoring','restore_failed');
