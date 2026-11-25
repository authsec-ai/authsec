-- 193_agent_containment_proof_levels.sql
--
-- SecOps W2 (SPEC-secops-backend-upgrade.md P4, P13, C8, C9): proof states
-- and the new stop levels of agent_containment.
--
-- 1. Proof: proof_state (requested -> applied -> proven | unproven |
--    cannot_verify -> kept), the event that proved it (proven_by_event_id),
--    the source skew of that event (skew_ms: received minus event time) and
--    token_expiry_at, the latest time a credential issued before the stop
--    can still be live (role sessions 12 h + 1 h, IAM user session tokens
--    36 h, Entra app tokens 90 min, projected ServiceAccount tokens 1 h).
--    Existing rows are backfilled from verified_at / effective /
--    verification.unverifiable exactly as services.containProofState
--    computes it (agentcontain.ProofStateOf).
-- 2. Levels: key, sessions_before, chain, source_identity, entra,
--    kubernetes, gateway, platform beside workload, identity, model; the
--    identity kinds they act on; the state 'requested' (a platform stop by
--    ask: AuthSec writes nothing); the step kinds assumer_policy,
--    entra_account, azure_role_assignment, k8s_binding_subject.
-- 3. target: what the stop names within its identity (the access key id of
--    a key stop, the agent of a source_identity stop, the gateway subject),
--    so one user may have a live key stop per key. The one-live-per
--    (workspace, identity, level) index becomes (.., level, target).
-- 4. narrowed_from: the wider containment a narrower one replaces (it is
--    released only once the narrower one is proven).
--
-- CHECK changes are forward-only (drop and re-add, admitting every earlier
-- value). Idempotent. 001_bootstrap.sql carries the same block at its end.

ALTER TABLE public.agent_containment ADD COLUMN IF NOT EXISTS proof_state text NOT NULL DEFAULT 'requested';
ALTER TABLE public.agent_containment ADD COLUMN IF NOT EXISTS proven_by_event_id text;
ALTER TABLE public.agent_containment ADD COLUMN IF NOT EXISTS skew_ms bigint;
ALTER TABLE public.agent_containment ADD COLUMN IF NOT EXISTS token_expiry_at timestamptz;
ALTER TABLE public.agent_containment ADD COLUMN IF NOT EXISTS target text NOT NULL DEFAULT '';
ALTER TABLE public.agent_containment ADD COLUMN IF NOT EXISTS narrowed_from uuid;

ALTER TABLE public.agent_containment DROP CONSTRAINT IF EXISTS agent_containment_proof_state_check;
ALTER TABLE public.agent_containment ADD CONSTRAINT agent_containment_proof_state_check
  CHECK (proof_state IN ('requested','applied','proven','unproven','cannot_verify','kept'));

ALTER TABLE public.agent_containment DROP CONSTRAINT IF EXISTS agent_containment_level_check;
ALTER TABLE public.agent_containment ADD CONSTRAINT agent_containment_level_check
  CHECK (level IN ('workload','identity','model','key','sessions_before','chain','source_identity',
                   'entra','kubernetes','gateway','platform'));

ALTER TABLE public.agent_containment DROP CONSTRAINT IF EXISTS agent_containment_identity_kind_check;
ALTER TABLE public.agent_containment ADD CONSTRAINT agent_containment_identity_kind_check
  CHECK (identity_kind IN ('iam_role','iam_user','entra_service_principal','entra_agent_identity',
                           'k8s_service_account','gateway_agent','platform_principal'));

ALTER TABLE public.agent_containment DROP CONSTRAINT IF EXISTS agent_containment_state_check;
ALTER TABLE public.agent_containment ADD CONSTRAINT agent_containment_state_check
  CHECK (state IN ('previewed','requested','containing','contained','partially_contained','failed','releasing','released'));

ALTER TABLE public.agent_containment_step DROP CONSTRAINT IF EXISTS agent_containment_step_kind_check;
ALTER TABLE public.agent_containment_step ADD CONSTRAINT agent_containment_step_kind_check
  CHECK (kind IN ('lambda_concurrency','ecs_desired','ecs_autoscaling','iam_policy','session_revoke','access_key',
                  'assumer_policy','entra_account','azure_role_assignment','k8s_binding_subject'));

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_containment_narrowed_from_fkey'
                     AND conrelid = 'public.agent_containment'::regclass) THEN
        ALTER TABLE public.agent_containment ADD CONSTRAINT agent_containment_narrowed_from_fkey
          FOREIGN KEY (workspace_id, narrowed_from) REFERENCES public.agent_containment (workspace_id, id);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_agent_containment_narrowed_from ON public.agent_containment (workspace_id, narrowed_from)
  WHERE narrowed_from IS NOT NULL;

-- One live containment per (workspace, identity, level, target).
DROP INDEX IF EXISTS public.uq_agent_containment_live;
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_containment_live ON public.agent_containment (workspace_id, identity_id, level, target)
  WHERE state IN ('previewed','requested','containing','contained','partially_contained','releasing');

-- Backfill the proof columns of the rows written before 193.
UPDATE public.agent_containment c SET
  proof_state = CASE
    WHEN c.state IN ('previewed','requested','containing','failed') THEN 'requested'
    WHEN c.state = 'released' AND (c.pending_restore_at IS NOT NULL OR EXISTS (
           SELECT 1 FROM public.agent_containment_step s
            WHERE s.workspace_id = c.workspace_id AND s.containment_id = c.id
              AND s.kind = 'access_key' AND s.after->>'rotate_required' = 'true')) THEN 'kept'
    WHEN c.verified_at IS NOT NULL AND c.effective IS TRUE THEN 'proven'
    WHEN c.effective IS FALSE THEN 'unproven'
    WHEN c.verification->'unverifiable'->>'final' = 'true' THEN 'cannot_verify'
    WHEN c.verification ? 'unverifiable' THEN 'unproven'
    WHEN c.state = 'released' THEN 'unproven'
    ELSE 'applied' END,
  proven_by_event_id = NULLIF(c.verification->'proof'->>'event_id', ''),
  token_expiry_at = CASE
    WHEN c.level IN ('identity','model') AND c.identity_kind = 'iam_role'
      THEN date_trunc('second', c.created_at) + interval '13 hours'
    WHEN c.level IN ('identity','model') AND c.identity_kind = 'iam_user'
      THEN date_trunc('second', c.created_at) + interval '36 hours'
    ELSE NULL END
WHERE c.proof_state = 'requested' AND c.proven_by_event_id IS NULL AND c.token_expiry_at IS NULL;
