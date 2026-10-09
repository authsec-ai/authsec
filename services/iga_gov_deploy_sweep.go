package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Stuck in-flight deployments (review P1-5; SPEC-iga-phase3-policy.md §8.1,
// §8.4). A deployment in queued, applying or outcome_unknown holds its role
// (uq_iga_gov_deployment_inflight) and moves only through its job: deploy
// for queued / applying, resolve_unknown for outcome_unknown. Two things
// could leave it holding the role with no job ever to move it:
//
//   - the job EXHAUSTED its attempts (repeated handler errors, or a lease
//     that lapsed at the ceiling): the job is terminal `failed`;
//   - the job is GONE (a crash between two transactions that should have
//     enqueued it, a job completed while the deployment was still in
//     flight).
//
// settleStuck decides, with the deployment row locked and no open job for it:
//
//	no open job, latest job not failed     -> the right job re-enqueued
//	                                          (deployment.job_requeued)
//	deploy exhausted, queued               -> failed (nothing was sent)
//	deploy exhausted, applying             -> the §8.1 replacement rule first
//	                                          (RecoverTx): a dispatched attempt
//	                                          becomes unknown -> outcome_unknown
//	                                          and resolve_unknown at
//	                                          settle_after, never re-sent;
//	                                          then, when AWS was never touched
//	                                          (no op done, nothing dispatched)
//	                                          -> failed; otherwise
//	                                          -> outcome_unresolved
//	resolve_unknown exhausted              -> outcome_unresolved
//
// DECISION (P1-5): an exhausted deploy job that may have changed AWS (an op
// done or a request dispatched) does NOT release the role: the deployment
// becomes outcome_unresolved -- the §8.1 step 3 operator state, which holds
// the role and offers Re-read, Accept observed state and Emergency undo
// (POST /deployments/:id/resolve) -- because the role's boundary may be
// half-way between the plan's precondition and its post-state, and only an
// operator (or the deploy job a Re-read restarts) can establish which.
// outcome_unknown_op names the first op not done ("readback" when every op
// is done) and settle_after is the moment of the decision (051's
// iga_gov_pd_unknown_chk requires both). A deployment that never touched
// AWS fails (§8.4 terminal), settling its intended ledger rows, and releases
// the role.
//
// The same transitions run from the worker's exhaustion hook (immediately)
// and from the sweeper (SweepStuckDeployments, every DeploySweepEvery; the
// safety net when the hook could not run).

// DeploySweepEvery is how often the stuck-deployment sweeper runs, and the
// least time between two re-enqueues of the same deployment's job.
const DeploySweepEvery = 2 * time.Minute

// deploySweepGrace is how long a deployment must have been unchanged before
// the sweeper looks at it (a deployment created a moment ago may still be
// getting its job in another transaction).
const deploySweepGrace = 2 * time.Minute

// Reasons and event names of this file.
const (
	DepReasonDeployJobExhausted  = "deploy_job_exhausted"
	DepReasonResolveJobExhausted = "resolve_job_exhausted"
	DepReasonOperatorDeclared    = "operator_declared_stuck"
	GovEventDeploymentRequeued   = "deployment.job_requeued"
	GovCodeDeployJobRunning      = "deploy_job_running"
)

// Stuck actions (what settleStuck did).
const (
	StuckNone           = "none"
	StuckHasJob         = "has_job"
	StuckRequeued       = "requeued"
	StuckWaiting        = "waiting"
	StuckFailed         = "failed"
	StuckOutcomeUnknown = "outcome_unknown"
	StuckUnresolved     = "outcome_unresolved"
)

// onJobExhausted is the deploy and resolve_unknown kinds' OnExhausted hook.
func (s *GovDeployments) onJobExhausted(ctx context.Context, job models.IGAGovJob, lastError string) {
	if job.SubjectID == nil {
		return
	}
	act, err := s.settleStuck(ctx, job.WorkspaceID, *job.SubjectID, lastError)
	if err != nil {
		log.Printf("[policy-worker] %s %s exhausted; settling deployment %s: %v (the sweeper retries)", job.Kind, job.ID, *job.SubjectID, err)
		return
	}
	log.Printf("[policy-worker] %s %s exhausted; deployment %s: %s", job.Kind, job.ID, *job.SubjectID, act)
}

// SweepStuckDeployments settles every in-flight deployment that has no open
// job (see the file comment). It returns what it did per deployment.
func (s *GovDeployments) SweepStuckDeployments(ctx context.Context) (map[uuid.UUID]string, error) {
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	if err := s.db.WithContext(ctx).Raw(`
		SELECT d.workspace_id, d.id FROM iga_gov_deployment d
		 WHERE d.state IN ('queued','applying','outcome_unknown') AND d.updated_at < ?
		   AND NOT EXISTS (SELECT 1 FROM iga_gov_job j WHERE j.workspace_id = d.workspace_id
		                     AND j.dedupe_key = 'deployment:' || d.id::text AND j.status IN ('queued','running'))
		 ORDER BY d.updated_at`, s.now().Add(-deploySweepGrace)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[uuid.UUID]string{}
	var first error
	for _, r := range rows {
		act, err := s.settleStuck(ctx, r.WorkspaceID, r.ID, "")
		if err != nil {
			if first == nil {
				first = fmt.Errorf("deployment %s: %w", r.ID, err)
			}
			continue
		}
		out[r.ID] = act
	}
	return out, first
}

// jobKindFor is the job that moves a deployment in state, "" for none.
func jobKindFor(state string) string {
	switch state {
	case models.GovDeployQueued, models.GovDeployApplying:
		return repositories.GovJobDeploy
	case models.GovDeployOutcomeUnknown:
		return repositories.GovJobResolveUnknown
	}
	return ""
}

// lockDeploymentTx locks the deployment's control, then the deployment (the
// shared lock order: control -> deployment/artifact -> posture -> findings).
func lockDeploymentTx(tx *gorm.DB, ws, id uuid.UUID) (*models.IGAGovDeployment, error) {
	var ctl []uuid.UUID
	if err := tx.Raw(`SELECT control_id FROM iga_gov_deployment WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&ctl).Error; err != nil {
		return nil, err
	}
	if len(ctl) == 0 {
		return nil, GovNotFound()
	}
	if err := tx.Exec(`SELECT id FROM iga_gov_control WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, ctl[0]).Error; err != nil {
		return nil, err
	}
	var d models.IGAGovDeployment
	if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Clauses(lockForUpdate()).Take(&d).Error; err != nil {
		return nil, err
	}
	return &d, nil
}

// openJobs counts the deployment's open jobs (any kind), and its running ones.
func openJobs(tx *gorm.DB, ws, id uuid.UUID) (open, running int64, err error) {
	var row struct{ Open, Running int64 }
	err = tx.Raw(`SELECT count(*) AS open, count(*) FILTER (WHERE status = 'running') AS running FROM iga_gov_job
		WHERE workspace_id = ? AND dedupe_key = ? AND status IN ('queued','running')`, ws, "deployment:"+id.String()).Scan(&row).Error
	return row.Open, row.Running, err
}

// settleStuck applies the file comment's table to one deployment.
func (s *GovDeployments) settleStuck(ctx context.Context, ws, id uuid.UUID, lastError string) (string, error) {
	act := StuckNone
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		d, err := lockDeploymentTx(tx, ws, id)
		if err != nil {
			return err
		}
		kind := jobKindFor(d.State)
		if kind == "" {
			return nil
		}
		open, _, err := openJobs(tx, ws, d.ID)
		if err != nil {
			return err
		}
		if open > 0 {
			act = StuckHasJob
			return nil
		}
		var last []models.IGAGovJob
		if err := tx.Where("workspace_id = ? AND kind = ? AND dedupe_key = ?", ws, kind, "deployment:"+d.ID.String()).
			Order("created_at DESC, id DESC").Limit(1).Find(&last).Error; err != nil {
			return err
		}
		if len(last) == 0 || last[0].Status != models.GovJobFailed {
			at := s.now()
			if kind == repositories.GovJobResolveUnknown && d.SettleAfter != nil && d.SettleAfter.After(at) {
				at = *d.SettleAfter
			}
			sid := d.ID
			created, err := repositories.NewIGAGovJobRepository(tx).EnqueuePeriodicTx(tx, &models.IGAGovJob{WorkspaceID: ws, Kind: kind,
				SubjectID: &sid, DedupeKey: "deployment:" + d.ID.String(), RunAfter: at}, DeploySweepEvery)
			if err != nil {
				return err
			}
			if !created {
				act = StuckWaiting // its job completed moments ago; the next sweep re-enqueues it
				return nil
			}
			act = StuckRequeued
			prev := "none"
			if len(last) == 1 {
				prev = last[0].Status
			}
			return s.event(tx, *d, GovEventDeploymentRequeued, map[string]any{"kind": kind, "state": d.State,
				"previous_job_status": prev, "run_after": at,
				"reason": "the deployment was in flight with no open job; its job was queued again"})
		}
		if lastError == "" {
			lastError = last[0].LastError
		}
		act, err = s.exhaustedTx(tx, d, kind, lastError)
		return err
	})
	return act, err
}

// exhaustedTx moves a deployment whose job (kind) exhausted its attempts.
func (s *GovDeployments) exhaustedTx(tx *gorm.DB, d *models.IGAGovDeployment, kind, lastError string) (string, error) {
	lastError = truncate(lastError, 1000)
	switch d.State {
	case models.GovDeployQueued:
		return StuckFailed, s.failTx(tx, d, DepReasonDeployJobExhausted,
			"The deploy job exhausted its attempts before the deployment started; nothing was sent: "+lastError)
	case models.GovDeployOutcomeUnknown:
		return StuckUnresolved, s.declareUnresolvedTx(tx, d, DepReasonResolveJobExhausted,
			"The unknown outcome could not be resolved: resolve_unknown exhausted its attempts: "+lastError, models.GovActorSystem, "policy-worker")
	case models.GovDeployApplying:
	default:
		return StuckNone, nil
	}
	rec, err := s.attempts.RecoverTx(tx, d.WorkspaceID, d.ID)
	if err != nil {
		return "", err
	}
	switch rec.Action {
	case RecoveryOutcomeUnknown, RecoveryHold:
		at, err := s.ensureOutcomeUnknownTx(tx, d, rec)
		if err != nil {
			return "", err
		}
		return StuckOutcomeUnknown, enqueueJobTx(tx, d.WorkspaceID, repositories.GovJobResolveUnknown, d.ID, at)
	}
	touched, err := deploymentTouchedAWS(tx, *d)
	if err != nil {
		return "", err
	}
	if !touched {
		return StuckFailed, s.failTx(tx, d, DepReasonDeployJobExhausted,
			"The deploy job exhausted its attempts; no request was ever sent for this deployment: "+lastError)
	}
	return StuckUnresolved, s.declareUnresolvedTx(tx, d, DepReasonDeployJobExhausted,
		"The deploy job exhausted its attempts after changing AWS; the role is held for the operator: "+lastError,
		models.GovActorSystem, "policy-worker")
}

// ensureOutcomeUnknownTx makes sure a deployment whose attempt is unknown is
// outcome_unknown (RecoverTx moved an applying one; a held attempt on an
// applying deployment is moved here) and returns its settle_after.
func (s *GovDeployments) ensureOutcomeUnknownTx(tx *gorm.DB, d *models.IGAGovDeployment, rec *AttemptRecovery) (time.Time, error) {
	var cur models.IGAGovDeployment
	if err := tx.Where("id = ?", d.ID).Take(&cur).Error; err != nil {
		return time.Time{}, err
	}
	if cur.State == models.GovDeployOutcomeUnknown && cur.SettleAfter != nil {
		*d = cur
		return *cur.SettleAfter, nil
	}
	at := s.now()
	if rec.Attempt != nil && rec.Attempt.SignedAt != nil {
		at = rec.Attempt.SignedAt.Add(s.attempts.settle())
	}
	op := "unknown"
	if rec.Attempt != nil {
		op = fmt.Sprintf("%d:%s", rec.Attempt.OpSeq, rec.Attempt.Operation)
	}
	if err := setStateTx(tx, cur, []string{models.GovDeployApplying}, map[string]any{"state": models.GovDeployOutcomeUnknown,
		"outcome_unknown_op": op, "settle_after": at, "state_reason": "an unknown attempt holds the role"}); err != nil {
		return time.Time{}, err
	}
	d.State = models.GovDeployOutcomeUnknown
	return at, nil
}

// deploymentTouchedAWS reports whether the deployment may have changed AWS:
// an op recorded done, or any attempt that was dispatched.
func deploymentTouchedAWS(tx *gorm.DB, d models.IGAGovDeployment) (bool, error) {
	var row struct {
		Ops  int64
		Sent int64
	}
	err := tx.Raw(`SELECT jsonb_array_length(completed_ops) AS ops,
		(SELECT count(*) FROM iga_gov_attempt a WHERE a.workspace_id = d.workspace_id AND a.deployment_id = d.id AND a.dispatched_at IS NOT NULL) AS sent
		FROM iga_gov_deployment d WHERE d.workspace_id = ? AND d.id = ?`, d.WorkspaceID, d.ID).Scan(&row).Error
	return row.Ops > 0 || row.Sent > 0, err
}

// failTx is stop(failed) inside the caller's transaction (no job fence: the
// caller proved no job runs the deployment).
func (s *GovDeployments) failTx(tx *gorm.DB, d *models.IGAGovDeployment, code, msg string) error {
	if err := setStateTx(tx, *d, []string{models.GovDeployQueued, models.GovDeployApplying}, map[string]any{
		"state": models.GovDeployFailed, "state_reason": truncate(code+": "+msg, 2000)}); err != nil {
		return err
	}
	if err := s.settleLedgerTx(tx, *d); err != nil {
		return err
	}
	d.State = models.GovDeployFailed
	return s.event(tx, *d, GovEventDeploymentFailed, map[string]any{"code": code, "message": msg})
}

// nextOpTx names the first op of the deployment's plan not recorded done
// ("<op_seq>:<op>"), or "readback" when every op is done.
func nextOpTx(tx *gorm.DB, d models.IGAGovDeployment) (string, error) {
	p, err := LoadIGAGovPlan(tx, d.WorkspaceID, d.PlanID)
	if err != nil {
		return "", err
	}
	var cur struct{ CompletedOps json.RawMessage }
	if err := tx.Raw(`SELECT completed_ops FROM iga_gov_deployment WHERE id = ?`, d.ID).Scan(&cur).Error; err != nil {
		return "", err
	}
	var done []struct {
		OpSeq   int    `json:"op_seq"`
		Outcome string `json:"outcome"`
	}
	_ = json.Unmarshal(cur.CompletedOps, &done)
	did := map[int]bool{}
	for _, o := range done {
		if OpDone(o.Outcome) {
			did[o.OpSeq] = true
		}
	}
	for k, op := range p.Ops {
		if !did[k] {
			return fmt.Sprintf("%d:%s", k, op.Op), nil
		}
	}
	return "readback", nil
}

// declareUnresolvedTx moves an applying or outcome_unknown deployment to
// outcome_unresolved (§8.1 step 3: it keeps holding the role; the operator
// chooses Re-read, Accept observed state or Emergency undo).
func (s *GovDeployments) declareUnresolvedTx(tx *gorm.DB, d *models.IGAGovDeployment, cause, detail, actorKind, actorID string) error {
	set := map[string]any{"state": models.GovDeployOutcomeUnresolved, "state_reason": truncate(cause+": "+detail, 2000)}
	// From applying, outcome_unknown_op / settle_after may still hold an
	// earlier, already resolved unknown op: they are rewritten to this
	// decision's (the first op not done, now).
	if d.State == models.GovDeployApplying || d.OutcomeUnknownOp == "" {
		op, err := nextOpTx(tx, *d)
		if err != nil {
			return err
		}
		set["outcome_unknown_op"] = op
	}
	if d.State == models.GovDeployApplying || d.SettleAfter == nil {
		set["settle_after"] = s.now()
	}
	from := d.State
	if err := setStateTx(tx, *d, []string{models.GovDeployApplying, models.GovDeployOutcomeUnknown}, set); err != nil {
		return err
	}
	d.State = models.GovDeployOutcomeUnresolved
	pol, _, err := s.policyOfVersion(tx, d.WorkspaceID, d.VersionID)
	if err != nil {
		return err
	}
	return appendGovEvent(tx, d.WorkspaceID, GovEventDeploymentUnresolved, actorKind, actorID, depRefs(*d, pol), map[string]any{
		"cause": cause, "detail": detail, "from_state": from,
		"choices":     []string{"reread", "accept_observed", "emergency_undo"},
		"assigned_to": "the policy owner and every holder of governance:enforce"})
}

/* ------------------------- operator: a stuck applying ------------------------ */

// resolveApplying is POST /deployments/:id/resolve on an `applying`
// deployment (review P1-5: "an operator path for a stuck applying", §8.1
// step 3's choices, §7.6). It is refused (409 deploy_job_running) while a
// job holds the deployment's lease: a running deploy job may be about to send.
//
//   - reread: the deploy job is (re)queued now -- a fresh attempt budget; it
//     starts with the §8.1 replacement rule and re-reads live state;
//   - accept_observed / emergency_undo: the queued deploy job is abandoned,
//     the replacement rule runs (a dispatched attempt becomes unknown: the
//     deployment is outcome_unknown and the answer is 409
//     outcome_unknown_pending), and the deployment is declared
//     outcome_unresolved -- it keeps holding the role -- so the choice then
//     proceeds exactly as for an unresolved outcome (the atomic handoff).
func (s *GovDeployments) resolveApplying(ctx context.Context, d models.IGAGovDeployment, actor uuid.UUID, req GovResolveRequest) error {
	ws := d.WorkspaceID
	k, a := userActor(actor)
	var pending *time.Time
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		cur, err := lockDeploymentTx(tx, ws, d.ID)
		if err != nil {
			return err
		}
		if cur.State != models.GovDeployApplying {
			return govConflict(GovCodeNotUnresolved, "The deployment moved meanwhile.", map[string]any{"state": cur.State})
		}
		_, running, err := openJobs(tx, ws, cur.ID)
		if err != nil {
			return err
		}
		if running > 0 {
			return govConflict(GovCodeDeployJobRunning, "A job is running this deployment now; wait for it to finish or for its lease to lapse.",
				map[string]any{"deployment_id": cur.ID})
		}
		pol, _, err := s.policyOfVersion(tx, ws, cur.VersionID)
		if err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventDeploymentResolveReq, k, a, depRefs(*cur, pol),
			map[string]any{"action": req.Action, "reason": req.Reason, "from_state": cur.State}); err != nil {
			return err
		}
		if req.Action == "reread" {
			res := tx.Exec(`UPDATE iga_gov_job SET run_after = ? WHERE workspace_id = ? AND kind = ? AND dedupe_key = ? AND status = 'queued'`,
				s.now(), ws, repositories.GovJobDeploy, "deployment:"+cur.ID.String())
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected > 0 {
				return nil
			}
			return enqueueJobTx(tx, ws, repositories.GovJobDeploy, cur.ID, s.now())
		}
		if err := tx.Exec(`UPDATE iga_gov_job SET status = 'abandoned', completed_at = now(), last_error = ?
			WHERE workspace_id = ? AND dedupe_key = ? AND status = 'queued'`,
			"abandoned: an operator declared the deployment stuck ("+req.Action+")", ws, "deployment:"+cur.ID.String()).Error; err != nil {
			return err
		}
		rec, err := s.attempts.RecoverTx(tx, ws, cur.ID)
		if err != nil {
			return err
		}
		if rec.Action == RecoveryOutcomeUnknown || rec.Action == RecoveryHold {
			at, err := s.ensureOutcomeUnknownTx(tx, cur, rec)
			if err != nil {
				return err
			}
			pending = &at
			return enqueueJobTx(tx, ws, repositories.GovJobResolveUnknown, cur.ID, at)
		}
		return s.declareUnresolvedTx(tx, cur, DepReasonOperatorDeclared, strings.TrimSpace(req.Reason), k, a)
	})
	if errors.Is(err, errStateMoved) {
		return govConflict(GovCodeNotUnresolved, "The deployment moved meanwhile.", nil)
	}
	if err != nil {
		return err
	}
	if pending != nil {
		return govConflict(GovCodeOutcomeUnknownPending, "A request of this deployment was dispatched without an answer; its outcome is established first.",
			map[string]any{"settle_after": pending})
	}
	return nil
}

// rereadWithoutAttemptTx restarts an unresolved deployment that has no
// unresolved unknown attempt (an exhausted deploy job, or an operator's
// declaration): back to applying, the deploy job queued; the deploy job
// starts with the §8.1 replacement rule and re-reads live state.
func (s *GovDeployments) rereadWithoutAttemptTx(tx *gorm.DB, d models.IGAGovDeployment) error {
	if err := setStateTx(tx, d, []string{models.GovDeployOutcomeUnresolved, models.GovDeployOutcomeUnknown}, map[string]any{
		"state": models.GovDeployApplying, "state_reason": "re-read requested: no unknown request is open; the deploy job re-reads live state"}); err != nil {
		return err
	}
	return enqueueJobTx(tx, d.WorkspaceID, repositories.GovJobDeploy, d.ID, s.now())
}
