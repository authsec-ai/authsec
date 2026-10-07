package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// IGAGovAttemptLog is §8.1's write-ahead attempt lifecycle, as one reusable
// component the AWS enforcement adapter (T3.10) calls around every mutating
// call. Every step is its own committed transaction, fenced on the job lease
// (PolicyJobRun.InTx: the job row locked and the fence proven first), and the
// table's trigger iga_gov_attempt_transition refuses any other order:
//
//  1. Prepare  -> `prepared`: operation, op_seq, attempt_no, lease_version,
//     request_hash, document_hash. Nothing has been sent; the prepared
//     request is immutable from here on (trigger).
//  2. Dispatch -> `dispatched`: signed_at and dispatched_at, committed
//     IMMEDIATELY BEFORE the call, and only with at least Margin (60 s) of
//     lease left (else ErrPolicyJobLeaseShort and nothing is sent).
//  3. Complete -> `completed` with the outcome, request id and error code,
//     and the op recorded in the deployment's completed_ops, in ONE
//     transaction; or MarkUnknown -> `unknown` when no answer was recorded,
//     with the deployment moved to outcome_unknown and settle_after =
//     signed_at + 15 min, in one transaction.
//
// A replacement worker calls Recover before doing anything on a deployment:
// a `prepared` attempt is `abandoned` (it was never sent; re-prepare as
// attempt_no + 1), a `dispatched` one becomes `unknown` and the deployment
// outcome_unknown -- it is NEVER re-sent -- and an unresolved `unknown` one
// holds the role.
//
// Execute runs 1-3 around an operation: the caller supplies the call; the
// log owns the bookkeeping, the lease margin and the timeout. A call that
// gives no definitive answer (timeout, connection reset, cancelled context,
// any error) is `unknown`, never retried here: a retry is a NEW attempt and
// is allowed only after a definitive answer proved the first was not applied
// (outcome `retryable`, §8.5).
type IGAGovAttemptLog struct {
	db     *gorm.DB
	events repositories.IGAGovEventRepository
	now    func() time.Time

	// Margin is the least lease an attempt may be dispatched with; default
	// PolicyJobExternalMargin (60 s).
	Margin time.Duration
	// CallTimeout bounds one call in Execute; default 30 s. It is the
	// client-side timeout §8.1 says proves nothing about AWS.
	CallTimeout time.Duration
	// SettleWindow is settle_after - signed_at (§8.1 step 1); default 15 min.
	SettleWindow time.Duration
}

// Attempt outcomes (051 iga_gov_attempt.outcome, §8.5).
const (
	AttemptOutcomeOK             = "ok"
	AttemptOutcomeRetryable      = "retryable"
	AttemptOutcomeTerminal       = "terminal"
	AttemptOutcomeRecognisedDone = "recognised_done"
	AttemptOutcomeNotNeeded      = "not_needed"
)

// Resolutions of an unknown attempt (§8.1 step 2).
const (
	AttemptResolvedApplied    = "applied"
	AttemptResolvedNotApplied = "not_applied"
)

// DefaultAttemptSettleWindow is §8.1's settle bound after signing: AWS
// accepts a signed request for about 5 minutes, and the enforcement session
// expires 15 minutes after issue.
const DefaultAttemptSettleWindow = 15 * time.Minute

var (
	// ErrAttemptOpen: the deployment already has an open attempt (prepared,
	// dispatched, or unknown and unresolved; uq_iga_gov_attempt_open). Call
	// Recover first.
	ErrAttemptOpen = errors.New("the deployment already has an open attempt")
	// ErrAttemptState: the attempt is not in the state this step needs (for
	// example Complete on an attempt a replacement already marked unknown),
	// or was prepared under another lease version.
	ErrAttemptState = errors.New("the attempt is not in the state this step needs")
	// ErrOutcomeUnknownPending is §7.12's outcome_unknown_pending: an earlier
	// mutation on this deployment has no established outcome; nothing may be
	// sent until it is resolved.
	ErrOutcomeUnknownPending = errors.New("outcome_unknown_pending: an earlier mutation has no established outcome")
)

// AttemptRequest is the immutable prepared request.
type AttemptRequest struct {
	WorkspaceID  uuid.UUID
	DeploymentID uuid.UUID
	OpSeq        int
	Operation    string
	// RequestHash is sha256 of the canonical request parameters (the caller
	// computes it, igagov canonical form).
	RequestHash string
	// DocumentHash is the policy document the request carries, "" for none;
	// it must already be in iga_gov_document (FK).
	DocumentHash string
}

// AttemptAnswer is a DEFINITIVE answer from the external service, already
// classified by the caller (§8.5): ok, retryable, terminal, recognised_done
// or not_needed.
type AttemptAnswer struct {
	Outcome      string
	RequestID    string
	ErrorCode    string
	ErrorMessage string
}

// AttemptCall makes the external call. Return (answer, nil) for ANY
// definitive response, error responses included (classified into
// answer.Outcome). Return a non-nil error when there is NO definitive
// answer: timeout, connection error, a 5xx/ServiceFailure on a mutating call
// -- anything after which the request may or may not have been applied. The
// call must honour ctx; one that does not is abandoned at the timeout and its
// late answer discarded.
type AttemptCall func(ctx context.Context) (AttemptAnswer, error)

// AttemptResult is what Execute established.
type AttemptResult struct {
	Attempt models.IGAGovAttempt
	// Answer is set when the call answered definitively.
	Answer *AttemptAnswer
	// Unknown is true when no answer was recorded: the deployment is now
	// outcome_unknown until SettleAfter (§8.1).
	Unknown     bool
	SettleAfter *time.Time
	// CallErr is the call's own error when Unknown.
	CallErr error
}

// NewIGAGovAttemptLog builds the attempt log over db.
func NewIGAGovAttemptLog(db *gorm.DB) *IGAGovAttemptLog {
	return &IGAGovAttemptLog{db: db, events: repositories.NewIGAGovEventRepository(db), now: time.Now}
}

// WithClock replaces the clock (tests).
func (l *IGAGovAttemptLog) WithClock(now func() time.Time) *IGAGovAttemptLog {
	l.now = now
	return l
}

func (l *IGAGovAttemptLog) margin() time.Duration {
	if l.Margin > 0 {
		return l.Margin
	}
	return PolicyJobExternalMargin
}

func (l *IGAGovAttemptLog) settle() time.Duration {
	if l.SettleWindow > 0 {
		return l.SettleWindow
	}
	return DefaultAttemptSettleWindow
}

func (l *IGAGovAttemptLog) callTimeout() time.Duration {
	if l.CallTimeout > 0 {
		return l.CallTimeout
	}
	return 30 * time.Second
}

// Prepare commits step 1. attempt_no is one more than the highest for
// (deployment, op_seq); the deployment's attempts counter is bumped in the
// same transaction. ErrAttemptOpen when the deployment has an open attempt.
func (l *IGAGovAttemptLog) Prepare(ctx context.Context, run *PolicyJobRun, req AttemptRequest) (*models.IGAGovAttempt, error) {
	if req.Operation == "" || req.RequestHash == "" || req.OpSeq < 0 {
		return nil, errors.New("an attempt needs an operation, a request hash and op_seq >= 0")
	}
	var out models.IGAGovAttempt
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		var next int
		if err := tx.Raw(`SELECT COALESCE(MAX(attempt_no), 0) + 1 FROM iga_gov_attempt
			WHERE workspace_id = ? AND deployment_id = ? AND op_seq = ?`,
			req.WorkspaceID, req.DeploymentID, req.OpSeq).Scan(&next).Error; err != nil {
			return err
		}
		out = models.IGAGovAttempt{
			ID: uuid.New(), WorkspaceID: req.WorkspaceID, DeploymentID: req.DeploymentID, OpSeq: req.OpSeq,
			AttemptNo: next, LeaseVersion: run.Fence.Version, Operation: req.Operation,
			RequestHash: req.RequestHash, Status: models.GovAttemptPrepared, PreparedAt: l.now(),
		}
		if req.DocumentHash != "" {
			dh := req.DocumentHash
			out.DocumentHash = &dh
		}
		if err := tx.Create(&out).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_attempt_open") {
				return ErrAttemptOpen
			}
			return err
		}
		if err := tx.Exec(`UPDATE iga_gov_deployment SET attempts = attempts + 1, updated_at = now()
			WHERE workspace_id = ? AND id = ?`, req.WorkspaceID, req.DeploymentID).Error; err != nil {
			return err
		}
		return l.event(tx, &out, "attempt.prepared", nil)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Dispatch commits step 2, immediately before the call: fenced, the attempt
// prepared under THIS lease version, and at least Margin of lease left by the
// locked job row. ErrPolicyJobLeaseShort when the margin is short (nothing is
// sent; the attempt stays prepared and is abandoned by Recover or re-used).
func (l *IGAGovAttemptLog) Dispatch(ctx context.Context, run *PolicyJobRun, att *models.IGAGovAttempt) error {
	return run.InTx(ctx, func(tx *gorm.DB) error {
		var exp *time.Time
		if err := tx.Raw(`SELECT lease_expires_at FROM iga_gov_job WHERE id = ?`, run.Fence.JobID).Scan(&exp).Error; err != nil {
			return err
		}
		now := l.now()
		if exp == nil || exp.Sub(now) < l.margin() {
			left := time.Duration(0)
			if exp != nil {
				left = exp.Sub(now)
			}
			return fmt.Errorf("%w: %s left, %s needed before dispatch", repositories.ErrPolicyJobLeaseShort,
				left.Round(time.Second), l.margin())
		}
		res := tx.Model(&models.IGAGovAttempt{}).
			Where("workspace_id = ? AND id = ? AND status = ? AND lease_version = ?",
				att.WorkspaceID, att.ID, models.GovAttemptPrepared, run.Fence.Version).
			Updates(map[string]any{"status": models.GovAttemptDispatched, "signed_at": now, "dispatched_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("%w: dispatch of attempt %s", ErrAttemptState, att.ID)
		}
		att.Status, att.SignedAt, att.DispatchedAt = models.GovAttemptDispatched, &now, &now
		return l.event(tx, att, "attempt.dispatched", nil)
	})
}

// Complete commits step 3a: the definitive answer, and for an op that is
// done (ok, recognised_done, not_needed) its entry in the deployment's
// completed_ops, in one transaction. Only the worker that dispatched it
// (same lease version) may complete it; after a reclaim this is
// ErrPolicyJobLeaseLost, and the replacement marks the attempt unknown.
func (l *IGAGovAttemptLog) Complete(ctx context.Context, run *PolicyJobRun, att *models.IGAGovAttempt, ans AttemptAnswer) error {
	switch ans.Outcome {
	case AttemptOutcomeOK, AttemptOutcomeRetryable, AttemptOutcomeTerminal, AttemptOutcomeRecognisedDone, AttemptOutcomeNotNeeded:
	default:
		return fmt.Errorf("attempt outcome %q is not one of 051's", ans.Outcome)
	}
	return run.InTx(ctx, func(tx *gorm.DB) error {
		now := l.now()
		outcome := ans.Outcome
		res := tx.Model(&models.IGAGovAttempt{}).
			Where("workspace_id = ? AND id = ? AND status = ? AND lease_version = ?",
				att.WorkspaceID, att.ID, models.GovAttemptDispatched, run.Fence.Version).
			Updates(map[string]any{
				"status": models.GovAttemptCompleted, "completed_at": now, "outcome": outcome,
				"request_id": ans.RequestID, "error_code": ans.ErrorCode, "error_message": truncate(ans.ErrorMessage, 2000),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("%w: complete of attempt %s", ErrAttemptState, att.ID)
		}
		if OpDone(outcome) {
			// DECISION: completed_ops is a jsonb array of
			// {op_seq, operation, attempt_id, outcome}, appended only when
			// the op is done; a retryable or terminal answer leaves the op
			// not done.
			entry, _ := json.Marshal([]map[string]any{{
				"op_seq": att.OpSeq, "operation": att.Operation, "attempt_id": att.ID, "outcome": outcome,
			}})
			if err := tx.Exec(`UPDATE iga_gov_deployment SET completed_ops = completed_ops || ?::jsonb, updated_at = now()
				WHERE workspace_id = ? AND id = ?`, string(entry), att.WorkspaceID, att.DeploymentID).Error; err != nil {
				return err
			}
		}
		att.Status, att.CompletedAt, att.Outcome = models.GovAttemptCompleted, &now, &outcome
		att.RequestID, att.ErrorCode = ans.RequestID, ans.ErrorCode
		return l.event(tx, att, "attempt.completed", map[string]any{
			"outcome": outcome, "request_id": ans.RequestID, "error_code": ans.ErrorCode})
	})
}

// OpDone reports whether an outcome means the op is done.
func OpDone(outcome string) bool {
	return outcome == AttemptOutcomeOK || outcome == AttemptOutcomeRecognisedDone || outcome == AttemptOutcomeNotNeeded
}

// MarkUnknown commits step 3b for the worker that dispatched the attempt: no
// answer was recorded. The attempt becomes `unknown` and the deployment
// outcome_unknown with outcome_unknown_op and settle_after = signed_at +
// SettleWindow, in one transaction. It returns settle_after.
func (l *IGAGovAttemptLog) MarkUnknown(ctx context.Context, run *PolicyJobRun, att *models.IGAGovAttempt, reason string) (time.Time, error) {
	var settle time.Time
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		var err error
		settle, err = l.markUnknownTx(tx, att, &run.Fence.Version, reason)
		return err
	})
	return settle, err
}

// markUnknownTx moves a dispatched attempt to unknown and its deployment to
// outcome_unknown. leaseVersion, when set, requires the attempt to have been
// prepared under it (the dispatching worker); Recover passes nil.
func (l *IGAGovAttemptLog) markUnknownTx(tx *gorm.DB, att *models.IGAGovAttempt, leaseVersion *int64, reason string) (time.Time, error) {
	q := tx.Model(&models.IGAGovAttempt{}).
		Where("workspace_id = ? AND id = ? AND status = ?", att.WorkspaceID, att.ID, models.GovAttemptDispatched)
	if leaseVersion != nil {
		q = q.Where("lease_version = ?", *leaseVersion)
	}
	res := q.Update("status", models.GovAttemptUnknown)
	if res.Error != nil {
		return time.Time{}, res.Error
	}
	if res.RowsAffected != 1 {
		return time.Time{}, fmt.Errorf("%w: mark unknown of attempt %s", ErrAttemptState, att.ID)
	}
	signed := l.now()
	if att.SignedAt != nil {
		signed = *att.SignedAt
	}
	settle := signed.Add(l.settle())
	op := fmt.Sprintf("%d:%s", att.OpSeq, att.Operation)
	// Only an applying deployment can be waiting on a sent request (§8.4).
	dres := tx.Exec(`UPDATE iga_gov_deployment
		SET state = 'outcome_unknown', outcome_unknown_op = ?, settle_after = ?, state_reason = ?, updated_at = now()
		WHERE workspace_id = ? AND id = ? AND state = 'applying'`,
		op, settle, truncate(reason, 500), att.WorkspaceID, att.DeploymentID)
	if dres.Error != nil {
		return time.Time{}, dres.Error
	}
	if dres.RowsAffected != 1 {
		return time.Time{}, fmt.Errorf("%w: deployment %s is not applying", ErrAttemptState, att.DeploymentID)
	}
	att.Status = models.GovAttemptUnknown
	return settle, l.event(tx, att, "attempt.unknown", map[string]any{"reason": reason, "settle_after": settle})
}

// Recovery actions (the §8.1 replacement-worker table).
const (
	// RecoveryContinue: no open attempt; re-read live state and continue.
	RecoveryContinue = "continue"
	// RecoveryReprepare: a prepared attempt was abandoned (never sent);
	// re-read live state, classify, and prepare attempt_no + 1.
	RecoveryReprepare = "reprepare"
	// RecoveryOutcomeUnknown: a dispatched attempt was marked unknown and the
	// deployment is outcome_unknown until SettleAfter. Never re-send.
	RecoveryOutcomeUnknown = "outcome_unknown"
	// RecoveryHold: an unknown attempt is still unresolved; the role stays
	// held (409 outcome_unknown_pending for conflicting work).
	RecoveryHold = "hold"
)

// AttemptRecovery is what Recover found and did.
type AttemptRecovery struct {
	Action      string
	Attempt     *models.IGAGovAttempt
	SettleAfter *time.Time
}

// Recover applies §8.1's replacement-worker rule to a deployment's open
// attempt, fenced on THIS run's lease, before anything else is done on the
// deployment.
func (l *IGAGovAttemptLog) Recover(ctx context.Context, run *PolicyJobRun, ws, deploymentID uuid.UUID) (*AttemptRecovery, error) {
	var out AttemptRecovery
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		var open []models.IGAGovAttempt
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("workspace_id = ? AND deployment_id = ? AND (status IN ? OR (status = ? AND resolved_as IS NULL))",
				ws, deploymentID, []string{models.GovAttemptPrepared, models.GovAttemptDispatched}, models.GovAttemptUnknown).
			Find(&open).Error; err != nil {
			return err
		}
		if len(open) == 0 {
			out = AttemptRecovery{Action: RecoveryContinue}
			return nil
		}
		att := open[0] // uq_iga_gov_attempt_open: at most one
		out.Attempt = &att
		switch att.Status {
		case models.GovAttemptPrepared:
			now := l.now()
			res := tx.Model(&models.IGAGovAttempt{}).Where("id = ? AND status = ?", att.ID, models.GovAttemptPrepared).
				Updates(map[string]any{"status": models.GovAttemptAbandoned, "completed_at": now})
			if res.Error != nil {
				return res.Error
			}
			att.Status, att.CompletedAt = models.GovAttemptAbandoned, &now
			out.Action = RecoveryReprepare
			return l.event(tx, &att, "attempt.abandoned", map[string]any{"reason": "prepared, never sent; found by a replacement worker"})
		case models.GovAttemptDispatched:
			settle, err := l.markUnknownTx(tx, &att, nil,
				"dispatched with no answer recorded; found by a replacement worker (never re-sent)")
			if err != nil {
				return err
			}
			out.Action, out.SettleAfter = RecoveryOutcomeUnknown, &settle
			return nil
		default: // unknown, unresolved
			var dep []struct{ SettleAfter *time.Time }
			if err := tx.Raw(`SELECT settle_after FROM iga_gov_deployment WHERE workspace_id = ? AND id = ?`,
				ws, deploymentID).Scan(&dep).Error; err != nil {
				return err
			}
			out.Action = RecoveryHold
			if len(dep) == 1 {
				out.SettleAfter = dep[0].SettleAfter // nil when the deployment no longer records one
			}
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ResolveUnknown records §8.1 step 2's resolution of an unknown attempt
// (applied or not_applied, from two consistent readbacks and CloudTrail --
// established by the caller, T3.16) and returns the deployment from
// outcome_unknown to applying, in one transaction. The attempt keeps status
// `unknown`; resolved_as is write-once (trigger).
func (l *IGAGovAttemptLog) ResolveUnknown(ctx context.Context, run *PolicyJobRun, att *models.IGAGovAttempt, resolvedAs string) error {
	if resolvedAs != AttemptResolvedApplied && resolvedAs != AttemptResolvedNotApplied {
		return fmt.Errorf("resolved_as %q is not applied or not_applied", resolvedAs)
	}
	return run.InTx(ctx, func(tx *gorm.DB) error {
		now := l.now()
		res := tx.Model(&models.IGAGovAttempt{}).
			Where("workspace_id = ? AND id = ? AND status = ? AND resolved_as IS NULL", att.WorkspaceID, att.ID, models.GovAttemptUnknown).
			Updates(map[string]any{"resolved_as": resolvedAs, "resolved_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("%w: resolve of attempt %s", ErrAttemptState, att.ID)
		}
		if err := tx.Exec(`UPDATE iga_gov_deployment SET state = 'applying', state_reason = ?, updated_at = now()
			WHERE workspace_id = ? AND id = ? AND state = 'outcome_unknown'`,
			"outcome of "+att.Operation+" resolved: "+resolvedAs, att.WorkspaceID, att.DeploymentID).Error; err != nil {
			return err
		}
		att.ResolvedAs, att.ResolvedAt = &resolvedAs, &now
		return l.event(tx, att, "attempt.resolved", map[string]any{"resolved_as": resolvedAs})
	})
}

// Execute runs the whole lifecycle around call: Prepare, Dispatch, the call
// (bounded by CallTimeout and the job context), then Complete or MarkUnknown.
//
//   - A definitive answer is completed (fenced). If the fence was lost while
//     the call ran, Complete fails with ErrPolicyJobLeaseLost: the answer is
//     not recorded, the attempt stays dispatched, and the replacement marks it
//     unknown -- the safe direction.
//   - No answer (the call's error, its timeout, the job context ending) is
//     unknown: the deployment goes outcome_unknown, nothing is retried, and a
//     late answer from a call that ignored its context is discarded.
//   - ErrPolicyJobLeaseShort before dispatch: nothing was sent; the prepared
//     attempt is abandoned in the same run so the next Execute can re-prepare.
func (l *IGAGovAttemptLog) Execute(ctx context.Context, run *PolicyJobRun, req AttemptRequest, call AttemptCall) (*AttemptResult, error) {
	att, err := l.Prepare(ctx, run, req)
	if err != nil {
		return nil, err
	}
	if err := l.Dispatch(ctx, run, att); err != nil {
		if errors.Is(err, repositories.ErrPolicyJobLeaseShort) {
			if aerr := l.abandonOwn(ctx, run, att); aerr != nil {
				return nil, errors.Join(err, aerr)
			}
		}
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, l.callTimeout())
	defer cancel()
	type reply struct {
		ans AttemptAnswer
		err error
	}
	ch := make(chan reply, 1) // buffered: a late answer never blocks
	go func() {
		a, e := call(callCtx)
		ch <- reply{a, e}
	}()
	var rep reply
	select {
	case rep = <-ch:
	case <-callCtx.Done():
		rep = reply{err: fmt.Errorf("no answer before the client timeout or cancellation: %w", callCtx.Err())}
	}

	if rep.err == nil {
		if err := l.Complete(ctx, run, att, rep.ans); err != nil {
			return nil, err
		}
		a := rep.ans
		return &AttemptResult{Attempt: *att, Answer: &a}, nil
	}
	// The job context may itself be the cancelled one (shutdown, lease lost):
	// the bookkeeping write must still be attempted, fenced.
	settle, err := l.MarkUnknown(context.WithoutCancel(ctx), run, att, rep.err.Error())
	if err != nil {
		return nil, errors.Join(fmt.Errorf("no answer (%v), and marking the attempt unknown failed", rep.err), err)
	}
	return &AttemptResult{Attempt: *att, Unknown: true, SettleAfter: &settle, CallErr: rep.err}, nil
}

// abandonOwn abandons a prepared attempt this run prepared and never sent.
func (l *IGAGovAttemptLog) abandonOwn(ctx context.Context, run *PolicyJobRun, att *models.IGAGovAttempt) error {
	return run.InTx(ctx, func(tx *gorm.DB) error {
		now := l.now()
		res := tx.Model(&models.IGAGovAttempt{}).
			Where("workspace_id = ? AND id = ? AND status = ? AND lease_version = ?",
				att.WorkspaceID, att.ID, models.GovAttemptPrepared, run.Fence.Version).
			Updates(map[string]any{"status": models.GovAttemptAbandoned, "completed_at": now})
		if res.Error != nil {
			return res.Error
		}
		att.Status, att.CompletedAt = models.GovAttemptAbandoned, &now
		return l.event(tx, att, "attempt.abandoned", map[string]any{"reason": "lease margin short before dispatch; never sent"})
	})
}

// OpenAttempt returns the deployment's open attempt (prepared, dispatched, or
// unknown and unresolved), or nil. Conflicting work checks it and answers
// 409 outcome_unknown_pending (ErrOutcomeUnknownPending) while one is open.
func (l *IGAGovAttemptLog) OpenAttempt(db *gorm.DB, ws, deploymentID uuid.UUID) (*models.IGAGovAttempt, error) {
	var open []models.IGAGovAttempt
	if err := db.Where("workspace_id = ? AND deployment_id = ? AND (status IN ? OR (status = ? AND resolved_as IS NULL))",
		ws, deploymentID, []string{models.GovAttemptPrepared, models.GovAttemptDispatched}, models.GovAttemptUnknown).
		Limit(1).Find(&open).Error; err != nil {
		return nil, err
	}
	if len(open) == 0 {
		return nil, nil
	}
	return &open[0], nil
}

func (l *IGAGovAttemptLog) event(tx *gorm.DB, att *models.IGAGovAttempt, name string, extra map[string]any) error {
	payload := map[string]any{
		"attempt_id": att.ID, "op_seq": att.OpSeq, "attempt_no": att.AttemptNo,
		"operation": att.Operation, "lease_version": att.LeaseVersion, "status": att.Status,
	}
	for k, v := range extra {
		payload[k] = v
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	dep := att.DeploymentID
	return l.events.AppendTx(tx, &models.IGAGovEvent{
		WorkspaceID: att.WorkspaceID, Event: name, ActorKind: models.GovActorSystem, ActorID: "policy-worker",
		DeploymentID: &dep, Payload: raw,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// isUniqueViolation reports a 23505 on the named constraint or index.
func isUniqueViolation(err error, name string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return (strings.Contains(msg, "23505") || strings.Contains(msg, "duplicate key")) && strings.Contains(msg, name)
}
